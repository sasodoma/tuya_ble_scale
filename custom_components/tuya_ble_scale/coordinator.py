"""Opportunistic connection manager for a transient Tuya BLE scale."""

from __future__ import annotations

import asyncio
from collections.abc import Callable
from datetime import datetime
import logging
import time
from typing import TYPE_CHECKING, Any

from bleak.backends.device import BLEDevice
from homeassistant.components import bluetooth
from homeassistant.const import CONF_ADDRESS
from homeassistant.core import CALLBACK_TYPE, HomeAssistant, callback
from homeassistant.helpers.storage import Store
from homeassistant.util import dt as dt_util

from .const import (
    CONF_DEVICE_ID,
    CONF_LOCAL_KEY,
    CONF_UUID,
    COOLDOWN_AFTER_AUTH_FAILURE,
    COOLDOWN_AFTER_FAILURE,
    COOLDOWN_AFTER_SUCCESS,
    DOMAIN,
    EVENT_MEASUREMENT,
    TUYA_MANUFACTURER_ID,
    TUYA_SERVICE_DATA_UUID,
)
from .tuya_ble_client import (
    ScaleReading,
    TuyaBLEScaleAuthError,
    TuyaBLEScaleCredentials,
    TuyaBLEScaleError,
    TuyaBLEScaleSession,
)
from .tuya_ble_proto import decode_uuid_from_advertisement

if TYPE_CHECKING:
    from homeassistant.config_entries import ConfigEntry

_LOGGER = logging.getLogger(__name__)

STORAGE_VERSION = 1
_MIN_VALID_TS = 1577836800  # 2020-01-01; older = scale clock never set


def uuid_from_service_info(service_info: bluetooth.BluetoothServiceInfoBleak) -> str | None:
    """Derive the Tuya uuid from an advertisement, if it carries enough data."""
    return decode_uuid_from_advertisement(
        service_info.service_data.get(TUYA_SERVICE_DATA_UUID),
        service_info.manufacturer_data.get(TUYA_MANUFACTURER_ID),
    )


class TuyaBLEScaleCoordinator:
    """Connects whenever the scale advertises and keeps the latest reading."""

    def __init__(self, hass: HomeAssistant, entry: ConfigEntry) -> None:
        self.hass = hass
        self.entry = entry
        self.address: str = entry.data[CONF_ADDRESS]
        self._local_key6 = bytes.fromhex(entry.data[CONF_LOCAL_KEY])
        self._device_id: str = entry.data[CONF_DEVICE_ID]
        self._uuid: str | None = entry.data.get(CONF_UUID)
        self._store: Store[dict[str, Any]] = Store(
            hass, STORAGE_VERSION, f"{DOMAIN}.{entry.entry_id}"
        )
        self._listeners: list[Callable[[], None]] = []
        self._task: asyncio.Task[None] | None = None
        self._cooldown_until = 0.0
        self._auth_failed = False

        self.weight: float | None = None
        self.impedance: int | None = None
        self.measured_at: datetime | None = None
        self.live_weight: float | None = None
        self.connected = False
        self.device_version: str | None = None

    # ------------------------------------------------------------------ #
    # Lifecycle
    # ------------------------------------------------------------------ #

    async def async_load(self) -> None:
        """Restore the last weigh-in so sensors survive restarts."""
        if not (data := await self._store.async_load()):
            return
        self.weight = data.get("weight")
        self.impedance = data.get("impedance")
        if ts := data.get("measured_at"):
            self.measured_at = dt_util.parse_datetime(ts)
        self.device_version = data.get("device_version")

    @callback
    def async_start(self) -> CALLBACK_TYPE:
        """Start listening for advertisements."""
        unsub = bluetooth.async_register_callback(
            self.hass,
            self._async_on_advertisement,
            bluetooth.BluetoothCallbackMatcher(address=self.address, connectable=True),
            bluetooth.BluetoothScanningMode.ACTIVE,
        )
        # Scale may already be awake (e.g. HA restarted mid weigh-in).
        if service_info := bluetooth.async_last_service_info(
            self.hass, self.address, connectable=True
        ):
            self._async_on_advertisement(service_info, bluetooth.BluetoothChange.ADVERTISEMENT)
        return unsub

    async def async_stop(self) -> None:
        """Cancel an in-flight session."""
        if self._task and not self._task.done():
            self._task.cancel()
            try:
                await self._task
            except (asyncio.CancelledError, Exception):  # noqa: BLE001
                pass
        self._task = None

    @callback
    def async_add_listener(self, update_callback: Callable[[], None]) -> CALLBACK_TYPE:
        """Entities subscribe here."""
        self._listeners.append(update_callback)

        @callback
        def _remove() -> None:
            self._listeners.remove(update_callback)

        return _remove

    @callback
    def _async_notify(self) -> None:
        for update_callback in list(self._listeners):
            update_callback()

    # ------------------------------------------------------------------ #
    # Advertisement -> session
    # ------------------------------------------------------------------ #

    @callback
    def _async_on_advertisement(
        self,
        service_info: bluetooth.BluetoothServiceInfoBleak,
        change: bluetooth.BluetoothChange,
    ) -> None:
        if self._uuid is None and (uuid := uuid_from_service_info(service_info)):
            _LOGGER.debug("Derived uuid %s from advertisement", uuid)
            self._uuid = uuid
            self.hass.config_entries.async_update_entry(
                self.entry, data={**self.entry.data, CONF_UUID: uuid}
            )
        if self._task is not None and not self._task.done():
            return
        if self._auth_failed or time.monotonic() < self._cooldown_until:
            return
        if self._uuid is None:
            _LOGGER.debug("Waiting for an advertisement that carries the uuid")
            return
        self._task = self.entry.async_create_background_task(
            self.hass,
            self._async_session(service_info.device),
            f"{DOMAIN} session {self.address}",
        )

    async def _async_session(self, ble_device: BLEDevice) -> None:
        assert self._uuid is not None
        session = TuyaBLEScaleSession(
            TuyaBLEScaleCredentials(self._local_key6, self._device_id, self._uuid),
            self._async_on_reading,
        )
        cooldown = COOLDOWN_AFTER_FAILURE
        self.connected = True
        self._async_notify()
        try:
            got_final = await session.async_run(
                ble_device,
                lambda: bluetooth.async_ble_device_from_address(
                    self.hass, self.address, connectable=True
                )
                or ble_device,
            )
            _LOGGER.debug("Session finished (final weight: %s)", got_final)
            cooldown = COOLDOWN_AFTER_SUCCESS
            if session.device_version and session.device_version != self.device_version:
                self.device_version = session.device_version
                self._async_save()
        except TuyaBLEScaleAuthError as err:
            _LOGGER.error(
                "Scale %s rejected the credentials: %s. Re-extract local_key "
                "(the scale was probably re-paired) and update the integration",
                self.address,
                err,
            )
            cooldown = COOLDOWN_AFTER_AUTH_FAILURE
            self._auth_failed = True
            self.entry.async_start_reauth(self.hass)
        except (TuyaBLEScaleError, TimeoutError) as err:
            # Expected often: the user stepped off before we finished connecting.
            _LOGGER.debug("Session with %s failed: %s", self.address, err)
        finally:
            self.connected = False
            self.live_weight = None
            self._cooldown_until = time.monotonic() + cooldown
            self._async_notify()

    # ------------------------------------------------------------------ #
    # Readings
    # ------------------------------------------------------------------ #

    @callback
    def _async_on_reading(self, reading: ScaleReading) -> None:
        if not reading.final:
            self.live_weight = reading.weight_kg
            self._async_notify()
            return

        now = time.time()
        ts = reading.timestamp
        if ts is None or not _MIN_VALID_TS <= ts <= now + 86400:
            ts = now
        measured_at = dt_util.utc_from_timestamp(ts)
        if self.measured_at is not None and measured_at <= self.measured_at:
            # Replay of a record we already have (or an older offline record).
            _LOGGER.debug("Ignoring old/duplicate record from %s", measured_at)
            return

        _LOGGER.debug("Weigh-in: %.1f kg at %s", reading.weight_kg, measured_at)
        self.weight = reading.weight_kg
        self.impedance = reading.impedance
        self.measured_at = measured_at
        self.live_weight = reading.weight_kg
        self._async_save()
        self._async_notify()
        self.hass.bus.async_fire(
            EVENT_MEASUREMENT,
            {
                "address": self.address,
                "weight": reading.weight_kg,
                "impedance": reading.impedance,
                "measured_at": measured_at.isoformat(),
            },
        )

    @callback
    def _async_save(self) -> None:
        self._store.async_delay_save(
            lambda: {
                "weight": self.weight,
                "impedance": self.impedance,
                "measured_at": self.measured_at.isoformat() if self.measured_at else None,
                "device_version": self.device_version,
            },
            1,
        )
