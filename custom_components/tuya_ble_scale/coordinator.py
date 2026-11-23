"""Opportunistic connection manager for a transient Tuya BLE scale."""

from __future__ import annotations

import asyncio
from collections import deque
from collections.abc import Callable
from datetime import datetime, timedelta
import logging
import time
from typing import TYPE_CHECKING, Any

from bleak.backends.device import BLEDevice
from homeassistant.components import bluetooth
from homeassistant.const import CONF_ADDRESS
from homeassistant.core import CALLBACK_TYPE, HomeAssistant, callback
from homeassistant.helpers.event import async_track_time_interval
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
_MAX_FUTURE_S = 300  # a record "from the future" means a wrong scale clock
_SEEN_RECORDS_MAX = 32
# The scale sometimes stores a weigh-in it already sent live and uploads it
# again later, stamped a few seconds earlier (when the weight settled rather
# than when the final record was sent). Same weight within this window = same
# weigh-in.
_SAME_RECORD_WINDOW_S = 10

# Home Assistant only dispatches an advertisement to callbacks when its content
# differs from the previous one, and this scale sends identical adverts on
# every wake-up. HA still refreshes its stored copy (and its timestamp) for
# each advert, so we also poll that to notice the scale waking up.
ADVERTISEMENT_POLL_INTERVAL = timedelta(seconds=1)

type _RecordKey = tuple[float, int, int | None]


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
        self._last_adv_time: float | None = None
        self._last_skip_reason: str | None = None
        # Records already processed, keyed by the scale's own (raw) timestamp,
        # weight and impedance. The scale replays records on reconnect and
        # re-sends ones whose ACK it missed.
        self._seen_records: deque[_RecordKey] = deque(maxlen=_SEEN_RECORDS_MAX)

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
        for key in data.get("seen_records") or []:
            try:
                rec_ts, rec_weight, rec_impedance = key
                self._seen_records.append((float(rec_ts), int(rec_weight), rec_impedance))
            except (TypeError, ValueError):
                continue
        if "seen_records" not in data and self.measured_at and self.weight is not None:
            # Stored by an older version, where measured_at was the scale's own
            # time: treat a replay of that record as already seen.
            self._seen_records.append(
                (self.measured_at.timestamp(), round(self.weight * 10), self.impedance)
            )

    @callback
    def async_start(self) -> CALLBACK_TYPE:
        """Start listening for advertisements."""
        unsub_adv = bluetooth.async_register_callback(
            self.hass,
            self._async_on_advertisement,
            bluetooth.BluetoothCallbackMatcher(address=self.address, connectable=True),
            bluetooth.BluetoothScanningMode.ACTIVE,
        )
        unsub_poll = async_track_time_interval(
            self.hass, self._async_poll_advertisement, ADVERTISEMENT_POLL_INTERVAL
        )
        # Scale may already be awake (e.g. HA restarted mid weigh-in).
        if service_info := bluetooth.async_last_service_info(
            self.hass, self.address, connectable=True
        ):
            self._async_on_advertisement(service_info, bluetooth.BluetoothChange.ADVERTISEMENT)

        @callback
        def _unsub() -> None:
            unsub_adv()
            unsub_poll()

        return _unsub

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
    def _async_poll_advertisement(self, _now: datetime) -> None:
        """Catch adverts HA didn't dispatch because their content was unchanged."""
        service_info = bluetooth.async_last_service_info(
            self.hass, self.address, connectable=True
        )
        if service_info is None or service_info.time == self._last_adv_time:
            return
        self._async_on_advertisement(service_info, bluetooth.BluetoothChange.ADVERTISEMENT)

    @callback
    def _async_on_advertisement(
        self,
        service_info: bluetooth.BluetoothServiceInfoBleak,
        change: bluetooth.BluetoothChange,
    ) -> None:
        self._last_adv_time = service_info.time
        if self._uuid is None and (uuid := uuid_from_service_info(service_info)):
            _LOGGER.debug("Derived uuid %s from advertisement", uuid)
            self._uuid = uuid
            self.hass.config_entries.async_update_entry(
                self.entry, data={**self.entry.data, CONF_UUID: uuid}
            )
        if self._task is not None and not self._task.done():
            self._log_skip("session already running")
            return
        if self._auth_failed:
            self._log_skip("credentials were rejected; reconfigure the integration")
            return
        if (remaining := self._cooldown_until - time.monotonic()) > 0:
            self._log_skip(
                "cooling down after the last session", f" ({remaining:.0f} s left)"
            )
            return
        if self._uuid is None:
            self._log_skip("waiting for an advertisement that carries the uuid")
            return
        self._last_skip_reason = None
        _LOGGER.debug(
            "Scale advertising (rssi %s, via %s), connecting",
            service_info.rssi,
            service_info.source,
        )
        self._task = self.entry.async_create_background_task(
            self.hass,
            self._async_session(service_info.device),
            f"{DOMAIN} session {self.address}",
        )

    @callback
    def _log_skip(self, reason: str, detail: str = "") -> None:
        """Log why an advert didn't start a session (once per reason, not per advert)."""
        if reason != self._last_skip_reason:
            self._last_skip_reason = reason
            _LOGGER.debug("Scale advertising, not connecting: %s%s", reason, detail)

    async def _async_session(self, ble_device: BLEDevice) -> None:
        assert self._uuid is not None
        session = TuyaBLEScaleSession(
            TuyaBLEScaleCredentials(self._local_key6, self._device_id, self._uuid),
            self._async_on_reading,
        )
        cooldown = COOLDOWN_AFTER_FAILURE
        started = time.monotonic()
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
            _LOGGER.debug(
                "Session finished after %.1f s (final weight: %s)",
                time.monotonic() - started,
                got_final,
            )
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
            _LOGGER.debug(
                "Session with %s failed after %.1f s: %s",
                self.address,
                time.monotonic() - started,
                err,
            )
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

        scale_ts = reading.timestamp
        if scale_ts is not None:
            key: _RecordKey = (scale_ts, round(reading.weight_kg * 10), reading.impedance)
            if self._is_seen(key):
                _LOGGER.debug(
                    "Ignoring repeated record: %.1f kg, scale time %s",
                    reading.weight_kg,
                    dt_util.utc_from_timestamp(scale_ts),
                )
                return
            self._seen_records.append(key)

        measured_at = self._measured_at_for(scale_ts)
        _LOGGER.debug(
            "Weigh-in: %.1f kg at %s (scale time %s)",
            reading.weight_kg,
            measured_at,
            dt_util.utc_from_timestamp(scale_ts) if scale_ts is not None else None,
        )
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
                "scale_timestamp": (
                    dt_util.utc_from_timestamp(scale_ts).isoformat()
                    if scale_ts is not None
                    else None
                ),
            },
        )

    def _is_seen(self, key: _RecordKey) -> bool:
        ts, weight, impedance = key
        return any(
            weight == seen_weight
            and impedance == seen_impedance
            and abs(ts - seen_ts) <= _SAME_RECORD_WINDOW_S
            for seen_ts, seen_weight, seen_impedance in self._seen_records
        )

    def _measured_at_for(self, scale_ts: float | None) -> datetime:
        """Pick the time to report for a new record.

        The scale's clock only runs while it is awake and is corrected when we
        answer its time request, so a record taken while nothing was connected
        carries a time that can be minutes or hours too early. Records arrive
        oldest first, so a scale time that isn't after the previous weigh-in is
        known to be wrong; use the time we received it instead. The result never
        goes backwards.
        """
        now = time.time()
        if (
            scale_ts is not None
            and _MIN_VALID_TS <= scale_ts <= now + _MAX_FUTURE_S
            and (self.measured_at is None or scale_ts > self.measured_at.timestamp())
        ):
            return dt_util.utc_from_timestamp(min(scale_ts, now))
        if scale_ts is not None:
            _LOGGER.debug(
                "Scale time %s is not plausible, using the receive time",
                dt_util.utc_from_timestamp(scale_ts),
            )
        if self.measured_at is not None and now <= self.measured_at.timestamp():
            now = self.measured_at.timestamp() + 0.001
        return dt_util.utc_from_timestamp(now)

    @callback
    def _async_save(self) -> None:
        self._store.async_delay_save(
            lambda: {
                "weight": self.weight,
                "impedance": self.impedance,
                "measured_at": self.measured_at.isoformat() if self.measured_at else None,
                "device_version": self.device_version,
                "seen_records": [list(key) for key in self._seen_records],
            },
            1,
        )
