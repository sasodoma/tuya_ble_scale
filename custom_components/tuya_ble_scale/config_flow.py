"""Config flow for the Tuya BLE Scale integration (local, no cloud)."""

from __future__ import annotations

from collections.abc import Mapping
import re
from typing import Any

import voluptuous as vol

from homeassistant.components.bluetooth import (
    BluetoothServiceInfoBleak,
    async_discovered_service_info,
)
from homeassistant.config_entries import ConfigFlow, ConfigFlowResult
from homeassistant.const import CONF_ADDRESS
from homeassistant.helpers.selector import (
    SelectOptionDict,
    SelectSelector,
    SelectSelectorConfig,
    SelectSelectorMode,
)

from .const import (
    CONF_DEVICE_ID,
    CONF_LOCAL_KEY,
    CONF_UUID,
    DOMAIN,
    TUYA_GATT_SERVICE_UUID,
    TUYA_LOCAL_NAME,
    TUYA_MANUFACTURER_ID,
    TUYA_SERVICE_DATA_UUID,
)
from .coordinator import uuid_from_service_info
from .tuya_ble_proto import PAIR_DATA_LEN, normalize_local_key

_ADDRESS_RE = re.compile(r"^([0-9A-F]{2}:){5}[0-9A-F]{2}$")


def _is_candidate(info: BluetoothServiceInfoBleak) -> bool:
    """Looks like a Tuya BLE device (scale adverts as name 'TY')."""
    return (
        info.name == TUYA_LOCAL_NAME
        or TUYA_GATT_SERVICE_UUID in info.service_uuids
        or (
            TUYA_MANUFACTURER_ID in info.manufacturer_data
            and TUYA_SERVICE_DATA_UUID in info.service_data
        )
    )


def _validate_credentials(
    user_input: dict[str, Any], uuid: str | None, errors: dict[str, str]
) -> tuple[bytes, str, str | None] | None:
    """Return (local_key6, device_id, uuid) or fill ``errors``.

    uuid may stay None; the coordinator then derives it from the next advert.
    """
    try:
        key6 = normalize_local_key(user_input[CONF_LOCAL_KEY])
    except ValueError:
        errors[CONF_LOCAL_KEY] = "invalid_local_key"
        key6 = b""
    device_id = user_input[CONF_DEVICE_ID].strip()
    if not device_id.isascii() or not device_id:
        errors[CONF_DEVICE_ID] = "invalid_device_id"
    uuid = (user_input.get(CONF_UUID) or uuid or "").strip() or None
    if uuid is not None and not (uuid.isascii() and uuid.isalnum()):
        errors[CONF_UUID] = "invalid_uuid"
    elif len(uuid or "x" * 16) + 6 + len(device_id) > PAIR_DATA_LEN:
        errors["base"] = "ids_too_long"
    if errors:
        return None
    return key6, device_id, uuid


class TuyaBLEScaleConfigFlow(ConfigFlow, domain=DOMAIN):
    """Handle a config flow."""

    VERSION = 1

    def __init__(self) -> None:
        self._address: str | None = None
        self._uuid: str | None = None
        self._discovered: dict[str, BluetoothServiceInfoBleak] = {}

    async def async_step_bluetooth(
        self, discovery_info: BluetoothServiceInfoBleak
    ) -> ConfigFlowResult:
        """Discovered via the manifest bluetooth matcher."""
        await self.async_set_unique_id(discovery_info.address)
        self._abort_if_unique_id_configured()
        if not _is_candidate(discovery_info):
            return self.async_abort(reason="not_supported")
        self._address = discovery_info.address
        self._uuid = uuid_from_service_info(discovery_info)
        self.context["title_placeholders"] = {
            "name": f"{discovery_info.name or 'Tuya BLE'} ({discovery_info.address})"
        }
        return await self.async_step_credentials()

    async def async_step_user(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Pick a discovered scale or type its address."""
        errors: dict[str, str] = {}
        if user_input is not None:
            address = user_input[CONF_ADDRESS].strip().upper()
            if not _ADDRESS_RE.match(address):
                errors[CONF_ADDRESS] = "invalid_address"
            else:
                await self.async_set_unique_id(address, raise_on_progress=False)
                self._abort_if_unique_id_configured()
                self._address = address
                if info := self._discovered.get(address):
                    self._uuid = uuid_from_service_info(info)
                return await self.async_step_credentials()

        current = self._async_current_ids(include_ignore=False)
        for info in async_discovered_service_info(self.hass, connectable=False):
            if info.address not in current and _is_candidate(info):
                self._discovered[info.address] = info

        options = [
            SelectOptionDict(value=addr, label=f"{info.name or '?'} ({addr})")
            for addr, info in self._discovered.items()
        ]
        return self.async_show_form(
            step_id="user",
            data_schema=vol.Schema(
                {
                    vol.Required(CONF_ADDRESS): SelectSelector(
                        SelectSelectorConfig(
                            options=options,
                            custom_value=True,
                            mode=SelectSelectorMode.DROPDOWN,
                        )
                    )
                }
            ),
            errors=errors,
        )

    async def async_step_credentials(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Ask for local_key and device_id; uuid comes from the advert."""
        assert self._address is not None
        errors: dict[str, str] = {}
        if user_input is not None:
            if result := _validate_credentials(user_input, self._uuid, errors):
                key6, device_id, uuid = result
                return self.async_create_entry(
                    title=f"Tuya BLE Scale {self._address}",
                    data={
                        CONF_ADDRESS: self._address,
                        CONF_LOCAL_KEY: key6.hex(),
                        CONF_DEVICE_ID: device_id,
                        CONF_UUID: uuid,
                    },
                )

        schema: dict[Any, Any] = {
            vol.Required(CONF_LOCAL_KEY): str,
            vol.Required(CONF_DEVICE_ID): str,
        }
        # Pre-filled when derivable from the advertisement. Left empty, it is
        # derived from the scale's next advertisement.
        schema[vol.Optional(CONF_UUID, default=self._uuid or "")] = str
        return self.async_show_form(
            step_id="credentials",
            data_schema=self.add_suggested_values_to_schema(vol.Schema(schema), user_input),
            description_placeholders={"address": self._address},
            errors=errors,
        )

    async def async_step_reauth(self, entry_data: Mapping[str, Any]) -> ConfigFlowResult:
        """local_key stopped working (scale re-paired)."""
        return await self.async_step_reauth_confirm()

    async def async_step_reauth_confirm(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        entry = self._get_reauth_entry()
        errors: dict[str, str] = {}
        if user_input is not None:
            if result := _validate_credentials(user_input, entry.data.get(CONF_UUID), errors):
                key6, device_id, uuid = result
                return self.async_update_reload_and_abort(
                    entry,
                    data_updates={
                        CONF_LOCAL_KEY: key6.hex(),
                        CONF_DEVICE_ID: device_id,
                        CONF_UUID: uuid,
                    },
                )
        return self.async_show_form(
            step_id="reauth_confirm",
            data_schema=vol.Schema(
                {
                    vol.Required(CONF_LOCAL_KEY): str,
                    vol.Required(
                        CONF_DEVICE_ID, default=entry.data.get(CONF_DEVICE_ID, "")
                    ): str,
                    vol.Optional(CONF_UUID, default=entry.data.get(CONF_UUID) or ""): str,
                }
            ),
            description_placeholders={"address": entry.data[CONF_ADDRESS]},
            errors=errors,
        )
