"""Tuya BLE body-fat scale - fully local Bluetooth integration."""

from __future__ import annotations

from homeassistant.config_entries import ConfigEntry
from homeassistant.const import Platform
from homeassistant.core import HomeAssistant

from .coordinator import TuyaBLEScaleCoordinator

PLATFORMS: list[Platform] = [Platform.SENSOR]

type TuyaBLEScaleConfigEntry = ConfigEntry[TuyaBLEScaleCoordinator]


async def async_setup_entry(hass: HomeAssistant, entry: TuyaBLEScaleConfigEntry) -> bool:
    """Set up a scale.

    No connection is attempted here: the scale is only reachable while someone
    stands on it, so the coordinator connects when it next advertises.
    """
    coordinator = TuyaBLEScaleCoordinator(hass, entry)
    await coordinator.async_load()
    entry.runtime_data = coordinator
    await hass.config_entries.async_forward_entry_setups(entry, PLATFORMS)
    entry.async_on_unload(coordinator.async_start())
    return True


async def async_unload_entry(hass: HomeAssistant, entry: TuyaBLEScaleConfigEntry) -> bool:
    """Unload a scale."""
    if unload_ok := await hass.config_entries.async_unload_platforms(entry, PLATFORMS):
        await entry.runtime_data.async_stop()
    return unload_ok
