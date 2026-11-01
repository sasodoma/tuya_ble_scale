"""Sensors for the Tuya BLE scale."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime

from homeassistant.components.sensor import (
    SensorDeviceClass,
    SensorEntity,
    SensorEntityDescription,
    SensorStateClass,
)
from homeassistant.const import EntityCategory, UnitOfMass
from homeassistant.core import HomeAssistant
from homeassistant.helpers.device_registry import CONNECTION_BLUETOOTH, DeviceInfo
from homeassistant.helpers.entity_platform import AddEntitiesCallback

from . import TuyaBLEScaleConfigEntry
from .const import DOMAIN
from .coordinator import TuyaBLEScaleCoordinator


@dataclass(frozen=True, kw_only=True)
class TuyaBLEScaleSensorDescription(SensorEntityDescription):
    """Describes a scale sensor."""

    value_fn: Callable[[TuyaBLEScaleCoordinator], float | int | datetime | None]
    # Only meaningful while connected (live stream).
    live: bool = False


SENSORS: tuple[TuyaBLEScaleSensorDescription, ...] = (
    TuyaBLEScaleSensorDescription(
        key="weight",
        translation_key="weight",
        device_class=SensorDeviceClass.WEIGHT,
        state_class=SensorStateClass.MEASUREMENT,
        native_unit_of_measurement=UnitOfMass.KILOGRAMS,
        suggested_display_precision=1,
        value_fn=lambda c: c.weight,
    ),
    TuyaBLEScaleSensorDescription(
        key="last_weigh_in",
        translation_key="last_weigh_in",
        device_class=SensorDeviceClass.TIMESTAMP,
        value_fn=lambda c: c.measured_at,
    ),
    TuyaBLEScaleSensorDescription(
        key="live_weight",
        translation_key="live_weight",
        device_class=SensorDeviceClass.WEIGHT,
        native_unit_of_measurement=UnitOfMass.KILOGRAMS,
        suggested_display_precision=1,
        entity_registry_enabled_default=False,
        live=True,
        value_fn=lambda c: c.live_weight,
    ),
    TuyaBLEScaleSensorDescription(
        key="impedance",
        translation_key="impedance",
        entity_category=EntityCategory.DIAGNOSTIC,
        entity_registry_enabled_default=False,
        value_fn=lambda c: c.impedance,
    ),
)


async def async_setup_entry(
    hass: HomeAssistant,
    entry: TuyaBLEScaleConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    """Add sensors."""
    coordinator = entry.runtime_data
    async_add_entities(TuyaBLEScaleSensor(coordinator, desc) for desc in SENSORS)


class TuyaBLEScaleSensor(SensorEntity):
    """A scale value. Stays available between weigh-ins (except live values)."""

    _attr_has_entity_name = True
    _attr_should_poll = False
    entity_description: TuyaBLEScaleSensorDescription

    def __init__(
        self,
        coordinator: TuyaBLEScaleCoordinator,
        description: TuyaBLEScaleSensorDescription,
    ) -> None:
        self.coordinator = coordinator
        self.entity_description = description
        self._attr_unique_id = f"{coordinator.address}_{description.key}"
        self._attr_device_info = DeviceInfo(
            connections={(CONNECTION_BLUETOOTH, coordinator.address)},
            identifiers={(DOMAIN, coordinator.address)},
            manufacturer="Tuya",
            model="BLE body-fat scale",
            name="Tuya BLE Scale",
            sw_version=coordinator.device_version,
        )

    async def async_added_to_hass(self) -> None:
        self.async_on_remove(self.coordinator.async_add_listener(self.async_write_ha_state))

    @property
    def available(self) -> bool:
        if self.entity_description.live:
            return self.coordinator.connected
        return True

    @property
    def native_value(self) -> float | int | datetime | None:
        return self.entity_description.value_fn(self.coordinator)
