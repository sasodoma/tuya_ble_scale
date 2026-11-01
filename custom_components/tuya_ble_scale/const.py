"""Constants for the Tuya BLE Scale integration."""

from __future__ import annotations

DOMAIN = "tuya_ble_scale"

CONF_LOCAL_KEY = "local_key"  # stored as 12 hex chars = local_key[:6]
CONF_DEVICE_ID = "device_id"
CONF_UUID = "uuid"

TUYA_MANUFACTURER_ID = 0x07D0
TUYA_SERVICE_DATA_UUID = "0000a201-0000-1000-8000-00805f9b34fb"
TUYA_GATT_SERVICE_UUID = "00001910-0000-1000-8000-00805f9b34fb"
TUYA_LOCAL_NAME = "TY"

EVENT_MEASUREMENT = f"{DOMAIN}_measurement"

# Pause before reconnecting after a session (the scale keeps advertising for a
# while after a weigh-in; a reconnect would only replay the same record).
COOLDOWN_AFTER_SUCCESS = 15.0
COOLDOWN_AFTER_FAILURE = 5.0
COOLDOWN_AFTER_AUTH_FAILURE = 300.0
