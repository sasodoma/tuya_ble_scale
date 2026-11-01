# Tuya BLE Scale for Home Assistant (local)

> [!CAUTION]
> TRIGGER WARNING! This repo is almost completely vibe coded. If you don't
> like that feel free to use the findings to write your own integration
> in accordance with GPLv3.

A Home Assistant custom integration that reads weight from a Tuya Bluetooth
body-fat scale. It talks to the scale directly through Home Assistant's
Bluetooth stack. There is no Tuya cloud account, no MQTT broker and no bridge
app in the loop.

The only requirement is the key. Every Tuya BLE device encrypts its traffic with a
per-device `local_key` that lives in the Tuya cloud. Many scales are "no-bind"
or shared devices that don't show up in the Tuya developer API, so there is no
way to fetch that key. This repo includes a Frida script that reads it out
of the Tuya app on a rooted Android phone. This needs to be done once.

## Does it work with my scale?

Written for and tested with a scale that advertises as **`TY`**, uses the Tuya
BLE service `0x1910` and reports firmware 4.5. If your scale shows up in the
Smart Life or Tuya Smart app as a Bluetooth body-fat scale, it very likely uses
the same protocol. The datapoint numbers could still differ. The weight is
`dp1` (final) and `dp9` (live), both in 0.1 kg. If you get a connection but no
weight, run [`tools/decode_capture.py`](#checking-a-key-with-a-sniffer-optional)
on a sniffer capture to see what your scale sends.

Needs Home Assistant 2024.11 or newer, with a working Bluetooth adapter or an
ESPHome Bluetooth proxy that supports active connections.

## What you need before you start

| Value | Where it comes from |
|---|---|
| `local_key` | Only the first 6 bytes are used. [Get it with Frida](#getting-the-local_key-with-frida), or from the Tuya cloud if your device is listed there. |
| `device_id` | Shown in the Tuya app ([below](#finding-the-device_id)). |
| `uuid` | Nothing to do. The integration reads it from the scale's Bluetooth advertisement. |

## Install

**HACS:** add this repository as a custom repository (category *Integration*),
install *Tuya BLE Scale (local)* and restart Home Assistant.

**By hand:** copy `custom_components/tuya_ble_scale/` into your Home Assistant
`config/custom_components/` folder and restart.

## Set up

1. Step on the scale. It is only visible over Bluetooth while it is awake, which
   means while someone is standing on it and for a short while after.
2. It appears under **Settings → Devices & services → Discovered**. If it
   doesn't, choose **Add integration → Tuya BLE Scale (local)**. Then pick it
   from the list or type its MAC address.
3. Enter the `local_key` and `device_id`. The key can be 12 hex digits
   (`a1b2c3d4e5f6`) or the key text itself. Hex is safer, because the text
   often starts with punctuation that is easy to mistype. Leave `uuid` as it
   is. If it is empty, it gets filled in on the next weigh-in.

Nothing connects during setup, because the scale is probably asleep by then.
The first real connection happens the next time someone steps on it.

## Entities

| Entity | What it shows |
|---|---|
| Weight | Final weight in kg (`device_class: weight`, `state_class: measurement`). Kept across restarts. |
| Last weigh-in | Time of the last measurement. It changes on every weigh-in, even if the weight doesn't, so use this one to trigger automations. |
| Live weight | Disabled by default. The number shown on the display while you stand on the scale. Available only while connected. |
| Impedance | Disabled by default. The raw `dp7` value. It is 0 when you're wearing socks. I haven't worked out the units. |

Each new weigh-in also fires the `tuya_ble_scale_measurement` event, with
`address`, `weight`, `impedance` and `measured_at`.

## Finding the device_id

In the Smart Life or Tuya Smart app, open the scale, tap the pencil or "⋯" in
the top-right corner and open **Device Information**. The `device_id` is the
**Virtual ID**, a string of about 16–22 letters and digits. The menu wording
changes between app versions, but it's always somewhere in that device-info
screen.

## Getting the local_key with Frida

Got a cloud account that lists the scale, through the Tuya IoT platform or
`tinytuya wizard`? Then use the `local_key` from there and skip this section.
Shared and no-bind scales won't be listed, though. For those, take the key from
the app while it talks to the scale.

This works because the app computes `MD5(local_key[:6])` every time it connects
to the scale. [`tools/tuya_keydump.js`](tools/tuya_keydump.js) hooks Java's
`MessageDigest` and logs every short MD5 input, and the AES keys the app builds
from them. [`tools/find_local_key.py`](tools/find_local_key.py) then picks the
6-byte input whose MD5 matches one of the logged AES keys. That match proves
it's the key and not a coincidence.

### What you need

- A **rooted** Android phone or tablet (Magisk works) with the scale already
  added in the Tuya or Smart Life app.
- `adb` on your computer (Android SDK platform-tools), with USB debugging
  enabled on the phone.
- Python 3 on the computer.

### Steps

1. Install Frida on the computer and note the version:

   ```
   pip install frida-tools
   frida --version
   ```

2. Find the phone's CPU type:

   ```
   adb shell getprop ro.product.cpu.abi
   ```

   `arm64-v8a` means `arm64`. Download the file
   `frida-server-<same version>-android-arm64.xz` from
   [Frida's releases](https://github.com/frida/frida/releases). The version has
   to match `frida --version` exactly. Unpack it with `unxz`, or 7-Zip on
   Windows, and rename the result to `frida-server`.

3. Copy it to the phone and start it as root:

   ```
   adb push frida-server /data/local/tmp/
   adb shell "su -c 'chmod 755 /data/local/tmp/frida-server'"
   adb shell "su -c '/data/local/tmp/frida-server -D'"
   ```

   The first `su` makes Magisk ask for permission on the phone, so watch the
   screen and tap Grant. If the last command hangs, leave it running and open a
   second terminal.

4. Check that the computer can see the phone's processes, and find the app's
   package name:

   ```
   frida-ps -Uai
   ```

   Tuya Smart is `com.tuya.smart`. Smart Life is `com.tuya.smartlife`. White-label
   apps have their own names, so look for the app's label in the list.

5. If Home Assistant is already set up for this scale, disable the integration
   for now. The scale accepts one connection at a time, and the app needs it.

6. Start the app under Frida, with the log going to a file:

   ```
   frida -U -f com.tuya.smart -l tools/tuya_keydump.js -o fridalog.txt
   ```

   The app opens on the phone. Open the scale in the app and step on it. Wait
   until the app shows your weight, because that means it has connected and
   finished the handshake. Then type `exit` at the Frida prompt.

7. Read the key out of the log:

   ```
   python tools/find_local_key.py fridalog.txt
   ```

   The result looks like `local_key[:6] = 1a2b3c4d5e6f ... <- verified`. Enter
   that hex value in Home Assistant.

`fridalog.txt` contains your key. Don't commit it or post it anywhere. The
`.gitignore` in this repo already excludes it.

### If it doesn't work

- **The app freezes or gets killed under Frida.** An earlier version of the
  script also hooked SHA-1 and SHA-256, and the flood of log lines made Android
  kill the app as unresponsive. The shipped script only logs MD5. If you add
  hooks, filter them hard.
- **`find_local_key.py` finds no 6-byte inputs.** The app never got far enough
  into the handshake. Make sure Bluetooth is on and you stood on the scale long
  enough for the app to show a weight. Also check that nothing else, such as
  Home Assistant or another phone, was connected to the scale.
- **Inputs found, but none verified.** The script lists the candidates anyway.
  Usually one of them is correct, so try it.
- **The key worked before and now Home Assistant reports a decryption
  failure.** Removing the scale from the app and adding it again, or resetting
  it, makes the cloud issue a new key. Run the Frida steps again, then enter
  the new key in the re-authentication prompt that Home Assistant shows.

## Checking a key with a sniffer (optional)

Here's a quick way to test a key, or to work out the datapoints of a different
scale. Record the scale's Bluetooth traffic while the app connects. Android's
*Bluetooth HCI snoop log* developer option works, and so does an nRF52 sniffer
with Wireshark. Then run:

```
python tools/decode_capture.py capture.pcapng 1a2b3c4d5e6f
```

It needs `tshark` from Wireshark, and `pip install cryptography`. Every
message is decrypted with the integration's own code and printed with its
datapoints, and final weights are marked `=> WEIGHT 72.4 kg`. A wrong key shows
up right away as CRC mismatches. The capture must include the start of the
connection, since the session key is derived from the first exchange.

## Troubleshooting

- **No weight after stepping on the scale.** Turn on debug logging for
  `custom_components.tuya_ble_scale` and weigh yourself again. Lines starting
  with `<-` are decrypted messages from the scale. If there are none, Home
  Assistant didn't connect in time. A Bluetooth adapter or proxy closer to the
  scale helps, because the scale only stays awake for a few seconds after you
  step off.
- **The phone app is open nearby.** It may grab the connection before Home
  Assistant does. Close it.
- **"rejected the credentials" in the log.** The key or `device_id` is wrong,
  or the key changed. See the last item in [If it doesn't work](#if-it-doesnt-work).

## How it works

One connection per weigh-in. When the scale advertises, the integration
connects and subscribes to notifications on `0x2b10`. It then sends three
requests on `0x2b11`: device info, encrypted with `MD5(local_key[:6])`; pair,
with `uuid + local_key[:6] + device_id`, encrypted with
`MD5(local_key[:6] + srand)`; and a status query. After that the scale streams
live weights (`0x8005`) and finally a weigh-complete record (`0x8003`) that
carries `dp1`. The integration acknowledges every report the same way the app
does. It also answers the scale's time request, so record timestamps are
correct. It disconnects a few seconds after the final record.

Messages are AES-128-CBC with a fresh IV each time and a CRC16 inside the
plaintext, split into 20-byte GATT packets. The protocol code lives in
[`tuya_ble_proto.py`](custom_components/tuya_ble_scale/tuya_ble_proto.py), has
no Home Assistant imports, and can be reused on its own.

Records come with the scale's own timestamp. A record that isn't newer than the
last one stored is ignored. That stops a reconnect, or an old offline
measurement, from overwriting the latest weight.

Known gaps: `dp11` is probably the display unit, and nothing here handles a
scale that is set to pounds. The impedance value isn't turned into body-fat
numbers.

## Credits

The Tuya BLE framing, pairing and key derivation follow the reverse-engineering
in [PlusPlus-ua/ha_tuya_ble](https://github.com/PlusPlus-ua/ha_tuya_ble). This
integration doesn't use or need that project, but it was the map.

## License

GPL-3.0. See [LICENSE](LICENSE).
