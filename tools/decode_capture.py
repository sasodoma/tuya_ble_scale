#!/usr/bin/env python3
"""Decrypt a Bluetooth sniffer capture of a Tuya BLE scale session.

Handy for checking a local_key before going to Home Assistant, or for mapping
datapoints on a scale that differs from the one this was written for. It uses
the integration's own protocol code, so a capture that decodes here will decode
in Home Assistant too.

Usage:  python decode_capture.py capture.pcapng 1a2b3c4d5e6f
        (key = local_key[:6] as 12 hex digits, or the 6-character text)

Needs tshark (Wireshark) on PATH, or set TSHARK=/path/to/tshark, plus
`pip install cryptography`.
"""

from __future__ import annotations

import importlib
import os
from pathlib import Path
import shutil
import subprocess
import sys
import types

COMPONENT = Path(__file__).resolve().parent.parent / "custom_components" / "tuya_ble_scale"
WINDOWS_TSHARK = r"C:\Program Files\Wireshark\tshark.exe"

# ATT opcodes: write request / write command (app -> scale), notification / indication.
TO_SCALE = {"0x12", "0x52"}
FROM_SCALE = {"0x1b", "0x1d"}


def load_proto() -> types.ModuleType:
    """Import tuya_ble_proto without running the Home Assistant package __init__."""
    pkg = types.ModuleType("tuya_ble_scale")
    pkg.__path__ = [str(COMPONENT)]
    sys.modules.setdefault("tuya_ble_scale", pkg)
    return importlib.import_module("tuya_ble_scale.tuya_ble_proto")


def att_values(pcap: str) -> list[tuple[str, str, str, bytes]]:
    tshark = os.environ.get("TSHARK") or shutil.which("tshark") or WINDOWS_TSHARK
    out = subprocess.run(
        [tshark, "-r", pcap, "-Y", "btatt.value", "-T", "fields",
         "-e", "frame.number", "-e", "btatt.opcode", "-e", "btatt.handle", "-e", "btatt.value"],
        capture_output=True, text=True, check=True,
    ).stdout
    rows = []
    for line in out.splitlines():
        parts = line.split("\t")
        if len(parts) == 4 and parts[3]:
            rows.append((parts[0], parts[1], parts[2], bytes.fromhex(parts[3])))
    return rows


def main(pcap: str, key: str) -> None:
    proto = load_proto()
    key6 = proto.normalize_local_key(key)
    login_key = proto.login_key_from_local_key(key6)
    session_key = None
    reassemblers: dict[tuple[str, str], object] = {}
    weights = []

    for frame_no, opcode, handle, value in att_values(pcap):
        if opcode in TO_SCALE:
            direction = "app->scale"
        elif opcode in FROM_SCALE:
            direction = "scale->app"
        else:
            continue
        rx = reassemblers.setdefault((direction, handle), proto.Reassembler())
        try:
            payload = rx.feed(value)
            if payload is None:
                continue
            frame = proto.decrypt_payload(payload, login_key, session_key)
        except proto.TuyaBLECRCError:
            print(f"#{frame_no} {direction}: CRC mismatch - wrong key for this capture?")
            continue
        except proto.TuyaBLEProtocolError:
            continue  # not a Tuya frame, or a fragment we missed

        line = f"#{frame_no:<6} {direction}  code={frame.code:#06x} sn={frame.sn} ack={frame.ack_sn}"
        if frame.code == proto.TuyaBLECode.FUN_SENDER_DEVICE_INFO and direction == "scale->app":
            info = proto.parse_device_info(frame.data)
            session_key = proto.session_key_from_srand(key6, info.srand)
            line += f"  device-info v{info.device_version}, session key derived"
        elif direction == "scale->app" and frame.code in (0x8001, 0x8003, 0x8004, 0x8005):
            report = proto.parse_dp_report(frame.code, frame.data)
            dps = "  ".join(f"dp{dp.id}={dp.value}" for dp in report.datapoints)
            line += f"  {dps}"
            for dp in report.datapoints:
                if dp.id == 1 and dp.type == proto.DPType.VALUE:
                    weights.append(dp.value / 10)
                    line += f"   => WEIGHT {dp.value / 10:.1f} kg"
        elif frame.data:
            line += f"  data={frame.data.hex()}"
        print(line)

    if session_key is None:
        print("\nNo device-info exchange found: the capture must include the connection start.")
    elif not weights:
        print("\nKey works, but no final weight (dp1) in this capture.")


if __name__ == "__main__":
    if len(sys.argv) != 3:
        sys.exit(__doc__)
    main(sys.argv[1], sys.argv[2])
