#!/usr/bin/env python3
"""Pull local_key[:6] out of a tuya_keydump.js log.

The Tuya app computes login_key = MD5(local_key[:6]) and then builds an AES key
from it. The Frida script logs both: every short MD5 input ("[MD5 in] len=6 ...")
and every AES key ("[AES key] len=16 ..."). A 6-byte MD5 input whose digest also
shows up as an AES key is the real local_key[:6]; anything else is noise.

Usage:  python find_local_key.py fridalog.txt
"""

from __future__ import annotations

import hashlib
from pathlib import Path
import re
import sys

MD5_IN = re.compile(r"MD5 in\] len=6\s+ascii=\"(.{6})\"\s+hex=([0-9a-f]{12})")
AES_KEY = re.compile(r"\[AES key\] len=16\s+hex=([0-9a-f]{32})")


def read_log(path: Path) -> str:
    raw = path.read_bytes()
    # PowerShell redirection writes UTF-16; frida -o writes UTF-8.
    if raw[:2] in (b"\xff\xfe", b"\xfe\xff") or raw[1:2] == b"\x00":
        return raw.decode("utf-16", errors="replace")
    return raw.decode("utf-8", errors="replace")


def main(path: Path) -> int:
    text = read_log(path)
    candidates = {hex_: ascii_ for ascii_, hex_ in MD5_IN.findall(text)}
    aes_keys = set(AES_KEY.findall(text))
    if not candidates:
        print("No 6-byte MD5 inputs in the log. Did the app actually connect to the scale?")
        return 1

    verified = [h for h in candidates if hashlib.md5(bytes.fromhex(h)).hexdigest() in aes_keys]
    for hex_ in verified:
        print(f"local_key[:6] = {hex_}   (ascii {candidates[hex_]!r})  <- verified")
    if verified:
        print("\nEnter the hex value as local_key in Home Assistant.")
        return 0

    print("Found 6-byte MD5 inputs, but none matched a logged AES key:")
    for hex_, ascii_ in candidates.items():
        print(f"  {hex_}   (ascii {ascii_!r})")
    print("One of them is probably the key. Try them in Home Assistant, or rerun the capture.")
    return 2


if __name__ == "__main__":
    if len(sys.argv) != 2:
        sys.exit(__doc__)
    sys.exit(main(Path(sys.argv[1])))
