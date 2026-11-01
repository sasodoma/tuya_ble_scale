"""Tuya BLE wire protocol: fragmentation, AES-128-CBC framing and datapoints.

Pure Python (only depends on ``cryptography``) so it can be unit-tested
without Home Assistant or a Bluetooth adapter.

Wire format (see HANDOFF.md §4-§7)::

    GATT packet   = varint(frag_seq) || [varint(total_len) || protover<<4]  (first only) || chunk
    payload       = security_flag(1) || IV(16) || AES-128-CBC(plaintext)
    plaintext     = sn(4) | ack_sn(4) | code(2) | data_len(2) | data | crc16(2) | zero-pad to 16
    datapoint     = id(1) | type(1) | len(1) | value[len]
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import IntEnum
import hashlib
import secrets
import struct
import time
from typing import Any

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

GATT_MTU = 20
# Protocol version sent in the first fragment header (app -> device).
CLIENT_PROTOCOL_VERSION = 2
PAIR_DATA_LEN = 44


class TuyaBLECode(IntEnum):
    """Command codes."""

    FUN_SENDER_DEVICE_INFO = 0x0000
    FUN_SENDER_PAIR = 0x0001
    FUN_SENDER_DPS = 0x0002
    FUN_SENDER_DEVICE_STATUS = 0x0003
    FUN_RECEIVE_DP = 0x8001
    FUN_RECEIVE_TIME_DP = 0x8003
    FUN_RECEIVE_SIGN_DP = 0x8004
    FUN_RECEIVE_SIGN_TIME_DP = 0x8005
    FUN_RECEIVE_TIME1_REQ = 0x8011
    FUN_RECEIVE_TIME2_REQ = 0x8012


class SecurityFlag(IntEnum):
    """Which key encrypts a payload."""

    LOGIN_KEY = 0x04
    SESSION_KEY = 0x05


class DPType(IntEnum):
    """Datapoint value types."""

    RAW = 0
    BOOLEAN = 1
    VALUE = 2
    STRING = 3
    ENUM = 4
    BITMAP = 5


class TuyaBLEProtocolError(Exception):
    """Malformed or undecryptable data."""


class TuyaBLECRCError(TuyaBLEProtocolError):
    """CRC mismatch after decryption - almost always a wrong local_key."""


# --------------------------------------------------------------------------- #
# Primitives
# --------------------------------------------------------------------------- #


def calc_crc16(data: bytes) -> int:
    """CRC-16 (poly 0xA001, init 0xFFFF) as used by Tuya BLE."""
    crc = 0xFFFF
    for byte in data:
        crc ^= byte
        for _ in range(8):
            lsb = crc & 1
            crc >>= 1
            if lsb:
                crc ^= 0xA001
    return crc


def pack_varint(value: int) -> bytes:
    """Little-endian base-128 varint."""
    out = bytearray()
    while True:
        byte = value & 0x7F
        value >>= 7
        if value:
            out.append(byte | 0x80)
        else:
            out.append(byte)
            return bytes(out)


def unpack_varint(data: bytes, pos: int) -> tuple[int, int]:
    """Decode a varint at ``pos``; return (value, new_pos)."""
    value = shift = 0
    while True:
        if pos >= len(data):
            raise TuyaBLEProtocolError("Truncated varint")
        byte = data[pos]
        pos += 1
        value |= (byte & 0x7F) << shift
        if not byte & 0x80:
            return value, pos
        shift += 7


def _aes_cbc_encrypt(key: bytes, iv: bytes, data: bytes) -> bytes:
    enc = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()
    return enc.update(data) + enc.finalize()


def _aes_cbc_decrypt(key: bytes, iv: bytes, data: bytes) -> bytes:
    dec = Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor()
    return dec.update(data) + dec.finalize()


def login_key_from_local_key(local_key6: bytes) -> bytes:
    """login_key = MD5(local_key[:6])."""
    return hashlib.md5(local_key6[:6]).digest()


def session_key_from_srand(local_key6: bytes, srand: bytes) -> bytes:
    """session_key = MD5(local_key[:6] + srand)."""
    return hashlib.md5(local_key6[:6] + srand).digest()


def normalize_local_key(value: str) -> bytes:
    """Turn user input into the 6 key bytes used for BLE crypto.

    Accepts 12 hex characters (``a1b2c3d4e5f6``) or the ASCII key itself
    (6 characters, or the full 16-character local_key, of which the first 6
    are used).
    """
    value = value.strip()
    if len(value) == 12:
        try:
            return bytes.fromhex(value)
        except ValueError:
            pass
    raw = value.encode("utf-8")
    if len(raw) < 6:
        raise ValueError("local_key must be at least 6 characters (or 12 hex digits)")
    return raw[:6]


# --------------------------------------------------------------------------- #
# Frames
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class TuyaBLEFrame:
    """A decrypted, CRC-checked frame."""

    security_flag: int
    sn: int
    ack_sn: int
    code: int
    data: bytes


def build_plaintext(sn: int, ack_sn: int, code: int, data: bytes) -> bytes:
    """Header + data + crc16, zero-padded to the AES block size."""
    raw = struct.pack(">IIHH", sn, ack_sn, code, len(data)) + data
    raw += struct.pack(">H", calc_crc16(raw))
    if len(raw) % 16:
        raw += bytes(16 - len(raw) % 16)
    return raw


def build_packets(
    key: bytes,
    security_flag: int,
    sn: int,
    ack_sn: int,
    code: int,
    data: bytes = b"",
    *,
    iv: bytes | None = None,
    mtu: int = GATT_MTU,
    protocol_version: int = CLIENT_PROTOCOL_VERSION,
) -> list[bytes]:
    """Encrypt a frame and split it into GATT-sized packets."""
    if iv is None:
        iv = secrets.token_bytes(16)
    encrypted = (
        bytes([security_flag])
        + iv
        + _aes_cbc_encrypt(key, iv, build_plaintext(sn, ack_sn, code, data))
    )
    packets: list[bytes] = []
    pos = 0
    frag = 0
    while pos < len(encrypted):
        header = pack_varint(frag)
        if frag == 0:
            header += pack_varint(len(encrypted)) + bytes([protocol_version << 4])
        chunk = encrypted[pos : pos + mtu - len(header)]
        packets.append(header + chunk)
        pos += len(chunk)
        frag += 1
    return packets


def decrypt_payload(payload: bytes, login_key: bytes, session_key: bytes | None) -> TuyaBLEFrame:
    """Decrypt a reassembled payload (flag || IV || ciphertext) and verify CRC."""
    if len(payload) < 33 or (len(payload) - 17) % 16:
        raise TuyaBLEProtocolError(f"Bad payload length {len(payload)}")
    flag = payload[0]
    if flag == SecurityFlag.LOGIN_KEY:
        key = login_key
    elif flag == SecurityFlag.SESSION_KEY:
        if session_key is None:
            raise TuyaBLEProtocolError("Session-key frame before session key known")
        key = session_key
    else:
        raise TuyaBLEProtocolError(f"Unsupported security flag {flag:#x}")
    raw = _aes_cbc_decrypt(key, payload[1:17], payload[17:])
    sn, ack_sn, code, length = struct.unpack(">IIHH", raw[:12])
    end = 12 + length
    if end + 2 > len(raw):
        raise TuyaBLECRCError("Data length exceeds frame (wrong key?)")
    if calc_crc16(raw[:end]) != int.from_bytes(raw[end : end + 2], "big"):
        raise TuyaBLECRCError("CRC mismatch (wrong local_key?)")
    return TuyaBLEFrame(flag, sn, ack_sn, code, bytes(raw[12:end]))


class Reassembler:
    """Collects GATT notification fragments into complete encrypted payloads."""

    def __init__(self) -> None:
        self._buffer = bytearray()
        self._expected_len = 0
        self._expected_frag = 0
        self._last_packet: bytes | None = None

    def reset(self) -> None:
        self._buffer.clear()
        self._expected_len = 0
        self._expected_frag = 0

    def feed(self, packet: bytes) -> bytes | None:
        """Add one packet; return the payload once complete, else None."""
        packet = bytes(packet)
        if packet == self._last_packet:
            # Exact repeat of the previous fragment (link-layer retransmit as
            # seen by a sniffer); fresh fragments always differ (random IV).
            return None
        frag, pos = unpack_varint(packet, 0)
        if frag == 0:
            self.reset()
            self._expected_len, pos = unpack_varint(packet, pos)
            pos += 1  # protocol version byte
        elif frag != self._expected_frag:
            self.reset()
            raise TuyaBLEProtocolError(
                f"Fragment {frag} out of order (expected {self._expected_frag})"
            )
        self._buffer += packet[pos:]
        self._expected_frag = frag + 1
        self._last_packet = packet
        if len(self._buffer) < self._expected_len:
            return None
        payload = bytes(self._buffer[: self._expected_len])
        overflow = len(self._buffer) > self._expected_len
        self.reset()
        if overflow:
            raise TuyaBLEProtocolError("Reassembled payload longer than announced")
        return payload


# --------------------------------------------------------------------------- #
# Datapoints
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class DataPoint:
    """One datapoint."""

    id: int
    type: DPType
    value: Any
    raw: bytes = field(repr=False)


def parse_datapoints(data: bytes, start: int = 0) -> list[DataPoint]:
    """Parse a v3 TLV datapoint list."""
    dps: list[DataPoint] = []
    pos = start
    while len(data) - pos >= 3:
        dp_id, dp_type, dp_len = data[pos], data[pos + 1], data[pos + 2]
        pos += 3
        raw = data[pos : pos + dp_len]
        if len(raw) != dp_len:
            raise TuyaBLEProtocolError(f"Truncated datapoint {dp_id}")
        pos += dp_len
        try:
            typ = DPType(dp_type)
        except ValueError as err:
            raise TuyaBLEProtocolError(f"Unknown DP type {dp_type}") from err
        if typ == DPType.VALUE:
            value: Any = int.from_bytes(raw, "big", signed=True)
        elif typ == DPType.BOOLEAN:
            value = raw != bytes(dp_len) if dp_len else False
        elif typ in (DPType.ENUM, DPType.BITMAP):
            value = int.from_bytes(raw, "big")
        elif typ == DPType.STRING:
            value = raw.decode("utf-8", errors="replace")
        else:
            value = bytes(raw)
        dps.append(DataPoint(dp_id, typ, value, bytes(raw)))
    return dps


def parse_timestamp(data: bytes, pos: int) -> tuple[float | None, int]:
    """Parse a time_type-prefixed timestamp; return (unix seconds, new_pos)."""
    time_type = data[pos]
    pos += 1
    if time_type == 0:
        return int(data[pos : pos + 13].decode()) / 1000, pos + 13
    if time_type == 1:
        return float(int.from_bytes(data[pos : pos + 4], "big")), pos + 4
    raise TuyaBLEProtocolError(f"Unknown time type {time_type}")


@dataclass(frozen=True)
class DPReport:
    """Datapoints from a device report, plus what to answer."""

    datapoints: list[DataPoint]
    timestamp: float | None
    ack_data: bytes


def parse_dp_report(code: int, data: bytes) -> DPReport:
    """Decode a 0x8001/0x8003/0x8004/0x8005 report and build its ACK payload."""
    if code == TuyaBLECode.FUN_RECEIVE_DP:
        return DPReport(parse_datapoints(data), None, b"\x00")
    if code == TuyaBLECode.FUN_RECEIVE_TIME_DP:
        ts, pos = parse_timestamp(data, 0)
        return DPReport(parse_datapoints(data, pos), ts, b"\x00")
    if code == TuyaBLECode.FUN_RECEIVE_SIGN_DP:
        dp_seq, flags = struct.unpack(">HB", data[:3])
        return DPReport(parse_datapoints(data, 3), None, struct.pack(">HBB", dp_seq, flags, 0))
    if code == TuyaBLECode.FUN_RECEIVE_SIGN_TIME_DP:
        dp_seq, flags = struct.unpack(">HB", data[:3])
        ts, pos = parse_timestamp(data, 3)
        return DPReport(parse_datapoints(data, pos), ts, struct.pack(">HBB", dp_seq, flags, 0))
    raise TuyaBLEProtocolError(f"Not a DP report code {code:#06x}")


# --------------------------------------------------------------------------- #
# Requests / responses
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class DeviceInfo:
    """Parsed device-info (code 0x0000) response."""

    device_version: str
    protocol_version: str
    is_bound: bool
    srand: bytes


def parse_device_info(data: bytes) -> DeviceInfo:
    if len(data) < 12:
        raise TuyaBLEProtocolError("Device info response too short")
    return DeviceInfo(
        device_version=f"{data[0]}.{data[1]}",
        protocol_version=f"{data[2]}.{data[3]}",
        is_bound=data[5] != 0,
        srand=bytes(data[6:12]),
    )


def build_pair_data(uuid: str, local_key6: bytes, device_id: str) -> bytes:
    """uuid || local_key[:6] || device_id, zero-padded to 44 bytes."""
    data = uuid.encode() + local_key6[:6] + device_id.encode()
    if len(data) > PAIR_DATA_LEN:
        raise ValueError("uuid/device_id too long for pair request")
    return data + bytes(PAIR_DATA_LEN - len(data))


def build_time1_response(now: float | None = None, utc_offset_s: int | None = None) -> bytes:
    """Answer to 0x8011: ASCII ms timestamp + int16 timezone (hours*100)."""
    if now is None:
        now = time.time()
    if utc_offset_s is None:
        utc_offset_s = time.localtime(now).tm_gmtoff
    return str(int(now * 1000)).encode() + struct.pack(">h", round(utc_offset_s / 36))


def build_time2_response(now: float | None = None, utc_offset_s: int | None = None) -> bytes:
    """Answer to 0x8012: broken-down local time + timezone."""
    if now is None:
        now = time.time()
    lt = time.localtime(now)
    if utc_offset_s is None:
        utc_offset_s = lt.tm_gmtoff
    return struct.pack(
        ">BBBBBBBh",
        lt.tm_year % 100,
        lt.tm_mon,
        lt.tm_mday,
        lt.tm_hour,
        lt.tm_min,
        lt.tm_sec,
        lt.tm_wday,
        round(utc_offset_s / 36),
    )


# --------------------------------------------------------------------------- #
# Advertisement
# --------------------------------------------------------------------------- #


def decode_uuid_from_advertisement(
    service_data: bytes | None, manufacturer_data: bytes | None
) -> str | None:
    """Derive the Tuya uuid from the 0xA201 service data + 0x07D0 manufacturer data.

    uuid = AES-CBC(key=iv=MD5(product_id)).decrypt(mfg[6:]); returns None if the
    advert lacks either part or the result isn't a printable ASCII id.
    """
    if not service_data or len(service_data) < 2 or service_data[0] != 0:
        return None
    if not manufacturer_data or len(manufacturer_data) <= 6:
        return None
    raw_uuid = manufacturer_data[6:]
    if len(raw_uuid) % 16:
        return None
    key = hashlib.md5(service_data[1:]).digest()
    plain = _aes_cbc_decrypt(key, key, raw_uuid).rstrip(b"\x00")
    try:
        uuid = plain.decode("ascii")
    except UnicodeDecodeError:
        return None
    if not uuid or not uuid.isalnum():
        return None
    return uuid
