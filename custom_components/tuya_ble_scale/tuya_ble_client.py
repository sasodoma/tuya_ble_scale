"""Live Bleak client: connect, run the Tuya BLE handshake, stream weight.

One :class:`TuyaBLEScaleSession` = one connection to the scale. The scale is
only connectable while someone stands on it, so a session is short-lived:
connect -> device-info -> pair -> status-query -> collect DP reports ->
disconnect after the final (0x8003) record or when the stream goes idle.

Only Bleak / bleak-retry-connector are used here (no Home Assistant imports),
so the protocol loop can be exercised in tests with a fake client.
"""

from __future__ import annotations

import asyncio
from collections.abc import Callable
from dataclasses import dataclass, field
import logging
from typing import Any

from bleak import BleakClient
from bleak.backends.characteristic import BleakGATTCharacteristic
from bleak.backends.device import BLEDevice
from bleak_retry_connector import BleakClientWithServiceCache, establish_connection

from .tuya_ble_proto import (
    DataPoint,
    SecurityFlag,
    TuyaBLECode,
    TuyaBLECRCError,
    TuyaBLEFrame,
    TuyaBLEProtocolError,
    Reassembler,
    build_packets,
    build_pair_data,
    build_time1_response,
    build_time2_response,
    decrypt_payload,
    login_key_from_local_key,
    parse_device_info,
    parse_dp_report,
    session_key_from_srand,
)

_LOGGER = logging.getLogger(__name__)

SERVICE_UUID = "00001910-0000-1000-8000-00805f9b34fb"
CHARACTERISTIC_WRITE = "00002b11-0000-1000-8000-00805f9b34fb"
CHARACTERISTIC_NOTIFY = "00002b10-0000-1000-8000-00805f9b34fb"

# Datapoints (HANDOFF.md §7)
DP_WEIGHT = 1  # final stabilized weight, 0.1 kg
DP_IMPEDANCE = 7  # 0 when there was no skin contact
DP_LIVE_WEIGHT = 9  # real-time weight while standing, 0.1 kg

PAIR_RESULT_OK = (0x00, 0x02)  # 0 = paired, 2 = already paired

_DP_REPORT_CODES = {
    TuyaBLECode.FUN_RECEIVE_DP,
    TuyaBLECode.FUN_RECEIVE_TIME_DP,
    TuyaBLECode.FUN_RECEIVE_SIGN_DP,
    TuyaBLECode.FUN_RECEIVE_SIGN_TIME_DP,
}


class TuyaBLEScaleError(Exception):
    """Connection or protocol failure."""


class TuyaBLEScaleAuthError(TuyaBLEScaleError):
    """local_key / device_id / uuid rejected by the scale."""


class TuyaBLEScaleTimeout(TuyaBLEScaleError):
    """The scale did not answer a request in time."""


@dataclass(frozen=True)
class TuyaBLEScaleCredentials:
    """Everything needed to talk to one scale."""

    local_key6: bytes
    device_id: str
    uuid: str


@dataclass(frozen=True)
class ScaleReading:
    """A weight value pushed by the scale."""

    weight_kg: float
    final: bool
    timestamp: float | None = None
    impedance: int | None = None
    datapoints: dict[int, Any] = field(default_factory=dict)


class TuyaBLEScaleSession:
    """A single connection to the scale."""

    def __init__(
        self,
        credentials: TuyaBLEScaleCredentials,
        on_reading: Callable[[ScaleReading], None],
        *,
        response_timeout: float = 5.0,
        idle_timeout: float = 20.0,
        linger_after_final: float = 3.0,
    ) -> None:
        self._creds = credentials
        self._on_reading = on_reading
        self._response_timeout = response_timeout
        self._idle_timeout = idle_timeout
        self._linger_after_final = linger_after_final

        self._login_key = login_key_from_local_key(credentials.local_key6)
        self._session_key: bytes | None = None
        self._reassembler = Reassembler()
        self._client: BleakClient | None = None
        self._sn = 0
        self._pending: dict[int, asyncio.Future[TuyaBLEFrame]] = {}
        self._write_lock = asyncio.Lock()
        self._tasks: set[asyncio.Task[None]] = set()
        self._done = asyncio.Event()
        self._error: TuyaBLEScaleError | None = None
        self._last_rx = 0.0
        self._paired = False
        self.got_final = False
        self.device_version: str | None = None

    # ------------------------------------------------------------------ #
    # Public
    # ------------------------------------------------------------------ #

    async def async_run(
        self,
        ble_device: BLEDevice,
        ble_device_callback: Callable[[], BLEDevice] | None = None,
    ) -> bool:
        """Connect, run the protocol, disconnect. Returns True if a final weight arrived."""
        try:
            client = await establish_connection(
                BleakClientWithServiceCache,
                ble_device,
                ble_device.name or ble_device.address,
                disconnected_callback=self._on_disconnected,
                ble_device_callback=ble_device_callback,
                max_attempts=3,
            )
        except Exception as err:  # bleak-retry-connector raises a family of errors
            raise TuyaBLEScaleError(f"Could not connect: {err}") from err
        try:
            return await self.async_run_protocol(client)
        finally:
            try:
                await client.disconnect()
            except Exception:  # noqa: BLE001 - best effort on a vanishing device
                _LOGGER.debug("Error while disconnecting", exc_info=True)

    async def async_run_protocol(self, client: BleakClient) -> bool:
        """Handshake + stream on an already connected client."""
        loop = asyncio.get_running_loop()
        self._client = client
        self._last_rx = loop.time()
        try:
            await client.start_notify(CHARACTERISTIC_NOTIFY, self._on_notify)

            frame = await self._request(
                TuyaBLECode.FUN_SENDER_DEVICE_INFO, b"", SecurityFlag.LOGIN_KEY
            )
            info = parse_device_info(frame.data)
            self.device_version = info.device_version
            self._session_key = session_key_from_srand(self._creds.local_key6, info.srand)
            _LOGGER.debug(
                "Device info: version %s, protocol %s, bound %s",
                info.device_version,
                info.protocol_version,
                info.is_bound,
            )

            frame = await self._request(
                TuyaBLECode.FUN_SENDER_PAIR,
                build_pair_data(
                    self._creds.uuid, self._creds.local_key6, self._creds.device_id
                ),
                SecurityFlag.SESSION_KEY,
            )
            result = frame.data[0] if frame.data else -1
            if result not in PAIR_RESULT_OK:
                raise TuyaBLEScaleAuthError(
                    f"Pairing rejected (result {result}); check device_id/uuid"
                )

            self._paired = True

            try:
                await self._request(
                    TuyaBLECode.FUN_SENDER_DEVICE_STATUS, b"", SecurityFlag.SESSION_KEY
                )
            except TuyaBLEScaleTimeout:
                # Not fatal: the scale usually streams anyway once paired.
                _LOGGER.debug("No answer to status query")

            await self._wait_until_idle()
        finally:
            self._done.set()
            for fut in self._pending.values():
                if not fut.done():
                    fut.cancel()
            self._pending.clear()
            if self._tasks:
                await asyncio.gather(*self._tasks, return_exceptions=True)
            self._client = None
        if self._error:
            raise self._error
        return self.got_final

    # ------------------------------------------------------------------ #
    # Sending
    # ------------------------------------------------------------------ #

    def _next_sn(self) -> int:
        self._sn += 1
        return self._sn

    async def _send(
        self, code: int, data: bytes, flag: SecurityFlag, sn: int, ack_sn: int = 0
    ) -> None:
        key = self._login_key if flag == SecurityFlag.LOGIN_KEY else self._session_key
        assert key is not None
        client = self._client
        if client is None:
            raise TuyaBLEScaleError("Not connected")
        packets = build_packets(key, flag, sn, ack_sn, code, data)
        async with self._write_lock:
            for packet in packets:
                await client.write_gatt_char(CHARACTERISTIC_WRITE, packet, response=False)

    async def _request(self, code: int, data: bytes, flag: SecurityFlag) -> TuyaBLEFrame:
        sn = self._next_sn()
        fut: asyncio.Future[TuyaBLEFrame] = asyncio.get_running_loop().create_future()
        self._pending[sn] = fut
        try:
            await self._send(code, data, flag, sn)
            done_wait = asyncio.ensure_future(self._done.wait())
            try:
                await asyncio.wait(
                    {fut, done_wait},
                    timeout=self._response_timeout,
                    return_when=asyncio.FIRST_COMPLETED,
                )
            finally:
                done_wait.cancel()
            if not fut.done():
                if not self._done.is_set():
                    raise TuyaBLEScaleTimeout(
                        f"No answer to {TuyaBLECode(code).name}"
                    )
                raise self._error or TuyaBLEScaleError(
                    f"Disconnected while waiting for {TuyaBLECode(code).name}"
                )
            return fut.result()
        finally:
            self._pending.pop(sn, None)

    def _respond(self, code: int, data: bytes, ack_sn: int) -> None:
        """Answer a device-initiated frame in the background."""

        async def _do() -> None:
            try:
                await self._send(code, data, SecurityFlag.SESSION_KEY, self._next_sn(), ack_sn)
            except Exception:  # noqa: BLE001 - device may have gone already
                _LOGGER.debug("Failed to answer %#06x", code, exc_info=True)

        task = asyncio.get_running_loop().create_task(_do())
        self._tasks.add(task)
        task.add_done_callback(self._tasks.discard)

    # ------------------------------------------------------------------ #
    # Receiving
    # ------------------------------------------------------------------ #

    def _on_disconnected(self, _client: BleakClient) -> None:
        _LOGGER.debug("Scale disconnected")
        self._done.set()

    def _fail(self, error: TuyaBLEScaleError) -> None:
        if self._error is None:
            self._error = error
        self._done.set()

    def _on_notify(self, _char: BleakGATTCharacteristic | int | str, data: bytearray) -> None:
        self._last_rx = asyncio.get_running_loop().time()
        try:
            payload = self._reassembler.feed(bytes(data))
            if payload is None:
                return
            frame = decrypt_payload(payload, self._login_key, self._session_key)
        except TuyaBLECRCError as err:
            if self._paired:
                # Session already proven good: treat as a transient glitch.
                _LOGGER.debug("Dropping undecryptable frame: %s", err)
                return
            self._fail(
                TuyaBLEScaleAuthError(f"Cannot decrypt scale data ({err}); local_key changed?")
            )
            return
        except TuyaBLEProtocolError as err:
            _LOGGER.debug("Dropping bad packet %s: %s", data.hex(), err)
            return
        _LOGGER.debug(
            "<- sn=%d ack=%d code=%#06x data=%s",
            frame.sn,
            frame.ack_sn,
            frame.code,
            frame.data.hex(),
        )
        self._handle_frame(frame)

    def _handle_frame(self, frame: TuyaBLEFrame) -> None:
        fut = self._pending.get(frame.ack_sn) if frame.ack_sn else None
        if fut is not None and not fut.done():
            fut.set_result(frame)
            return

        code = frame.code
        if code in _DP_REPORT_CODES:
            try:
                report = parse_dp_report(code, frame.data)
            except (TuyaBLEProtocolError, ValueError, IndexError) as err:
                _LOGGER.debug("Unparsable DP report %#06x: %s", code, err)
                return
            self._respond(code, report.ack_data, frame.sn)
            self._handle_datapoints(report.datapoints, report.timestamp)
        elif code == TuyaBLECode.FUN_RECEIVE_TIME1_REQ:
            self._respond(code, build_time1_response(), frame.sn)
        elif code == TuyaBLECode.FUN_RECEIVE_TIME2_REQ:
            self._respond(code, build_time2_response(), frame.sn)
        else:
            _LOGGER.debug("Ignoring unsolicited code %#06x", code)

    def _handle_datapoints(self, dps: list[DataPoint], timestamp: float | None) -> None:
        values = {dp.id: dp.value for dp in dps}
        impedance = values.get(DP_IMPEDANCE)
        if isinstance(values.get(DP_WEIGHT), int):
            self.got_final = True
            self._on_reading(
                ScaleReading(values[DP_WEIGHT] / 10, True, timestamp, impedance, values)
            )
        elif isinstance(values.get(DP_LIVE_WEIGHT), int):
            self._on_reading(
                ScaleReading(values[DP_LIVE_WEIGHT] / 10, False, timestamp, None, values)
            )

    async def _wait_until_idle(self) -> None:
        loop = asyncio.get_running_loop()
        while not self._done.is_set():
            idle = self._linger_after_final if self.got_final else self._idle_timeout
            remaining = self._last_rx + idle - loop.time()
            if remaining <= 0:
                _LOGGER.debug("Stream idle, ending session")
                return
            try:
                async with asyncio.timeout(remaining):
                    await self._done.wait()
            except TimeoutError:
                continue
