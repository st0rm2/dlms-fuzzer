"""Passive DLMS/HDLC system-title discovery for the main scan workflow."""

from __future__ import annotations

import time
from contextlib import nullcontext
from typing import Any, Callable

from gurux_common import ReceiveParameters
from gurux_common.io import Parity, StopBits
from gurux_dlms import _GXFCS16
from gurux_serial import GXSerial

from .config import AppConfig
from .result_model import utc_now


ProgressCallback = Callable[[dict[str, Any]], None]

_HDLC_FLAG = 0x7E
_HDLC_FRAME_FORMAT = 0xA0
_AARE = 0x61
_GENERAL_GLO_CIPHERING = 0xDB
_RESPONDING_AP_TITLE = 0xA4
_OCTET_STRING = 0x04


def _definite_length(data: bytes, offset: int) -> tuple[int, int] | None:
    """Decode a BER/A-XDR definite length as ``(length, content_offset)``."""

    if offset >= len(data):
        return None
    first = data[offset]
    if first < 0x80:
        return first, offset + 1
    count = first & 0x7F
    if count == 0 or count > 4 or offset + 1 + count > len(data):
        return None
    start = offset + 1
    return int.from_bytes(data[start : start + count], "big"), start + count


def _hdlc_address(data: bytes, offset: int) -> tuple[int, int] | None:
    """Decode one variable-length HDLC address and return its next offset."""

    value = 0
    for index in range(offset, min(offset + 4, len(data))):
        octet = data[index]
        value = (value << 7) | (octet >> 1)
        if octet & 1:
            return value, index + 1
    return None


def _frame_addresses(frame: bytes) -> tuple[int | None, int | None]:
    if len(frame) < 7 or frame[0] != _HDLC_FLAG:
        return None, None
    target = _hdlc_address(frame, 3)
    if target is None:
        return None, None
    source = _hdlc_address(frame, target[1])
    if source is None:
        return None, None
    return target[0], source[0]


def extract_hdlc_frames(buffer: bytearray) -> list[bytes]:
    """Remove and return complete HDLC frames from a mutable receive buffer."""

    frames: list[bytes] = []
    while buffer:
        try:
            start = buffer.index(_HDLC_FLAG)
        except ValueError:
            buffer.clear()
            break
        if start:
            del buffer[:start]
        if len(buffer) < 4:
            break
        if buffer[1] & 0xF0 != _HDLC_FRAME_FORMAT:
            del buffer[0]
            continue
        frame_length = ((buffer[1] & 0x07) << 8) | buffer[2]
        total_length = frame_length + 2
        if total_length < 9:
            del buffer[0]
            continue
        if len(buffer) < total_length:
            break
        if buffer[total_length - 1] != _HDLC_FLAG:
            del buffer[0]
            continue
        frames.append(bytes(buffer[:total_length]))
        # Some serial streams use one flag as both the closing flag of this
        # frame and the opening flag of the next frame.
        shared_flag = (
            len(buffer) > total_length
            and buffer[total_length] & 0xF0 == _HDLC_FRAME_FORMAT
        )
        del buffer[: total_length - 1 if shared_flag else total_length]
    return frames


def _information_payload(frame: bytes) -> bytes | None:
    """Return an LLC-stripped information field from a complete HDLC frame."""

    if len(frame) < 9 or frame[0] != _HDLC_FLAG:
        return None
    frame_length = ((frame[1] & 0x07) << 8) | frame[2]
    closing_flag = frame_length + 1
    if closing_flag >= len(frame) or frame[closing_flag] != _HDLC_FLAG:
        return None
    information_end = closing_flag - 2
    for marker in (b"\xE6\xE7\x00", b"\xE6\xE6\x00"):
        offset = frame.find(marker, 3, information_end)
        if offset >= 0:
            return frame[offset + len(marker) : information_end]
    return None


def _valid_frame_fcs(frame: bytes) -> bool:
    if len(frame) < 9 or frame[0] != _HDLC_FLAG:
        return False
    frame_length = ((frame[1] & 0x07) << 8) | frame[2]
    closing_flag = frame_length + 1
    if closing_flag >= len(frame) or closing_flag < 3:
        return False
    expected = _GXFCS16.countFCS16(frame, 1, frame_length - 2)
    observed = int.from_bytes(frame[closing_flag - 2 : closing_flag], "big")
    return expected == observed


def _aare_system_title(payload: bytes) -> bytes | None:
    if not payload or payload[0] != _AARE:
        return None
    outer = _definite_length(payload, 1)
    if outer is None:
        return None
    outer_length, offset = outer
    end = min(len(payload), offset + outer_length)
    while offset < end:
        tag = payload[offset]
        decoded = _definite_length(payload, offset + 1)
        if decoded is None:
            return None
        length, content_offset = decoded
        content_end = content_offset + length
        if content_end > end:
            return None
        if tag == _RESPONDING_AP_TITLE:
            content = payload[content_offset:content_end]
            nested = (
                _definite_length(content, 1)
                if content[:1] == bytes((_OCTET_STRING,))
                else None
            )
            if nested is not None:
                title_length, title_offset = nested
                title = content[title_offset : title_offset + title_length]
                if title_length == 8 and len(title) == 8:
                    return title
            return None
        offset = content_end
    return None


def system_title_observations(
    frame: bytes, *, server_address: int | None = None
) -> list[dict[str, Any]]:
    """Extract clear-text system-title evidence from one HDLC frame."""

    if not _valid_frame_fcs(frame):
        return []
    payload = _information_payload(frame)
    if not payload:
        return []
    target_address, source_address = _frame_addresses(frame)
    base = {
        "target_address": target_address,
        "source_address": source_address,
    }

    title = _aare_system_title(payload)
    if title is not None:
        return [
            {
                **base,
                "kind": "server",
                "hex": title.hex().upper(),
                "source": "passive_aare",
                "confidence": "observed_cleartext",
            }
        ]

    if payload[0] != _GENERAL_GLO_CIPHERING:
        return []
    decoded = _definite_length(payload, 1)
    if decoded is None:
        return []
    title_length, title_offset = decoded
    title = payload[title_offset : title_offset + title_length]
    if title_length != 8 or len(title) != 8:
        return []
    kind = "sender"
    if server_address is not None:
        if source_address == server_address:
            kind = "server"
        elif target_address == server_address:
            kind = "client"
    return [
        {
            **base,
            "kind": kind,
            "hex": title.hex().upper(),
            "source": "passive_general_glo_ciphering",
            "confidence": "observed_cleartext_sender",
        }
    ]


def _configure_media(config: AppConfig, baudrate: int, media: Any) -> None:
    media.port = config.transport.device
    media.baudRate = baudrate
    media.dataBits = config.transport.serial.data_bits
    media.parity = {
        "none": Parity.NONE,
        "even": Parity.EVEN,
        "odd": Parity.ODD,
        "mark": Parity.MARK,
        "space": Parity.SPACE,
    }[config.transport.serial.parity]
    media.stopBits = {
        1.0: StopBits.ONE,
        1.5: StopBits.ONE_POINT_FIVE,
        2.0: StopBits.TWO,
    }[config.transport.serial.stop_bits]


def listen_for_system_titles(
    config: AppConfig,
    *,
    baudrate: int,
    duration_seconds: int,
    traffic: Any,
    server_address: int | None = None,
    progress: ProgressCallback | None = None,
    media_factory: Callable[[], Any] | None = None,
) -> dict[str, Any]:
    """Listen without transmitting and return observed clear-text titles."""

    if not 1 <= duration_seconds <= 3600:
        raise ValueError(
            "passive system-title listen duration must be 1 through 3600 seconds"
        )
    progress = progress or (lambda _: None)
    media = (media_factory or (lambda: GXSerial(None)))()
    _configure_media(config, baudrate, media)
    started_at = utc_now()
    started = time.monotonic()
    receive_buffer = bytearray()
    observations: list[dict[str, Any]] = []
    frames_seen = 0
    bytes_received = 0
    errors: list[dict[str, Any]] = []
    opened = False
    progress(
        {
            "phase": "passive_system_title_listen",
            "message": f"Listening passively for system titles for {duration_seconds} seconds",
        }
    )
    try:
        media.open()
        opened = True
        synchronous = (
            media.getSynchronous()
            if hasattr(media, "getSynchronous")
            else nullcontext()
        )
        with synchronous:
            while True:
                remaining_ms = int((started + duration_seconds - time.monotonic()) * 1000)
                if remaining_ms <= 0:
                    break
                receive = ReceiveParameters()
                receive.count = 1
                receive.allData = True
                receive.waitTime = min(250, max(1, remaining_ms))
                if not media.receive(receive):
                    continue
                chunk = bytes(receive.reply or b"")
                if not chunk:
                    continue
                bytes_received += len(chunk)
                receive_buffer.extend(chunk)
                chunk_frames = extract_hdlc_frames(receive_buffer)
                for frame in chunk_frames:
                    frames_seen += 1
                    found = system_title_observations(
                        frame, server_address=server_address
                    )
                    for item in found:
                        observations.append(
                            {
                                **item,
                                "observed_at": utc_now(),
                                "frame_number": frames_seen,
                            }
                        )
                    if found:
                        # Retain raw evidence only for the two recognized APDU
                        # forms. Unrelated traffic could include an LLS AARQ
                        # carrying a reusable password and must not be logged.
                        traffic.log(
                            profile="passive_system_title_discovery",
                            phase="passive_system_title_listen",
                            purpose="observe_aare_or_general_glo_ciphering",
                            object_context={"passive": True},
                            operation="PASSIVE_RECEIVE",
                            attempt=frames_seen,
                            tx_frames=[],
                            tx_decoded={"transmitted": False},
                            rx_frames=[frame],
                            rx_decoded={"system_titles": found},
                            elapsed_ms=(time.monotonic() - started) * 1000,
                            result="SUCCESS",
                        )
    except Exception as exc:
        errors.append(
            {
                "phase": "passive_system_title_listen",
                "type": type(exc).__name__,
                "message": str(exc),
            }
        )
    finally:
        if opened:
            try:
                media.close()
            except Exception as exc:
                errors.append(
                    {
                        "phase": "passive_system_title_cleanup",
                        "type": type(exc).__name__,
                        "message": str(exc),
                    }
                )

    unique_titles: list[dict[str, Any]] = []
    seen: set[tuple[str, str, str]] = set()
    for item in observations:
        identity = (item["kind"], item["hex"], item["source"])
        if identity in seen:
            continue
        seen.add(identity)
        unique_titles.append(item)
    return {
        "schema_version": 1,
        "mode": "passive_serial_hdlc",
        "status": "failed" if errors else "completed",
        "started_at": started_at,
        "finished_at": utc_now(),
        "configured_duration_seconds": duration_seconds,
        "observed_duration_ms": round((time.monotonic() - started) * 1000, 3),
        "device": config.transport.device,
        "baudrate": baudrate,
        "serial": {
            "parity": config.transport.serial.parity,
            "data_bits": config.transport.serial.data_bits,
            "stop_bits": config.transport.serial.stop_bits,
        },
        "safety": {
            "transmitted": False,
            "recognized_apdus": ["AARE", "GeneralGloCiphering"],
            "decryption_attempted": False,
        },
        "bytes_received": bytes_received,
        "frames_seen": frames_seen,
        "incomplete_bytes": len(receive_buffer),
        "titles": unique_titles,
        "observations": observations,
        "errors": errors,
    }
