"""Normalized operation results and JSON-safe DLMS value rendering."""

from __future__ import annotations

import base64
import dataclasses
import datetime as dt
import enum
import math
from typing import Any


class Outcome(str, enum.Enum):
    SUCCESS = "SUCCESS"
    NOT_TESTED = "NOT_TESTED"
    INCONCLUSIVE = "INCONCLUSIVE"
    DLMS_ERROR = "DLMS_ERROR"
    TIMEOUT = "TIMEOUT"
    PROTOCOL_ERROR = "PROTOCOL_ERROR"
    TRANSPORT_ERROR = "TRANSPORT_ERROR"
    INVALID_ARGUMENT = "INVALID_ARGUMENT"
    ARGUMENT_GENERATION_FAILED = "ARGUMENT_GENERATION_FAILED"
    RESTORE_FAILED = "RESTORE_FAILED"


def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def enum_name(value: Any) -> str | None:
    name = getattr(value, "name", None)
    return str(name).lower() if name else None


def normalize_value(value: Any) -> Any:
    """Convert Gurux/DLMS values to deterministic, loss-aware JSON values."""

    if value is None or isinstance(value, (bool, str)):
        return value
    if isinstance(value, enum.Enum):
        return {"name": value.name, "value": int(value.value)}
    if isinstance(value, int):
        return int(value)
    if isinstance(value, float):
        if math.isfinite(value):
            return float(value)
        return {"special_float": str(value)}
    if isinstance(value, (bytes, bytearray, memoryview)):
        raw = bytes(value)
        decoded: str | None = None
        for encoding in ("utf-8", "ascii"):
            try:
                candidate = raw.decode(encoding)
            except UnicodeDecodeError:
                continue
            if candidate.isprintable():
                decoded = candidate
                break
        return {
            "encoding": "octet-string",
            "hex": raw.hex().upper(),
            "base64": base64.b64encode(raw).decode("ascii"),
            "text": decoded,
            "length": len(raw),
        }
    if isinstance(value, (dt.datetime, dt.date, dt.time)):
        return value.isoformat()
    if dataclasses.is_dataclass(value):
        return normalize_value(dataclasses.asdict(value))
    if isinstance(value, dict):
        return {str(key): normalize_value(item) for key, item in value.items()}
    if isinstance(value, (list, tuple, set)):
        return [normalize_value(item) for item in value]

    # Gurux date/time classes and typed integer wrappers have useful string
    # forms but are not Python datetime/enum instances.
    rendered = str(value)
    return {
        "python_type": f"{type(value).__module__}.{type(value).__name__}",
        "display": rendered,
    }


def classify_exception(exc: BaseException) -> Outcome:
    name = type(exc).__name__.lower()
    module = type(exc).__module__.lower()
    if "timeout" in name:
        return Outcome.TIMEOUT
    if "gxdlmsexception" in name or "errorcode" in module:
        return Outcome.DLMS_ERROR
    if isinstance(exc, (OSError, IOError)) or "serial" in module:
        return Outcome.TRANSPORT_ERROR
    if isinstance(exc, (ValueError, TypeError)):
        return Outcome.PROTOCOL_ERROR
    return Outcome.PROTOCOL_ERROR


def error_record(exc: BaseException, *, phase: str, context: dict[str, Any] | None = None) -> dict[str, Any]:
    return {
        "timestamp": utc_now(),
        "phase": phase,
        "category": classify_exception(exc).value,
        "type": type(exc).__name__,
        "message": str(exc),
        "context": context or {},
    }
