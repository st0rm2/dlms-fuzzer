"""Append-only, redacted, side-by-side DLMS traffic logging."""

from __future__ import annotations

import json
import re
import threading
from pathlib import Path
from typing import Any, TextIO

from .result_model import normalize_value, utc_now

_SENSITIVE_KEY = re.compile(
    r"(?:password|secret|private|key|challenge|dedicated|gak|guek|global.?authentication|global.?unicast)",
    re.IGNORECASE,
)
_SENSITIVE_XML = re.compile(
    r"(<(?:CallingAuthentication(?:Value)?|RespondingAuthentication(?:Value)?|StoCChallenge|CtoSChallenge)\b[^>]*)(?:Value=\"[^\"]*\")([^>]*/?>)",
    re.IGNORECASE,
)


def redact(value: Any, *, key: str = "") -> tuple[Any, list[str]]:
    indicators: list[str] = []
    if _SENSITIVE_KEY.search(key):
        return "<redacted>", [key or "sensitive-value"]
    if isinstance(value, dict):
        result: dict[str, Any] = {}
        for child_key, child_value in value.items():
            result[child_key], found = redact(child_value, key=str(child_key))
            indicators.extend(found)
        return result, indicators
    if isinstance(value, (list, tuple)):
        result_list = []
        for item in value:
            clean, found = redact(item, key=key)
            result_list.append(clean)
            indicators.extend(found)
        return result_list, indicators
    if isinstance(value, str) and "<" in value:
        clean, count = _SENSITIVE_XML.subn(r'\1Value="<redacted>"\2', value)
        if count:
            indicators.append("decoded-xml-authentication-value")
        return clean, indicators
    return normalize_value(value), indicators


class TrafficLogger:
    def __init__(self, path: str | Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._stream: TextIO = self.path.open("a", encoding="utf-8")
        self._sequence = 0
        self._lock = threading.Lock()

    def log(
        self,
        *,
        profile: str,
        phase: str,
        purpose: str,
        object_context: dict[str, Any] | None,
        operation: str,
        attempt: int,
        tx_frames: list[bytes],
        tx_decoded: Any,
        rx_frames: list[bytes],
        rx_decoded: Any,
        elapsed_ms: float,
        result: str,
    ) -> None:
        context_clean, context_redactions = redact(object_context or {})
        tx_clean, tx_redactions = redact(tx_decoded)
        rx_clean, rx_redactions = redact(rx_decoded)
        with self._lock:
            self._sequence += 1
            record = {
                "timestamp": utc_now(),
                "sequence_number": self._sequence,
                "profile": profile,
                "scan_phase": phase,
                "purpose": purpose,
                "object_context": context_clean,
                "operation": operation,
                "attempt_number": attempt,
                "tx": {
                    "encoded_frames": [frame.hex().upper() for frame in tx_frames],
                    "decoded": tx_clean,
                },
                "rx": {
                    "encoded_frames": [frame.hex().upper() for frame in rx_frames],
                    "decoded": rx_clean,
                },
                "timing": {"elapsed_ms": round(elapsed_ms, 3)},
                "result": result,
                "failure_category": None if result == "SUCCESS" else result,
                "redaction_indicators": sorted(
                    set(context_redactions + tx_redactions + rx_redactions)
                ),
            }
            self._stream.write(json.dumps(record, ensure_ascii=False, separators=(",", ":")) + "\n")
            self._stream.flush()

    def close(self) -> None:
        if not self._stream.closed:
            self._stream.flush()
            self._stream.close()

    def __enter__(self) -> "TrafficLogger":
        return self

    def __exit__(self, *_: object) -> None:
        self.close()
