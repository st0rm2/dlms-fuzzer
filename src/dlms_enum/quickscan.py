"""Zero-config scan bootstrap: inline discovery and secrets-file loading."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any, Callable

from .autodiscover import (
    DiscoveryOptions,
    discover_public_device,
    suggested_public_config,
)
from .config import AppConfig, parse_config
from .traffic_logger import TrafficLogger

# The discovery-backed scan flow creates its run directory before the
# suggested configuration exists, so both sides share this output parent.
DEFAULT_OUTPUT_DIRECTORY = "./runs"

_SECRET_KEY = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")


class QuickscanError(RuntimeError):
    """Zero-config discovery or secrets-file loading failed."""


def discover_config(
    device: str,
    traffic: TrafficLogger,
    *,
    progress: Callable[[dict[str, Any]], None] | None = None,
    session_factory: Callable[..., Any] | None = None,
    discover: Callable[..., dict[str, Any]] | None = None,
) -> AppConfig:
    """Discover the public endpoint on device and return a pinned AppConfig."""

    discover = discover or discover_public_device
    result = discover(
        DiscoveryOptions(device=device),
        traffic,
        progress=progress,
        session_factory=session_factory,
    )
    if not result.get("connection"):
        raise QuickscanError(
            f"no DLMS endpoint found on {device}; check the cabling and serial "
            "format, or widen the sweep with dlms-autodiscover --deep"
        )
    suggested = suggested_public_config(result)
    if suggested is None:
        raise QuickscanError(f"no DLMS endpoint found on {device}")
    suggested.setdefault("output", {})["directory"] = DEFAULT_OUTPUT_DIRECTORY
    return parse_config(suggested)


def load_secrets_file(path: str | Path) -> dict[str, str]:
    """Parse a KEY=VALUE secrets file; values are used verbatim, never expanded."""

    secrets_path = Path(path)
    try:
        lines = secrets_path.read_text(encoding="utf-8").splitlines()
    except OSError as exc:
        raise QuickscanError(f"cannot read secrets file {secrets_path}: {exc}") from exc
    secrets: dict[str, str] = {}
    for lineno, raw in enumerate(lines, start=1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        key, separator, value = line.partition("=")
        key = key.strip()
        if not separator or not _SECRET_KEY.fullmatch(key):
            raise QuickscanError(
                f"{secrets_path}:{lineno}: expected KEY=VALUE; "
                "comments start with # and shell expansion is not supported"
            )
        secrets[key] = value.strip()
    return secrets
