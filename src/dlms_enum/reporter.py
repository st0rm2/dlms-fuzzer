"""Canonical report writing and human-readable rendering."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any


def sha256_file(path: str | Path) -> str:
    digest = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def write_report(report: dict[str, Any], path: str | Path, traffic_path: str | Path) -> None:
    report["related_logs"] = {
        "traffic_file": str(Path(traffic_path).name),
        "traffic_sha256": sha256_file(traffic_path),
    }
    destination = Path(path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary = destination.with_suffix(destination.suffix + ".tmp")
    temporary.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    temporary.replace(destination)


def load_report(path: str | Path) -> dict[str, Any]:
    candidate = Path(path)
    if candidate.is_dir():
        candidate = candidate / "report.json"
    data = json.loads(candidate.read_text(encoding="utf-8"))
    if not isinstance(data, dict) or data.get("schema_version") != 1:
        raise ValueError(f"{candidate} is not a supported dlms-enum report")
    return data


def summary_lines(report: dict[str, Any]) -> list[str]:
    run = report.get("run", {})
    profiles = report.get("profiles", [])
    profile = profiles[0] if profiles else {}
    summary = profile.get("summary", {})
    lines = [
        f"Run: {run.get('id', 'unknown')} ({run.get('status', 'unknown')})",
        f"Profile: {profile.get('name', 'not established')}",
        f"Baud rate: {report.get('transport', {}).get('selected_baudrate', 'not found')}",
        f"HDLC server address: {report.get('transport', {}).get('selected_server_address', 'not found')}",
        f"Server Addressing Type: {report.get('transport', {}).get('server_addressing_type', 'not found')}",
        f"Objects: {summary.get('objects', 0)}",
        f"GET: {summary.get('get_success', 0)} success, {summary.get('get_failed', 0)} failed",
        f"Errors: {len(report.get('errors', []))}",
    ]
    association = profile.get("association", {})
    if profile.get("name") == "hls_gmac_suite0":
        lines.insert(2, f"HLS-GMAC validated: {association.get('hls_validated', False)}")
        lines.insert(3, f"Security: Suite 0 / {association.get('security', 'not established')}")
    return lines
