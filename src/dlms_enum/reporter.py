"""Canonical report writing and human-readable rendering."""

from __future__ import annotations

import hashlib
import json
import math
from pathlib import Path
from typing import Any


def sha256_file(path: str | Path) -> str:
    digest = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _markdown(value: Any) -> str:
    return str(value).replace("|", "\\|").replace("\r", " ").replace("\n", "<br>")


def _compact_value(value: Any, *, limit: int = 180) -> str:
    if value is None:
        return "—"
    if isinstance(value, dict):
        if value.get("text") is not None:
            rendered = str(value["text"])
        elif "display" in value:
            rendered = str(value["display"])
        elif "association_object_count" in value:
            rendered = f"{value['association_object_count']} objects"
        else:
            rendered = json.dumps(value, ensure_ascii=False, separators=(",", ":"))
    elif isinstance(value, (list, tuple)):
        rendered = json.dumps(value, ensure_ascii=False, separators=(",", ":"))
    else:
        rendered = str(value)
    if len(rendered) > limit:
        return rendered[: limit - 1] + "…"
    return rendered


def _hex_value(raw_value: Any) -> str:
    if isinstance(raw_value, dict) and isinstance(raw_value.get("hex"), str):
        return raw_value["hex"]
    if isinstance(raw_value, bool):
        return "01" if raw_value else "00"
    if isinstance(raw_value, int):
        if raw_value < 0:
            return f"-{abs(raw_value):X}"
        return f"{raw_value:X}"
    if isinstance(raw_value, float) and math.isfinite(raw_value):
        return raw_value.hex()
    return "—"


def render_summary_report(report: dict[str, Any]) -> str:
    """Create a compact Markdown view while retaining report.json as evidence."""

    run = report.get("run", {})
    transport = report.get("transport", {})
    profiles = report.get("profiles", [])
    lines = [
        "# DLMS scan report",
        "",
        "## Overview",
        "",
        "| Field | Value |",
        "|---|---|",
        f"| Run | {_markdown(run.get('id', 'unknown'))} |",
        f"| Status | {_markdown(run.get('status', 'unknown'))} |",
        f"| Started | {_markdown(run.get('started_at', '—'))} |",
        f"| Finished | {_markdown(run.get('finished_at', '—'))} |",
        f"| Baud rate | {_markdown(transport.get('selected_baudrate', 'not found'))} |",
        f"| HDLC server | {_markdown(transport.get('selected_server_address', 'not found'))} |",
        f"| Server addressing | {_markdown(transport.get('server_addressing_type', 'not found'))} |",
        "",
    ]

    for profile in profiles:
        association = profile.get("association", {})
        summary = profile.get("summary", {})
        profile_name = str(profile.get("name", "unknown"))
        lines.extend(
            [
                f"## Profile: {_markdown(profile_name)}",
                "",
                "| Field | Value |",
                "|---|---|",
                f"| Client address | {_markdown(association.get('client_address', '—'))} |",
                f"| Authentication | {_markdown(association.get('authentication', 'none'))} |",
                f"| Security | {_markdown(association.get('security', 'none'))} |",
                f"| Security suite | {_markdown(association.get('security_suite', '—'))} |",
                f"| HLS validated | {_markdown(association.get('hls_validated', '—'))} |",
                f"| Client system title | {_markdown(association.get('client_system_title', '—'))} |",
                f"| Server system title | {_markdown(association.get('server_system_title', '—'))} |",
                f"| Objects | {_markdown(summary.get('objects', 0))} |",
                f"| GET results | {_markdown(summary.get('get_success', 0))} successful / {_markdown(summary.get('get_failed', 0))} failed |",
            ]
        )
        bootstrap = association.get("invocation_counter_bootstrap")
        if isinstance(bootstrap, dict):
            lines.extend(
                [
                    f"| Meter counter | {_markdown(bootstrap.get('meter_reported_counter', '—'))} |",
                    f"| First secure counter | {_markdown(bootstrap.get('first_secure_counter', '—'))} |",
                    f"| Next persisted counter | {_markdown(association.get('next_client_invocation_counter', '—'))} |",
                ]
            )
        lines.append("")

        identification = profile.get("identification", {})
        if identification:
            lines.extend(["### Identification", "", "| Item | Value |", "|---|---|"])
            for key, value in identification.items():
                lines.append(f"| {_markdown(key)} | {_markdown(_compact_value(value))} |")
            lines.append("")

        lines.extend(
            [
                "### Decoded OBIS values",
                "",
                "One compact row is shown for every scanned OBIS attribute except the redundant logical-name attribute when other attributes exist. Raw hexadecimal is shown when available; integers use numeric hexadecimal. Complex values are shortened here, while the complete value remains in `report.json`.",
                "",
                "| OBIS | Class | Attribute | Name | Decoded value | Hex / numeric hex | Result |",
                "|---|---:|---:|---|---|---|---|",
            ]
        )
        for obj in profile.get("objects", []):
            attributes = list(obj.get("attributes", []))
            display_attributes = [item for item in attributes if item.get("attribute_id") != 1]
            if not display_attributes:
                display_attributes = attributes or [{}]
            for attribute in display_attributes:
                decoded = attribute.get("decoded", {})
                value = decoded.get("value") if isinstance(decoded, dict) else None
                raw = decoded.get("raw_value") if isinstance(decoded, dict) else None
                result = attribute.get("outcome") or attribute.get("lifecycle") or "not scanned"
                lines.append(
                    "| {} | {} | {} | {} | {} | {} | {} |".format(
                        _markdown(obj.get("logical_name", "—")),
                        _markdown(obj.get("class_id", "—")),
                        _markdown(attribute.get("attribute_id", "—")),
                        _markdown(attribute.get("name") or "—"),
                        _markdown(_compact_value(value)),
                        _markdown(_hex_value(raw)),
                        _markdown(result),
                    )
                )
        lines.append("")

    errors = report.get("errors", [])
    lines.extend(["## Errors and warnings", ""])
    if not errors:
        lines.append("None.")
    else:
        lines.extend(["| Phase | Category | Message |", "|---|---|---|"])
        for error in errors[:50]:
            lines.append(
                f"| {_markdown(error.get('phase', '—'))} | "
                f"{_markdown(error.get('category', '—'))} | "
                f"{_markdown(_compact_value(error.get('message'), limit=240))} |"
            )
        if len(errors) > 50:
            lines.append(
                f"| — | — | {len(errors) - 50} additional entries; see `report.json` |"
            )
    lines.extend(
        [
            "",
            "---",
            "",
            "Full structured data: `report.json`  ",
            "Raw protocol traffic: `traffic.jsonl`",
            "",
        ]
    )
    return "\n".join(lines)


def write_summary_report(report: dict[str, Any], path: str | Path) -> None:
    destination = Path(path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary = destination.with_suffix(destination.suffix + ".tmp")
    temporary.write_text(render_summary_report(report), encoding="utf-8")
    temporary.replace(destination)


def write_report(
    report: dict[str, Any],
    path: str | Path,
    traffic_path: str | Path,
    summary_path: str | Path | None = None,
) -> None:
    if summary_path is not None:
        write_summary_report(report, summary_path)
    report["related_logs"] = {
        "traffic_file": str(Path(traffic_path).name),
        "traffic_sha256": sha256_file(traffic_path),
    }
    if summary_path is not None:
        report["related_logs"].update(
            {
                "summary_file": str(Path(summary_path).name),
                "summary_sha256": sha256_file(summary_path),
            }
        )
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
