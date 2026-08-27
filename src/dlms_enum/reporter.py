"""Canonical report writing and human-readable rendering."""

from __future__ import annotations

import hashlib
import json
import math
import re
from pathlib import Path
from typing import Any

from .result_model import Outcome


def sha256_file(path: str | Path) -> str:
    digest = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _atomic_write_text(path: str | Path, content: str) -> None:
    destination = Path(path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary = destination.with_suffix(destination.suffix + ".tmp")
    temporary.write_text(content, encoding="utf-8")
    temporary.replace(destination)


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


def _data_type_summary(decoded: Any) -> str:
    """Return the detected wire/interface/UI types in a compact fixed order."""

    if not isinstance(decoded, dict):
        return "unknown / unknown / unknown"

    values: list[str] = []
    for key in ("dlms_data_type", "interface_data_type", "ui_data_type"):
        value = decoded.get(key)
        if value is None or str(value).strip().lower() in {"", "none", "unknown"}:
            values.append("unknown")
        else:
            values.append(str(value))
    return " / ".join(values)


def _profile_buffer_value(
    obj: dict[str, Any], attribute: dict[str, Any]
) -> list[Any] | None:
    if int(obj.get("class_id", -1)) != 7 or int(
        attribute.get("attribute_id", -1)
    ) != 2:
        return None
    if attribute.get("outcome") != Outcome.SUCCESS.value:
        return None
    decoded = attribute.get("decoded", {})
    value = decoded.get("value") if isinstance(decoded, dict) else None
    return value if isinstance(value, list) else None


def _decode_cosem_datetime(value: Any) -> str | None:
    """Render a normalized 12-byte COSEM date-time without altering JSON evidence."""

    if not isinstance(value, dict) or value.get("encoding") != "octet-string":
        return None
    encoded = value.get("hex")
    if not isinstance(encoded, str):
        return None
    try:
        raw = bytes.fromhex(encoded)
    except ValueError:
        return None
    if len(raw) != 12:
        return None
    year = int.from_bytes(raw[0:2], "big")
    month, day, hour, minute, second, hundredths = (
        raw[2], raw[3], raw[5], raw[6], raw[7], raw[8]
    )
    if year == 0xFFFF or 0xFF in {month, day, hour, minute, second}:
        return None
    rendered = f"{year:04d}-{month:02d}-{day:02d}T{hour:02d}:{minute:02d}:{second:02d}"
    if hundredths != 0xFF and hundredths:
        rendered += f".{hundredths:02d}"
    deviation_raw = int.from_bytes(raw[9:11], "big")
    if deviation_raw != 0x8000:
        deviation = int.from_bytes(raw[9:11], "big", signed=True)
        utc_offset = -deviation
        sign = "+" if utc_offset >= 0 else "-"
        hours, minutes = divmod(abs(utc_offset), 60)
        rendered += f"{sign}{hours:02d}:{minutes:02d}"
    return rendered


def _profile_display_value(value: Any) -> Any:
    return _decode_cosem_datetime(value) or value


def _profile_column_label(column: dict[str, Any]) -> str:
    name = column.get("attribute_name") or column.get("object_description")
    source = column.get("logical_name")
    attribute_id = column.get("attribute_id")
    if name and source:
        return f"{name} ({source} attr {attribute_id})"
    if source:
        return f"{source} attr {attribute_id}"
    return f"Column {column.get('position', '—')}"


def _profile_row_columns(obj: dict[str, Any], rows: list[Any]) -> list[str]:
    width = max(
        (
            len(row) if isinstance(row, (list, tuple)) else 1
            for row in rows
        ),
        default=0,
    )
    if width == 0:
        return []
    schema = obj.get("profile_generic", {}).get("columns", [])
    if len(schema) == width:
        return [_profile_column_label(column) for column in schema]
    if width == 1:
        return ["Value"]
    first_values = [
        row[0]
        for row in rows[:10]
        if isinstance(row, (list, tuple)) and row
    ]
    timestamped = bool(first_values) and sum(
        bool(
            re.search(
                r"(?:\d{4}[-/.]\d{1,2}[-/.]\d{1,2}|\d{1,2}:\d{2}:\d{2})",
                _compact_value(_profile_display_value(value)),
            )
        )
        for value in first_values
    ) >= max(1, len(first_values) // 2)
    if timestamped:
        second_values = [
            row[1]
            for row in rows[:10]
            if isinstance(row, (list, tuple)) and len(row) > 1
        ]
        if width == 2 and second_values and all(
            isinstance(value, int) and not isinstance(value, bool)
            for value in second_values
        ):
            return ["Timestamp", "Event code", "Description"]
        return ["Timestamp", "Event / description"] + [
            f"Value {index}" for index in range(3, width + 1)
        ]
    return [f"Value {index}" for index in range(1, width + 1)]


def _render_profile_buffers(profile: dict[str, Any]) -> list[str]:
    sections: list[str] = []
    for obj in profile.get("objects", []):
        for attribute in obj.get("attributes", []):
            rows = _profile_buffer_value(obj, attribute)
            if rows is None:
                continue
            columns = _profile_row_columns(obj, rows)
            profile_metadata = obj.get("profile_generic", {})
            sections.extend(
                [
                    "#### {} (`{}`)".format(
                        _markdown(obj.get("description") or "Profile Generic"),
                        _markdown(obj.get("logical_name", "—")),
                    ),
                    "",
                    f"{len(rows)} row(s), decoded after complete DLMS block reassembly.",
                    "",
                ]
            )
            if profile_metadata:
                sections.extend(
                    [
                        "| Profile metadata | Value |",
                        "|---|---|",
                        f"| Row encoding | {_markdown(profile_metadata.get('row_encoding', '—'))} |",
                        f"| Capture period | {_markdown(profile_metadata.get('capture_period_seconds', '—'))} seconds |",
                        f"| Sort method | {_markdown(_compact_value(profile_metadata.get('sort_method')))} |",
                        f"| Entries in use | {_markdown(profile_metadata.get('entries_in_use', '—'))} |",
                        f"| Capacity | {_markdown(profile_metadata.get('profile_entries', '—'))} |",
                        "",
                    ]
                )
                schema = profile_metadata.get("columns", [])
                if schema:
                    sections.extend(
                        [
                            "| Column | Source OBIS | Class | Attribute | Data index | Name | Type (wire / interface / UI) | Engineering |",
                            "|---:|---|---:|---:|---:|---|---|---|",
                        ]
                    )
                    for column in schema:
                        type_value = " / ".join(
                            str(column.get(key) or "unknown")
                            for key in (
                                "dlms_data_type",
                                "interface_data_type",
                                "ui_data_type",
                            )
                        )
                        engineering = ", ".join(
                            f"{key}={_compact_value(value)}"
                            for key, value in column.get("engineering_metadata", {}).items()
                        ) or "—"
                        sections.append(
                            "| {} | {} | {} | {} | {} | {} | {} | {} |".format(
                                _markdown(column.get("position", "—")),
                                _markdown(column.get("logical_name", "—")),
                                _markdown(column.get("class_id", "—")),
                                _markdown(column.get("attribute_id", "—")),
                                _markdown(column.get("data_index", "—")),
                                _markdown(column.get("attribute_name") or column.get("object_description") or "—"),
                                _markdown(type_value),
                                _markdown(engineering),
                            )
                        )
                    sections.append("")
            if not columns:
                sections.extend(["The buffer is empty.", ""])
                continue
            sections.extend(
                [
                    "| " + " | ".join(columns) + " |",
                    "|" + "---|" * len(columns),
                ]
            )
            for row in rows:
                values = list(row) if isinstance(row, (list, tuple)) else [row]
                values = [_profile_display_value(value) for value in values]
                if columns == ["Timestamp", "Event code", "Description"]:
                    event_code = values[1] if len(values) > 1 else None
                    values = [
                        values[0] if values else None,
                        event_code,
                        (
                            f"Meter-specific event code {event_code}"
                            if event_code is not None
                            else "—"
                        ),
                    ]
                values.extend([None] * (len(columns) - len(values)))
                sections.append(
                    "| "
                    + " | ".join(
                        _markdown(_compact_value(value, limit=240))
                        for value in values[: len(columns)]
                    )
                    + " |"
                )
            sections.append("")
    return sections


def _protected_traffic_entries(path: str | Path) -> list[dict[str, Any]]:
    entries: list[dict[str, Any]] = []
    with Path(path).open("r", encoding="utf-8") as stream:
        for line in stream:
            if not line.strip():
                continue
            record = json.loads(line)
            for direction in ("tx", "rx"):
                decoded = record.get(direction, {}).get("decoded", {})
                if not isinstance(decoded, dict) or not decoded.get("protected"):
                    continue
                if "ciphertext_hex" not in decoded:
                    continue
                control_value = decoded.get("security_control", "—")
                try:
                    control = int(str(control_value), 16)
                except (TypeError, ValueError):
                    control = 0
                entries.append(
                    {
                        "sequence_number": record.get("sequence_number", "—"),
                        "direction": direction.upper(),
                        "operation": record.get("operation", "—"),
                        "result": record.get("result", "—"),
                        "object_context": record.get("object_context", {}),
                        "protected_command": decoded.get("protected_command", "—"),
                        "security_control": decoded.get("security_control", "—"),
                        "security_suite": decoded.get(
                            "security_suite", control & 0x0F if control else "—"
                        ),
                        "authenticated": decoded.get(
                            "authenticated", bool(control & 0x10)
                        ),
                        "encrypted": decoded.get("encrypted", bool(control & 0x20)),
                        "compressed": decoded.get("compressed", False),
                        "broadcast_key": decoded.get("broadcast_key", False),
                        "key_scope": decoded.get("key_scope", "—"),
                        "originator_system_title": decoded.get(
                            "originator_system_title", "—"
                        ),
                        "recipient_system_title": decoded.get(
                            "recipient_system_title", "—"
                        ),
                        "transaction_id": decoded.get("transaction_id"),
                        "ciphering_datetime_hex": decoded.get(
                            "ciphering_datetime_hex", ""
                        ),
                        "other_information_hex": decoded.get(
                            "other_information_hex", ""
                        ),
                        "key_parameters": decoded.get("key_parameters"),
                        "key_ciphered_data_hex": decoded.get(
                            "key_ciphered_data_hex", ""
                        ),
                        "invocation_counter": decoded.get("invocation_counter", "—"),
                        "ciphertext_hex": decoded.get("ciphertext_hex", ""),
                        "ciphertext_captured_length": decoded.get(
                            "ciphertext_captured_length", 0
                        ),
                        "ciphertext_declared_length": decoded.get(
                            "ciphertext_declared_length", 0
                        ),
                        "ciphertext_complete": decoded.get("ciphertext_complete", False),
                        "authentication_tag_hex": decoded.get(
                            "authentication_tag_hex", ""
                        ),
                        "authentication_tag_complete": decoded.get(
                            "authentication_tag_complete", False
                        ),
                    }
                )
    return entries


def _protocol_traffic_entries(path: str | Path) -> list[dict[str, Any]]:
    entries: list[dict[str, Any]] = []
    with Path(path).open("r", encoding="utf-8") as stream:
        for line in stream:
            if not line.strip():
                continue
            record = json.loads(line)
            for direction in ("tx", "rx"):
                decoded = record.get(direction, {}).get("decoded", {})
                frames = decoded.get("protocol_frames", []) if isinstance(decoded, dict) else []
                for frame_number, frame in enumerate(frames, 1):
                    metadata = frame.get("metadata", {}) if isinstance(frame, dict) else {}
                    if metadata:
                        entries.append(
                            {
                                "sequence_number": record.get("sequence_number", "—"),
                                "direction": direction.upper(),
                                "operation": record.get("operation", "—"),
                                "result": record.get("result", "—"),
                                "frame_number": frame_number,
                                "metadata": metadata,
                            }
                        )
    return entries


def _encrypted_rx_by_attribute(
    protected_traffic: list[dict[str, Any]] | None,
) -> dict[tuple[int, str, int], list[str]]:
    evidence: dict[tuple[int, str, int], list[str]] = {}
    for entry in protected_traffic or []:
        if entry.get("direction") != "RX" or entry.get("operation") != "GET":
            continue
        context = entry.get("object_context", {})
        try:
            key = (
                int(context["class_id"]),
                str(context["logical_name"]),
                int(context["attribute_id"]),
            )
        except (KeyError, TypeError, ValueError):
            continue
        ciphertext = str(entry.get("ciphertext_hex") or "")
        if not ciphertext:
            continue
        if not entry.get("ciphertext_complete"):
            ciphertext += " (fragment)"
        values = evidence.setdefault(key, [])
        if ciphertext not in values:
            values.append(ciphertext)
    return evidence


def _encrypted_evidence_display(fragments: list[str]) -> str:
    if not fragments:
        return "—"
    captured_hex = [fragment.split(" ", 1)[0] for fragment in fragments]
    captured_bytes = sum(len(value) // 2 for value in captured_hex)
    if len(fragments) > 3 or sum(map(len, captured_hex)) > 384:
        return (
            f"{len(fragments)} protected response fragments, "
            f"{captured_bytes} captured ciphertext bytes — see traffic.jsonl"
        )
    return "<br>".join(fragments)


def _compact_ciphertext(value: Any, *, hexadecimal_char_limit: int = 64) -> str:
    ciphertext = str(value or "")
    if not ciphertext:
        return "—"
    if len(ciphertext) <= hexadecimal_char_limit:
        return ciphertext
    digest = hashlib.sha256(
        ciphertext.encode("ascii", errors="replace")
    ).hexdigest()[:12]
    return f"{ciphertext[:hexadecimal_char_limit]}… [sha256:{digest}]"


def _scan_scope_label(scan_scope: dict[str, Any]) -> str:
    if not scan_scope.get("short_test"):
        return "Full inventory"
    if scan_scope.get("get_limit") is not None:
        return "First {} of {} mapped GET operations".format(
            scan_scope.get("selected_gets", 0),
            scan_scope.get("mapped_gets", 0),
        )
    if "mapped_gets" not in scan_scope:
        return "First {} objects (short test)".format(
            scan_scope.get("selected_objects", 0)
        )
    return "GETs from first {} objects; {} total GETs mapped".format(
        scan_scope.get("selected_objects", 0),
        scan_scope.get("mapped_gets", 0),
    )


def render_summary_report(
    report: dict[str, Any],
    protected_traffic: list[dict[str, Any]] | None = None,
    protocol_traffic: list[dict[str, Any]] | None = None,
) -> str:
    """Create a compact Markdown view while retaining report.json as evidence."""

    run = report.get("run", {})
    transport = report.get("transport", {})
    profiles = report.get("profiles", [])
    redact_secrets = (
        report.get("effective_configuration", {})
        .get("output", {})
        .get("redact_secrets", True)
    )
    encrypted_rx = _encrypted_rx_by_attribute(protected_traffic)
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
        f"| Secret redaction | {'enabled' if redact_secrets else 'DISABLED'} |",
        "",
    ]
    if not redact_secrets:
        lines.extend(
            [
                "> **Warning:** Secret redaction was disabled. This report and its traffic logs may contain reusable credentials and readable Association data.",
                "",
            ]
        )

    system_title_discovery = report.get("system_title_discovery", {})
    if system_title_discovery.get("enabled"):
        lines.extend(
            [
                "## Passive system-title discovery",
                "",
                "This phase only listened to serial traffic; it did not transmit or decrypt data.",
                "",
                "| Kind | System title | Evidence | Source address | Target address |",
                "|---|---|---|---:|---:|",
            ]
        )
        titles = system_title_discovery.get("titles", [])
        if titles:
            for title in titles:
                lines.append(
                    "| {} | `{}` | {} | {} | {} |".format(
                        _markdown(title.get("kind", "sender")),
                        _markdown(title.get("hex", "—")),
                        _markdown(title.get("source", "—")),
                        _markdown(title.get("source_address", "—")),
                        _markdown(title.get("target_address", "—")),
                    )
                )
        else:
            lines.append("| — | — | No title observed | — | — |")
        lines.extend(
            [
                "",
                f"Frames observed: {_markdown(system_title_discovery.get('frames_seen', 0))}; "
                f"listen status: {_markdown(system_title_discovery.get('status', 'unknown'))}.",
                "",
            ]
        )

    candidate_generation = report.get("candidate_generation", {})
    if candidate_generation:
        lines.extend(
            [
                "## Unlisted-object candidate generation",
                "",
                "Known targets outside the Association View are generated deterministically and bounded before any GET is sent.",
                "",
                "| Field | Value |",
                "|---|---|",
                f"| Providers | {_markdown(', '.join(candidate_generation.get('providers', [])) or 'none')} |",
                f"| Candidate request limit | {_markdown(candidate_generation.get('request_limit', 0))} |",
                f"| Available targets | {_markdown(candidate_generation.get('available_targets', 0))} |",
                f"| Selected targets | {_markdown(candidate_generation.get('selected_targets', 0))} |",
                f"| Truncated targets | {_markdown(candidate_generation.get('truncated_targets', 0))} |",
                f"| Skipped because object was advertised | {_markdown(candidate_generation.get('excluded_association_targets', 0))} |",
                f"| Verified candidates | {_markdown(candidate_generation.get('verified_targets', 0))} |",
                f"| Expected negative evidence | {_markdown(candidate_generation.get('negative_targets', 0))} |",
                f"| Inconclusive candidates | {_markdown(candidate_generation.get('inconclusive_targets', 0))} |",
                "",
            ]
        )

    authentication_matrix = report.get("authentication_matrix", {})
    matrix_roles = authentication_matrix.get("roles", [])
    if matrix_roles:
        lines.extend(
            [
                "## Authentication result matrix",
                "",
                "| Mechanism | "
                + " | ".join(
                    "{} (client {})".format(
                        _markdown(role.get("role", "unknown")),
                        _markdown(role.get("client_address", "—")),
                    )
                    for role in matrix_roles
                )
                + " |",
                "|---|" + "---|" * len(matrix_roles),
            ]
        )
        for row in authentication_matrix.get("rows", []):
            lines.append(
                "| {} | {} |".format(
                    _markdown(
                        row.get("display_name", row.get("mechanism", "unknown"))
                    ),
                    " | ".join(
                        _markdown(
                            row.get("roles", {})
                            .get(role.get("role"), {})
                            .get("status", "—")
                        )
                        for role in matrix_roles
                    ),
                )
            )
        lines.extend(
            [
                "",
                "`authenticated` means the complete association succeeded; for HLS "
                "this includes the challenge-response validation. "
                "`inconsistent_with_known_good` means the same role worked during "
                "the normal scan but failed its first isolated verification; treat "
                "that as meter state, throttling, or lockout evidence rather than a "
                "simple credential rejection.",
                "",
            ]
        )
        health_rows = [
            (profile, check)
            for profile in profiles
            for check in profile.get("authentication_scan", {}).get(
                "health_checks", []
            )
        ]
        if health_rows:
            lines.extend(
                [
                    "### Known-good connection checks",
                    "",
                    "A fresh known-good association is made between authentication mechanisms. Secure checks first refresh the public invocation counter and then use the crash-safe monotonic counter lease.",
                    "",
                    "| Role | After mechanism | Known-good method | Status | Counter handling |",
                    "|---|---|---|---|---|",
                ]
            )
            for profile, check in health_rows:
                lines.append(
                    "| {} | {} | {} | {} | {} |".format(
                        _markdown(profile.get("role", profile.get("name", "—"))),
                        _markdown(check.get("after_mechanism", "—")),
                        _markdown(check.get("mechanism", "—")),
                        _markdown(check.get("status", "—")),
                        _markdown(check.get("counter_safety", "not applicable")),
                    )
                )
            lines.append("")

    for profile in profiles:
        association = profile.get("association", {})
        authentication_enumeration = profile.get("authentication_enumeration", {})
        observed_authentication = ", ".join(
            authentication_enumeration.get("observed_methods", [])
        ) or "none observed"
        summary = profile.get("summary", {})
        expected_candidate_rejections = int(
            candidate_generation.get("negative_targets", 0)
        )
        unexpected_get_failures = max(
            0,
            int(summary.get("get_failed", 0)) - expected_candidate_rejections,
        )
        scan_scope = profile.get("scan_scope", {})
        list_scope = scan_scope.get("get_with_list", {})
        timeout_policy = scan_scope.get("timeout_policy", {})
        list_label = "disabled"
        if list_scope.get("effective_batch_size", 1) > 1:
            list_label = (
                f"up to {list_scope['effective_batch_size']} attributes; "
                f"{list_scope.get('successful_batches', 0)} successful list requests, "
                f"{list_scope.get('fallback_batches', 0)} fallbacks"
            )
        profile_name = str(profile.get("name", "unknown"))
        authentication_scan = profile.get("authentication_scan")
        if isinstance(authentication_scan, dict):
            if matrix_roles:
                continue
            results = authentication_scan.get("results", [])
            lines.extend(
                [
                    f"## Profile: {_markdown(profile_name)}",
                    "",
                    f"Client SAP: {_markdown(association.get('client_address', '—'))}",
                    "",
                    "### Authentication scan",
                    "",
                    "| Mechanism | Attempted | AARQ accepted | Fully authenticated | Security | Status |",
                    "|---|---:|---:|---:|---|---|",
                ]
            )
            for item in results:
                lines.append(
                    "| {} | {} | {} | {} | {} | {} |".format(
                        _markdown(item.get("mechanism", "unknown")),
                        _markdown(item.get("attempted", False)),
                        _markdown(item.get("aarq_accepted", "—")),
                        _markdown(item.get("fully_authenticated", "—")),
                        _markdown(item.get("security_policy", "—")),
                        _markdown(item.get("status", "unknown")),
                    )
                )
            lines.extend(
                [
                    "",
                    "Accepted mechanisms: "
                    + _markdown(
                        ", ".join(
                            authentication_scan.get("accepted_mechanisms", [])
                        )
                        or "none"
                    ),
                    "",
                ]
            )
            continue
        lines.extend(
            [
                f"## Profile: {_markdown(profile_name)}",
                "",
                "| Field | Value |",
                "|---|---|",
                f"| Client address | {_markdown(association.get('client_address', '—'))} |",
                f"| Authentication | {_markdown(association.get('authentication', 'none'))} |",
                f"| Authentication methods observed | {_markdown(observed_authentication)} |",
                f"| Advertised Association LNs | {_markdown(len(authentication_enumeration.get('advertised_associations', [])))} |",
                f"| Security | {_markdown(association.get('security', 'none'))} |",
                f"| Security suite | {_markdown(association.get('security_suite', '—'))} |",
                f"| HLS validated | {_markdown(association.get('hls_validated', '—'))} |",
                f"| Client system title | {_markdown(association.get('client_system_title', '—'))} |",
                f"| Client manufacturer ID | {_markdown((association.get('client_system_title_metadata') or {}).get('manufacturer_id', '—'))} |",
                f"| Server system title | {_markdown(association.get('server_system_title', '—'))} |",
                f"| Server manufacturer ID | {_markdown((association.get('server_system_title_metadata') or {}).get('manufacturer_id', '—'))} |",
                f"| Objects | {_markdown(summary.get('objects', 0))} |",
                f"| Scan scope | {_markdown(_scan_scope_label(scan_scope))} |",
                f"| Association View objects | {_markdown(scan_scope.get('association_view_objects', profile.get('association_view_object_count', '—')))} |",
                f"| Association View source | {_markdown(report.get('association_view', {}).get('mode', profile.get('association_view_source', 'live')))} |",
                f"| GET results | {_markdown(summary.get('get_success', 0))} successful / {_markdown(unexpected_get_failures)} unexpected failures / {_markdown(expected_candidate_rejections)} expected candidate rejections / {_markdown(summary.get('get_inconclusive', 0))} inconclusive |",
                f"| GET transmissions | {_markdown(summary.get('get_transmissions', 0))} |",
                f"| GET-with-list | {_markdown(list_label)} |",
                f"| Enumeration timeout | {_markdown(timeout_policy.get('enumeration_timeout_ms', '—'))} ms |",
                f"| Timeout circuit breaker | {_markdown(timeout_policy.get('trips', 0))} trips / {_markdown(timeout_policy.get('successful_reconnects', 0))} successful reconnects / stopped: {_markdown(timeout_policy.get('stopped', False))} |",
                f"| GET not tested | {_markdown(summary.get('get_not_tested', 0))} |",
                f"| Advertised SET attributes | {_markdown(summary.get('advertised_set_attributes', 0))} (not tested) |",
                f"| Advertised ACTION methods | {_markdown(summary.get('advertised_action_methods', 0))} (not tested) |",
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
        reuse_test = association.get("invocation_counter_reuse_test")
        if isinstance(reuse_test, dict):
            lines.extend(
                [
                    f"| Counter-reuse test | {_markdown(reuse_test.get('status', '—'))} |",
                    f"| Replayed counters accepted | {_markdown(reuse_test.get('accepted_probes', 0))} / {_markdown(reuse_test.get('attempted_probes', 0))} |",
                ]
            )
        lines.append("")

        protocol_metadata = association.get("protocol_metadata", {})
        request_metadata = protocol_metadata.get("request", {})
        response_metadata = protocol_metadata.get("response", {})
        if request_metadata or response_metadata:
            association_result = response_metadata.get("association_result")
            result_label = {
                0: "accepted",
                1: "permanently rejected",
                2: "transiently rejected",
            }.get(association_result, association_result or "—")
            diagnostic = response_metadata.get("result_source_diagnostic", {})
            diagnostic_label = (
                "{} code {}".format(
                    diagnostic.get("source", "unknown"),
                    diagnostic.get("code", "—"),
                )
                if diagnostic
                else "—"
            )
            lines.extend(
                [
                    "### Association negotiation metadata",
                    "",
                    "| Field | Client proposed | Server response |",
                    "|---|---|---|",
                    "| Application context | {} | {} |".format(
                        _markdown(request_metadata.get("application_context", "—")),
                        _markdown(response_metadata.get("application_context", "—")),
                    ),
                    "| DLMS version | {} | {} |".format(
                        _markdown(request_metadata.get("proposed_dlms_version", "—")),
                        _markdown(response_metadata.get("negotiated_dlms_version", "—")),
                    ),
                    "| Conformance | {} | {} |".format(
                        _markdown(", ".join(request_metadata.get("proposed_conformance", [])) or "—"),
                        _markdown(", ".join(response_metadata.get("negotiated_conformance", [])) or "—"),
                    ),
                    "| Maximum PDU | {} | {} |".format(
                        _markdown(request_metadata.get("proposed_max_pdu_size", "—")),
                        _markdown(response_metadata.get("negotiated_max_pdu_size", "—")),
                    ),
                    "| Quality of service | {} | {} |".format(
                        _markdown(request_metadata.get("proposed_quality_of_service", "—")),
                        _markdown(response_metadata.get("negotiated_quality_of_service", "—")),
                    ),
                    f"| Association result | — | {_markdown(result_label)} |",
                    f"| Result diagnostic | — | {_markdown(diagnostic_label)} |",
                    f"| VAA name | — | {_markdown(response_metadata.get('vaa_name', '—'))} |",
                    "",
                ]
            )

        association_objects = profile.get("association_metadata", [])
        if association_objects:
            privacy_note = (
                "User names and Association secrets are not included in this human-readable report."
                if redact_secrets
                else "Secret redaction is disabled; readable user and Association-secret values are shown below."
            )
            lines.extend(
                [
                    "### Association object metadata",
                    "",
                    privacy_note,
                    "",
                    "| Association LN | Version | Client SAP | Server SAP | Application context | xDLMS context | Mechanism | Status | Security Setup | Users | Current user | Association secret |",
                    "|---|---:|---:|---:|---|---|---|---|---|---|---|---|",
                ]
            )
            for item in association_objects:
                user_list = item.get("user_list", {})
                current_user = item.get("current_user", {})
                users_display = (
                    user_list.get("count", "—")
                    if redact_secrets
                    else _compact_value(user_list.get("value"))
                )
                lines.append(
                    "| {} | {} | {} | {} | {} | {} | {} | {} | {} | {} | {} | {} |".format(
                        _markdown(item.get("logical_name", "—")),
                        _markdown(item.get("object_version", "—")),
                        _markdown(item.get("client_sap", "—")),
                        _markdown(item.get("server_sap", "—")),
                        _markdown(_compact_value(item.get("application_context"))),
                        _markdown(_compact_value(item.get("xdlms_context_info"))),
                        _markdown(_compact_value(item.get("authentication_mechanism"))),
                        _markdown(_compact_value(item.get("association_status"))),
                        _markdown(_compact_value(item.get("security_setup_reference"))),
                        _markdown(users_display),
                        _markdown(
                            "—"
                            if redact_secrets
                            else _compact_value(current_user.get("value"))
                        ),
                        _markdown(
                            "—"
                            if redact_secrets
                            else _compact_value(item.get("association_secret"))
                        ),
                    )
                )
            lines.append("")

        view_comparison = report.get("association_view", {}).get("comparison")
        if isinstance(view_comparison, dict):
            lines.extend(
                [
                    "### Association View comparison",
                    "",
                    "Result: **{}** — {} added, {} removed, {} changed object(s).".format(
                        "match" if view_comparison.get("matches") else "changed",
                        len(view_comparison.get("added", [])),
                        len(view_comparison.get("removed", [])),
                        len(view_comparison.get("changed", [])),
                    ),
                    "",
                ]
            )
            differences = [
                (label, item)
                for key, label in (
                    ("added", "Added on meter"),
                    ("removed", "Missing from meter"),
                    ("changed", "Version/access changed"),
                )
                for item in view_comparison.get(key, [])
            ]
            if differences:
                lines.extend(
                    [
                        "| Difference | Class | Logical name |",
                        "|---|---:|---|",
                    ]
                )
                for label, item in differences:
                    lines.append(
                        "| {} | {} | {} |".format(
                            _markdown(label),
                            _markdown(item.get("class_id", "—")),
                            _markdown(item.get("logical_name", "—")),
                        )
                    )
                lines.append("")

        advertised_associations = authentication_enumeration.get(
            "advertised_associations", []
        )
        if advertised_associations:
            lines.extend(
                [
                    "### Authentication enumeration",
                    "",
                    "| Association LN | Client SAP | Server SAP | Mechanism ID | Mechanism | Evidence |",
                    "|---|---:|---:|---:|---|---|",
                ]
            )
            for item in advertised_associations:
                lines.append(
                    "| {} | {} | {} | {} | {} | {} |".format(
                        _markdown(item.get("logical_name", "—")),
                        _markdown(item.get("client_sap", "—")),
                        _markdown(item.get("server_sap", "—")),
                        _markdown(item.get("mechanism_id", "—")),
                        _markdown(item.get("mechanism", "unknown")),
                        _markdown(item.get("evidence", "—")),
                    )
                )
            lines.extend(
                [
                    "",
                    _markdown(authentication_enumeration.get("limitation", "")),
                    "",
                ]
            )

        if isinstance(reuse_test, dict) and reuse_test.get("enabled"):
            lines.extend(["### Invocation-counter reuse test", ""])
            if reuse_test.get("device_allows_reuse"):
                lines.extend(
                    [
                        "**Invocation-counter reuse was accepted by the meter.** At least one protected GET using a stale counter succeeded.",
                        "",
                    ]
                )
            elif reuse_test.get("status") == "reuse_not_observed":
                lines.extend(
                    [
                        "No stale-counter GET was accepted in the two requested probes.",
                        "",
                    ]
                )
            else:
                lines.extend(
                    [
                        "The replay diagnostic was inconclusive; inspect the individual outcomes and traffic log.",
                        "",
                    ]
                )
            lines.extend(
                [
                    "| Probe | Counter source | Reused counter | Outcome | Accepted |",
                    "|---:|---|---|---|---|",
                ]
            )
            for probe in reuse_test.get("probes", []):
                lines.append(
                    "| {} | {} | {} | {} | {} |".format(
                        _markdown(probe.get("sequence", "—")),
                        _markdown(probe.get("source", "—")),
                        _markdown(
                            probe.get(
                                "reused_counter_hex",
                                probe.get("reused_counter", "—"),
                            )
                        ),
                        _markdown(probe.get("outcome", "—")),
                        _markdown(probe.get("accepted", False)),
                    )
                )
            lines.append("")
            recoveries = [
                (probe.get("sequence", "—"), probe.get("recovery"))
                for probe in reuse_test.get("probes", [])
                if isinstance(probe.get("recovery"), dict)
            ]
            if recoveries:
                lines.extend(
                    [
                        "#### Post-replay recovery",
                        "",
                        "| Probe | Safe counter | Safe GET | Fresh client | Reconnect attempts | Waited (ms) |",
                        "|---:|---:|---|---|---:|---:|",
                    ]
                )
                for sequence, recovery in recoveries:
                    lines.append(
                        "| {} | {} | {} | {} | {} | {} |".format(
                            _markdown(sequence),
                            _markdown(recovery.get("safe_counter", "—")),
                            _markdown(recovery.get("safe_get_succeeded", False)),
                            _markdown(recovery.get("fresh_client", False)),
                            _markdown(recovery.get("reconnect_attempts", 0)),
                            _markdown(recovery.get("waited_ms", 0)),
                        )
                    )
                lines.append("")

        identification = profile.get("identification", {})
        if identification:
            lines.extend(["### Identification", "", "| Item | Value |", "|---|---|"])
            for key, value in identification.items():
                lines.append(f"| {_markdown(key)} | {_markdown(_compact_value(value))} |")
            lines.append("")

        posture = profile.get("security_posture", {})
        if posture.get("security_setup_objects") or posture.get(
            "image_transfer_objects"
        ) or posture.get("candidate_objects"):
            lines.extend(
                [
                    "### Security and firmware-update posture",
                    "",
                    "This section is read-only. Advertised SET and ACTION permissions are passive evidence and were not executed.",
                    "",
                ]
            )
            for heading, objects in (
                ("Security Setup", posture.get("security_setup_objects", [])),
                ("Image Transfer", posture.get("image_transfer_objects", [])),
            ):
                for item in objects:
                    lines.extend(
                        [
                            f"#### {heading} `{_markdown(item.get('logical_name', '—'))}`",
                            "",
                            "| Member | Read | Write/action | Requirements | Result/value |",
                            "|---|---|---|---|---|",
                        ]
                    )
                    for attribute in item.get("attributes", []):
                        value = attribute.get("value")
                        outcome_value = (
                            _compact_value(value)
                            if value is not None
                            else attribute.get("outcome", "NOT_TESTED")
                        )
                        lines.append(
                            "| {} | {} | {} | {} | {} |".format(
                                _markdown(attribute.get("name", "—")),
                                _markdown(attribute.get("read_advertised", False)),
                                _markdown(attribute.get("write_advertised", False)),
                                _markdown(
                                    ", ".join(attribute.get("requirements", [])) or "none"
                                ),
                                _markdown(outcome_value),
                            )
                        )
                    for method in item.get("methods", []):
                        if not method.get("advertised"):
                            continue
                        lines.append(
                            "| {} | — | {} | {} | passive only |".format(
                                _markdown(method.get("name", "—")),
                                _markdown(True),
                                _markdown(
                                    ", ".join(method.get("requirements", [])) or "none"
                                ),
                            )
                        )
                    lines.append("")
            candidate_objects = posture.get("candidate_objects", [])
            if candidate_objects:
                lines.extend(
                    [
                        "#### Generated candidates",
                        "",
                        "These objects were not advertised by the meter. Their results are probe evidence, not Association View permissions.",
                        "",
                        "| Class | Logical name | Result |",
                        "|---:|---|---|",
                    ]
                )
                for item in candidate_objects:
                    lines.append(
                        "| {} | {} | {} |".format(
                            _markdown(item.get("class_id", "—")),
                            _markdown(item.get("logical_name", "—")),
                            _markdown(
                                item.get("discovery_status", "candidate_not_tested")
                            ),
                        )
                    )
                lines.append("")
            findings = posture.get("findings", [])
            if findings:
                lines.extend(["#### Findings", ""])
                for finding in findings:
                    lines.append(
                        f"- **{_markdown(str(finding.get('severity', 'info')).upper())}:** "
                        f"{_markdown(finding.get('message', ''))}"
                    )
                lines.append("")
            lines.extend([_markdown(posture.get("limitations", "")), ""])

        selector_rows = [
            (obj, attribute, attribute.get("access_rights", {}).get("access_selectors"))
            for obj in profile.get("objects", [])
            for attribute in obj.get("attributes", [])
            if attribute.get("access_rights", {}).get("access_selectors")
        ]
        if selector_rows:
            lines.extend(
                [
                    "### Selective-access metadata",
                    "",
                    "These selectors describe the bounded or filtered reads advertised by the meter.",
                    "",
                    "| OBIS | Class | Attribute | Name | Selectors |",
                    "|---|---:|---:|---|---|",
                ]
            )
            for obj, attribute, selectors in selector_rows:
                lines.append(
                    "| {} | {} | {} | {} | {} |".format(
                        _markdown(obj.get("logical_name", "—")),
                        _markdown(obj.get("class_id", "—")),
                        _markdown(attribute.get("attribute_id", "—")),
                        _markdown(attribute.get("name") or "—"),
                        _markdown(_compact_value(selectors)),
                    )
                )
            lines.append("")

        engineering_rows = [
            obj
            for obj in profile.get("objects", [])
            if obj.get("engineering_metadata")
        ]
        if engineering_rows:
            lines.extend(
                [
                    "### Engineering metadata",
                    "",
                    "Scaler and unit apply to the related register values; raw values remain available in `report.json`.",
                    "",
                    "| OBIS | Class | Scaler | Unit | Status | Capture time | Period |",
                    "|---|---:|---:|---|---|---|---:|",
                ]
            )
            for obj in engineering_rows:
                metadata = obj.get("engineering_metadata", {})
                lines.append(
                    "| {} | {} | {} | {} | {} | {} | {} |".format(
                        _markdown(obj.get("logical_name", "—")),
                        _markdown(obj.get("class_id", "—")),
                        _markdown(_compact_value(metadata.get("scaler"))),
                        _markdown(_compact_value(metadata.get("unit"))),
                        _markdown(_compact_value(metadata.get("status"))),
                        _markdown(_compact_value(metadata.get("capture_time"))),
                        _markdown(_compact_value(metadata.get("period"))),
                    )
                )
            lines.append("")

        temporal_rows = []
        for obj in profile.get("objects", []):
            for attribute in obj.get("attributes", []):
                decoded = attribute.get("decoded", {})
                value = decoded.get("value") if isinstance(decoded, dict) else None
                if isinstance(value, dict) and (
                    "clock_status" in value or "skipped_fields" in value
                ):
                    temporal_rows.append((obj, attribute, value))
        if temporal_rows:
            lines.extend(
                [
                    "### Date/time metadata",
                    "",
                    "| OBIS | Attribute | Value | Day of week | Skipped fields | Clock status | Extra information |",
                    "|---|---:|---|---:|---|---|---|",
                ]
            )
            for obj, attribute, value in temporal_rows:
                lines.append(
                    "| {} | {} | {} | {} | {} | {} | {} |".format(
                        _markdown(obj.get("logical_name", "—")),
                        _markdown(attribute.get("attribute_id", "—")),
                        _markdown(value.get("value") or value.get("display") or "—"),
                        _markdown(value.get("day_of_week", "—")),
                        _markdown(", ".join(value.get("skipped_fields", [])) or "none"),
                        _markdown(", ".join(value.get("clock_status", [])) or "none"),
                        _markdown(", ".join(value.get("extra_info", [])) or "none"),
                    )
                )
            lines.append("")

        profile_buffers = _render_profile_buffers(profile)
        if profile_buffers:
            lines.extend(
                [
                    "### Profile Generic logs and rows",
                    "",
                    "Rows from multi-block responses are shown after the complete response has been reassembled. The canonical values remain in `report.json`.",
                    "",
                    *profile_buffers,
                ]
            )

        lines.extend(
            [
                "### Decoded OBIS values",
                "",
                "This human view shows attempted GET attributes. Type values are shown as `wire / interface / UI`; `unknown` means that source did not provide a type. Logical-name attribute 1 and untested rows are omitted; the complete inventory remains in `report.json`. Large encrypted responses are summarized, with complete evidence in `traffic.jsonl`.",
                "",
                "| OBIS | Class | Attribute | Name | Type | Decoded value | Encoded value (hex) | Encrypted response (hex) | Result |",
                "|---|---:|---:|---|---|---|---|---|---|",
            ]
        )
        omitted_decoded_attributes = 0
        for obj in profile.get("objects", []):
            attributes = list(obj.get("attributes", []))
            attributes = [
                item
                for item in attributes
                if item.get("access_rights", {}).get("read", True)
                or item.get("access_rights", {}).get("catalogue_probe", False)
            ]
            display_attributes = [item for item in attributes if item.get("attribute_id") != 1]
            for attribute in display_attributes:
                result = (
                    attribute.get("outcome")
                    or attribute.get("lifecycle")
                    or "not scanned"
                )
                if result == Outcome.NOT_TESTED.value:
                    omitted_decoded_attributes += 1
                    continue
                decoded = attribute.get("decoded", {})
                value = decoded.get("value") if isinstance(decoded, dict) else None
                raw = decoded.get("raw_value") if isinstance(decoded, dict) else None
                profile_rows = _profile_buffer_value(obj, attribute)
                if profile_rows is not None:
                    value = f"{len(profile_rows)} rows — see Profile Generic table above"
                    raw = None
                encrypted = encrypted_rx.get(
                    (
                        int(obj.get("class_id", 0)),
                        str(obj.get("logical_name", "")),
                        int(attribute.get("attribute_id", 0)),
                    ),
                    [],
                )
                encrypted_display = _encrypted_evidence_display(encrypted)
                lines.append(
                    "| {} | {} | {} | {} | {} | {} | {} | {} | {} |".format(
                        _markdown(obj.get("logical_name", "—")),
                        _markdown(obj.get("class_id", "—")),
                        _markdown(attribute.get("attribute_id", "—")),
                        _markdown(attribute.get("name") or "—"),
                        _markdown(_data_type_summary(decoded)),
                        _markdown(_compact_value(value)),
                        _markdown(_hex_value(raw)),
                        _markdown(encrypted_display),
                        _markdown(result),
                    )
                )
        if omitted_decoded_attributes:
            lines.append(
                f"| — | — | — | — | — | — | — | {omitted_decoded_attributes} untested attributes omitted; see report.json | — |"
            )
        lines.append("")

        lines.extend(
            [
                "### Operation capability matrix",
                "",
                "Attempted GET operations and all advertised SET/ACTION permissions are listed. Untested GET detail remains in `report.json`. SET and ACTION are mapped passively and are never sent, so they remain `NOT_TESTED`.",
                "",
                "| Operation | OBIS | Class | Member | Name | Access mode | Status |",
                "|---|---|---:|---:|---|---|---|",
            ]
        )
        omitted_get_operations = 0
        for obj in profile.get("objects", []):
            for attribute in obj.get("attributes", []):
                if attribute.get("attribute_id") == 1:
                    continue
                rights = attribute.get("access_rights", {})
                if rights.get("read", True) or rights.get("catalogue_probe", False):
                    outcome = attribute.get("outcome") or Outcome.NOT_TESTED.value
                    if outcome == Outcome.NOT_TESTED.value:
                        omitted_get_operations += 1
                    else:
                        lines.append(
                            "| GET | {} | {} | {} | {} | {} | {} |".format(
                                _markdown(obj.get("logical_name", "—")),
                                _markdown(obj.get("class_id", "—")),
                                _markdown(attribute.get("attribute_id", "—")),
                                _markdown(attribute.get("name") or "—"),
                                _markdown(attribute.get("advertised_access", "—")),
                                _markdown(outcome),
                            )
                        )
                if rights.get("write", False):
                    lines.append(
                        "| SET | {} | {} | {} | {} | {} | NOT_TESTED |".format(
                            _markdown(obj.get("logical_name", "—")),
                            _markdown(obj.get("class_id", "—")),
                            _markdown(attribute.get("attribute_id", "—")),
                            _markdown(attribute.get("name") or "—"),
                            _markdown(attribute.get("advertised_access", "—")),
                        )
                    )
            for method in obj.get("methods", []):
                if not method.get("access_rights", {}).get("action", False):
                    continue
                lines.append(
                    "| ACTION | {} | {} | {} | {} | {} | NOT_TESTED |".format(
                        _markdown(obj.get("logical_name", "—")),
                        _markdown(obj.get("class_id", "—")),
                        _markdown(method.get("method_id", "—")),
                        _markdown(method.get("name") or "—"),
                        _markdown(method.get("advertised_access", "—")),
                    )
                )
        if omitted_get_operations:
            lines.append(
                f"| GET | — | — | — | — | — | {omitted_get_operations} untested operations omitted; see report.json |"
            )
        lines.append("")

    union_test = report.get("public_union_test", {})
    if union_test.get("enabled"):
        lines.extend(
            [
                "## Public cross-profile access test",
                "",
                "Authenticated-readable attributes absent from the public role's readable Association View were addressed directly through a fresh public association. A successful GET is flagged as unexpected public access; an explicit DLMS error is a rejection, while transport and protocol failures are inconclusive.",
                "",
                "| Field | Value |",
                "|---|---|",
                f"| Status | {_markdown(union_test.get('status', 'unknown'))} |",
                f"| Public Association View objects | {_markdown(union_test.get('public_association_view_objects', '—'))} |",
                f"| Candidate GETs | {_markdown(union_test.get('candidate_gets', 0))} |",
                f"| Selected GETs | {_markdown(union_test.get('selected_gets', union_test.get('candidate_gets', 0)))} |",
                f"| Unexpected public access | {_markdown(union_test.get('unexpected_public_access', 0))} |",
                f"| Public access rejected | {_markdown(union_test.get('public_access_rejected', 0))} |",
                f"| Inconclusive | {_markdown(union_test.get('inconclusive', 0))} |",
                "",
            ]
        )
        results = union_test.get("results", [])
        if results:
            lines.extend(
                [
                    "| OBIS | Class | Attribute | Name | Public view | Result | Assessment | Type (wire / interface / UI) | Decoded value |",
                    "|---|---:|---:|---|---|---|---|---|---|",
                ]
            )
            for result in results:
                decoded = result.get("decoded", {})
                value = decoded.get("value") if isinstance(decoded, dict) else None
                public_view = result.get("public_advertised_access") or (
                    "object advertised; attribute absent"
                    if result.get("public_object_advertised")
                    else "object absent"
                )
                lines.append(
                    "| {} | {} | {} | {} | {} | {} | {} | {} | {} |".format(
                        _markdown(result.get("logical_name", "—")),
                        _markdown(result.get("class_id", "—")),
                        _markdown(result.get("attribute_id", "—")),
                        _markdown(result.get("name") or "—"),
                        _markdown(public_view),
                        _markdown(result.get("outcome", "—")),
                        _markdown(result.get("access_assessment", "—")),
                        _markdown(_data_type_summary(decoded)),
                        _markdown(_compact_value(value)),
                    )
                )
            lines.append("")

    if protocol_traffic:
        lines.extend(
            [
                "## Protocol exchange metadata",
                "",
                "This compact view exposes HDLC sequencing, segmentation, FCS validation, xDLMS invoke IDs, block-transfer state, and selective-access parameters. Complete frame metadata and translated XML remain in `traffic.jsonl`.",
                "",
                "| Seq. | Direction | Operation | HDLC | Invoke | Block transfer | Selective access | FCS | Result |",
                "|---:|---|---|---|---|---|---|---|---|",
            ]
        )
        displayed_protocol = protocol_traffic
        omitted_protocol = 0
        if len(protocol_traffic) > 80:
            displayed_protocol = protocol_traffic[:40] + protocol_traffic[-40:]
            omitted_protocol = len(protocol_traffic) - 80
        for entry in displayed_protocol:
            metadata = entry.get("metadata", {})
            hdlc = "{}→{} {}; control {}".format(
                metadata.get("source_address", "—"),
                metadata.get("target_address", "—"),
                metadata.get("frame_class", "—"),
                metadata.get("control", "—"),
            )
            if metadata.get("frame_class") == "information":
                hdlc += "; N(S)={}; N(R)={}".format(
                    metadata.get("send_sequence", "—"),
                    metadata.get("receive_sequence", "—"),
                )
            if metadata.get("segmented"):
                hdlc += "; segmented"
            invoke = metadata.get("invoke", {})
            invoke_label = (
                "id {}; {}; {}".format(
                    invoke.get("invoke_id", "—"),
                    invoke.get("priority", "—"),
                    invoke.get("service_class", "—"),
                )
                if invoke
                else "—"
            )
            block_values = []
            for key, label in (
                ("block_number", "block"),
                ("block_number_ack", "ack"),
                ("window_size", "window"),
                ("last_block", "last"),
            ):
                if key in metadata:
                    block_values.append(f"{label}={metadata[key]}")
            lines.append(
                "| {} | {} | {} | {} | {} | {} | {} | {} | {} |".format(
                    _markdown(entry.get("sequence_number", "—")),
                    _markdown(entry.get("direction", "—")),
                    _markdown(entry.get("operation", "—")),
                    _markdown(hdlc),
                    _markdown(invoke_label),
                    _markdown(", ".join(block_values) or "—"),
                    _markdown(_compact_value(metadata.get("selective_access"))),
                    _markdown(metadata.get("fcs_valid", "—")),
                    _markdown(entry.get("result", "—")),
                )
            )
        if omitted_protocol:
            lines.append(
                f"| — | — | — | — | — | — | {omitted_protocol} frame entries omitted; see traffic.jsonl | — | — |"
            )
        lines.append("")

    if protected_traffic:
        lines.extend(
            [
                "## Protected APDU evidence",
                "",
                "The security-control byte is decoded into suite, authentication, encryption, compression, broadcast-key, and key-scope fields. Ciphertext below excludes the security-control byte, invocation counter, and any 12-byte AES-GCM authentication tag. A complete successfully decoded authenticated response also means its tag was verified; `fragment` means only the ciphertext bytes present in that HDLC segment are shown.",
                "",
                "| Seq. | Direction | Operation | Protected command | Security control | Invocation counter | Ciphertext (hex) | Capture | AES-GCM tag (hex) | Result | Protection details |",
                "|---:|---|---|---|---|---:|---|---|---|---|---|",
            ]
        )
        displayed_protected_traffic = protected_traffic
        omitted_protected_entries = 0
        if len(protected_traffic) > 80:
            displayed_protected_traffic = (
                protected_traffic[:40] + protected_traffic[-40:]
            )
            omitted_protected_entries = len(protected_traffic) - 80
        for entry in displayed_protected_traffic:
            captured_length = entry.get("ciphertext_captured_length", 0)
            declared_length = entry.get("ciphertext_declared_length", 0)
            capture = (
                f"complete ({captured_length} bytes)"
                if entry.get("ciphertext_complete")
                else f"fragment ({captured_length}/{declared_length} bytes)"
            )
            tag = entry.get("authentication_tag_hex") or "—"
            if tag != "—" and not entry.get("authentication_tag_complete"):
                tag = f"{tag} (fragment)"
            protection = "{}; suite {}; {}; {}{}{}".format(
                entry.get("security_control", "—"),
                entry.get("security_suite", "—"),
                (
                    "authentication + encryption"
                    if entry.get("authenticated") and entry.get("encrypted")
                    else "authentication"
                    if entry.get("authenticated")
                    else "encryption"
                    if entry.get("encrypted")
                    else "no protection"
                ),
                entry.get("key_scope", "—"),
                "; compressed" if entry.get("compressed") else "",
                "; broadcast key" if entry.get("broadcast_key") else "",
            )
            lines.append(
                "| {} | {} | {} | {} | {} | {} | {} | {} | {} | {} | {} |".format(
                    _markdown(entry.get("sequence_number", "—")),
                    _markdown(entry.get("direction", "—")),
                    _markdown(entry.get("operation", "—")),
                    _markdown(entry.get("protected_command", "—")),
                    _markdown(entry.get("security_control", "—")),
                    _markdown(entry.get("invocation_counter", "—")),
                    _markdown(_compact_ciphertext(entry.get("ciphertext_hex"))),
                    _markdown(capture),
                    _markdown(tag),
                    _markdown(entry.get("result", "—")),
                    _markdown(protection),
                )
            )
        if omitted_protected_entries:
            lines.append(
                f"| — | — | — | — | — | — | {omitted_protected_entries} entries omitted; see traffic.jsonl | — | — | — | — |"
            )
        lines.append("")
        general_entries = [
            entry
            for entry in protected_traffic
            if entry.get("transaction_id") is not None
            or entry.get("originator_system_title") != "—"
            or entry.get("recipient_system_title") != "—"
        ]
        if general_entries:
            lines.extend(
                [
                    "### General-ciphering envelope metadata",
                    "",
                    "| Seq. | Direction | Transaction ID | Originator title | Recipient title | Date/time (hex) | Key parameters |",
                    "|---:|---|---:|---|---|---|---|",
                ]
            )
            for entry in general_entries:
                lines.append(
                    "| {} | {} | {} | {} | {} | {} | {} |".format(
                        _markdown(entry.get("sequence_number", "—")),
                        _markdown(entry.get("direction", "—")),
                        _markdown(entry.get("transaction_id", "—")),
                        _markdown(entry.get("originator_system_title", "—")),
                        _markdown(entry.get("recipient_system_title", "—")),
                        _markdown(entry.get("ciphering_datetime_hex") or "—"),
                        _markdown(entry.get("key_parameters", "—")),
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
            "Raw protocol traffic: `traffic.jsonl`  "
            if report.get("related_logs", {}).get("profile_logs_file")
            else "Raw protocol traffic: `traffic.jsonl`",
        ]
    )
    profile_log_file = report.get("related_logs", {}).get("profile_logs_file")
    if profile_log_file:
        lines.append(f"Profile Generic rows: `{_markdown(profile_log_file)}`")
    lines.append("")
    return "\n".join(lines)


def write_summary_report(
    report: dict[str, Any],
    path: str | Path,
    traffic_path: str | Path | None = None,
) -> None:
    protected_traffic = (
        _protected_traffic_entries(traffic_path) if traffic_path is not None else None
    )
    protocol_traffic = (
        _protocol_traffic_entries(traffic_path) if traffic_path is not None else None
    )
    _atomic_write_text(
        path,
        render_summary_report(report, protected_traffic, protocol_traffic),
    )


def _profile_log_records(report: dict[str, Any]) -> list[dict[str, Any]]:
    """Create one schema record and one record per Profile Generic row."""

    records: list[dict[str, Any]] = []
    for profile in report.get("profiles", []):
        for obj in profile.get("objects", []):
            metadata = obj.get("profile_generic")
            if int(obj.get("class_id", -1)) != 7 or not isinstance(metadata, dict):
                continue
            buffer_attribute = next(
                (
                    attribute
                    for attribute in obj.get("attributes", [])
                    if int(attribute.get("attribute_id", -1)) == 2
                    and attribute.get("outcome") == Outcome.SUCCESS.value
                ),
                None,
            )
            if buffer_attribute is None:
                continue
            decoded = buffer_attribute.get("decoded", {})
            rows = decoded.get("value") if isinstance(decoded, dict) else None
            raw_rows = decoded.get("raw_value") if isinstance(decoded, dict) else None
            if not isinstance(rows, list):
                continue
            identity = {
                "profile": profile.get("name"),
                "class_id": 7,
                "logical_name": obj.get("logical_name"),
            }
            records.append(
                {
                    "record_type": "profile_schema",
                    **identity,
                    "metadata": metadata,
                }
            )
            columns = metadata.get("columns", [])
            for entry, row in enumerate(rows, 1):
                values = list(row) if isinstance(row, (list, tuple)) else [row]
                raw_values = (
                    list(raw_rows[entry - 1])
                    if isinstance(raw_rows, list)
                    and entry <= len(raw_rows)
                    and isinstance(raw_rows[entry - 1], (list, tuple))
                    else [None] * len(values)
                )
                cells = []
                for position, value in enumerate(values, 1):
                    column = columns[position - 1] if position <= len(columns) else {}
                    cells.append(
                        {
                            "position": position,
                            "source": {
                                key: column.get(key)
                                for key in (
                                    "class_id",
                                    "logical_name",
                                    "attribute_id",
                                    "data_index",
                                )
                            },
                            "dlms_data_type": column.get("dlms_data_type"),
                            "interface_data_type": column.get("interface_data_type"),
                            "ui_data_type": column.get("ui_data_type"),
                            "value": value,
                            "raw_value": raw_values[position - 1]
                            if position <= len(raw_values)
                            else None,
                        }
                    )
                records.append(
                    {
                        "record_type": "profile_row",
                        **identity,
                        "entry": entry,
                        "values": cells,
                    }
                )
    return records


def write_report(
    report: dict[str, Any],
    path: str | Path,
    traffic_path: str | Path,
    summary_path: str | Path | None = None,
) -> None:
    report["related_logs"] = {
        "traffic_file": str(Path(traffic_path).name),
        "traffic_sha256": sha256_file(traffic_path),
    }
    profile_records = _profile_log_records(report)
    if profile_records:
        profile_log_path = Path(path).with_name("profile-logs.jsonl")
        _atomic_write_text(
            profile_log_path,
            "".join(
                json.dumps(record, ensure_ascii=False, separators=(",", ":")) + "\n"
                for record in profile_records
            ),
        )
        report["related_logs"].update(
            {
                "profile_logs_file": profile_log_path.name,
                "profile_logs_sha256": sha256_file(profile_log_path),
                "profile_log_records": len(profile_records),
            }
        )
    if summary_path is not None:
        write_summary_report(report, summary_path, traffic_path)
    if summary_path is not None:
        report["related_logs"].update(
            {
                "summary_file": str(Path(summary_path).name),
                "summary_sha256": sha256_file(summary_path),
            }
        )
    _atomic_write_text(path, json.dumps(report, indent=2, ensure_ascii=False) + "\n")


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
    expected_candidate_rejections = int(
        report.get("candidate_generation", {}).get("negative_targets", 0)
    )
    unexpected_get_failures = max(
        0, int(summary.get("get_failed", 0)) - expected_candidate_rejections
    )
    lines = [
        f"Run: {run.get('id', 'unknown')} ({run.get('status', 'unknown')})",
        f"Profile: {profile.get('name', 'not established')}",
        f"Baud rate: {report.get('transport', {}).get('selected_baudrate', 'not found')}",
        f"HDLC server address: {report.get('transport', {}).get('selected_server_address', 'not found')}",
        f"Server Addressing Type: {report.get('transport', {}).get('server_addressing_type', 'not found')}",
        f"Objects: {summary.get('objects', 0)}",
        f"GET: {summary.get('get_success', 0)} success, {unexpected_get_failures} unexpected failures, {expected_candidate_rejections} expected candidate rejections, {summary.get('get_inconclusive', 0)} inconclusive",
        f"GET not tested: {summary.get('get_not_tested', 0)}",
        f"Advertised SET attributes: {summary.get('advertised_set_attributes', 0)} (not tested)",
        f"Advertised ACTION methods: {summary.get('advertised_action_methods', 0)} (not tested)",
        f"Errors: {len(report.get('errors', []))}",
    ]
    association = profile.get("association", {})
    authentication = profile.get("authentication_enumeration", {})
    authentication_scan = profile.get("authentication_scan", {})
    if authentication_scan:
        accepted = ", ".join(
            authentication_scan.get("accepted_mechanisms", [])
        ) or "none"
        lines.insert(2, f"Authenticated mechanisms: {accepted}")
        lines.insert(
            3,
            f"Mechanisms attempted: {summary.get('mechanisms_attempted', 0)}",
        )
    if authentication:
        lines.insert(
            2,
            "Authentication methods observed: "
            + (", ".join(authentication.get("observed_methods", [])) or "none"),
        )
    if profile.get("type", profile.get("name")) == "hls_gmac_suite0":
        lines.insert(2, f"HLS-GMAC validated: {association.get('hls_validated', False)}")
        lines.insert(3, f"Security: Suite 0 / {association.get('security', 'not established')}")
    scan_scope = profile.get("scan_scope", {})
    list_scope = scan_scope.get("get_with_list", {})
    timeout_policy = scan_scope.get("timeout_policy", {})
    if timeout_policy:
        lines.append(
            "Timeout policy: {} ms enumeration timeout, breaker after {}, {} trips, "
            "{} successful reconnects, stopped={}".format(
                timeout_policy.get("enumeration_timeout_ms", "unknown"),
                timeout_policy.get("circuit_breaker_threshold", "unknown"),
                timeout_policy.get("trips", 0),
                timeout_policy.get("successful_reconnects", 0),
                timeout_policy.get("stopped", False),
            )
        )
    if list_scope.get("effective_batch_size", 1) > 1:
        lines.append(
            "GET-with-list: up to {} attributes, {} successful batches, {} fallbacks".format(
                list_scope["effective_batch_size"],
                list_scope.get("successful_batches", 0),
                list_scope.get("fallback_batches", 0),
            )
        )
    if scan_scope.get("short_test"):
        lines.insert(
            2,
            f"Scope: short test — {_scan_scope_label(scan_scope)}",
        )
    union_test = report.get("public_union_test", {})
    if union_test.get("enabled"):
        lines.append(
            "Public cross-profile GETs: {} unexpected access, {} rejected, {} inconclusive".format(
                union_test.get("unexpected_public_access", 0),
                union_test.get("public_access_rejected", 0),
                union_test.get("inconclusive", 0),
            )
        )
    return lines
