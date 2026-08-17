"""Canonical report writing and human-readable rendering."""

from __future__ import annotations

import hashlib
import json
import math
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
                entries.append(
                    {
                        "sequence_number": record.get("sequence_number", "—"),
                        "direction": direction.upper(),
                        "operation": record.get("operation", "—"),
                        "result": record.get("result", "—"),
                        "object_context": record.get("object_context", {}),
                        "protected_command": decoded.get("protected_command", "—"),
                        "security_control": decoded.get("security_control", "—"),
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
) -> str:
    """Create a compact Markdown view while retaining report.json as evidence."""

    run = report.get("run", {})
    transport = report.get("transport", {})
    profiles = report.get("profiles", [])
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
        "",
    ]

    for profile in profiles:
        association = profile.get("association", {})
        summary = profile.get("summary", {})
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
                f"| Scan scope | {_markdown(_scan_scope_label(scan_scope))} |",
                f"| Association View objects | {_markdown(scan_scope.get('association_view_objects', profile.get('association_view_object_count', '—')))} |",
                f"| GET results | {_markdown(summary.get('get_success', 0))} successful / {_markdown(summary.get('get_failed', 0))} failed / {_markdown(summary.get('get_inconclusive', 0))} inconclusive |",
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
                        "No stale-counter GET was accepted in the five requested probes.",
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
                "One compact row is shown for every mapped GET attribute except logical-name attribute 1, which duplicates the OBIS value already present on the object. Untested rows remain mapped as `NOT_TESTED`. The encrypted-response column contains ciphertext only, excluding HDLC framing, security control, invocation counter, authentication tag, and CRC.",
                "",
                "| OBIS | Class | Attribute | Name | Decoded value | Encoded value (hex) | Encrypted response (hex) | Result |",
                "|---|---:|---:|---|---|---|---|---|",
            ]
        )
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
                decoded = attribute.get("decoded", {})
                value = decoded.get("value") if isinstance(decoded, dict) else None
                raw = decoded.get("raw_value") if isinstance(decoded, dict) else None
                result = attribute.get("outcome") or attribute.get("lifecycle") or "not scanned"
                encrypted = encrypted_rx.get(
                    (
                        int(obj.get("class_id", 0)),
                        str(obj.get("logical_name", "")),
                        int(attribute.get("attribute_id", 0)),
                    ),
                    [],
                )
                lines.append(
                    "| {} | {} | {} | {} | {} | {} | {} | {} |".format(
                        _markdown(obj.get("logical_name", "—")),
                        _markdown(obj.get("class_id", "—")),
                        _markdown(attribute.get("attribute_id", "—")),
                        _markdown(attribute.get("name") or "—"),
                        _markdown(_compact_value(value)),
                        _markdown(_hex_value(raw)),
                        _markdown("<br>".join(encrypted) if encrypted else "—"),
                        _markdown(result),
                    )
                )
        lines.append("")

        lines.extend(
            [
                "### Operation capability matrix",
                "",
                "Every mapped operation is listed. GET contains its actual result when tested; operations outside a short-test budget are `NOT_TESTED`. SET and ACTION are mapped passively from this role's Association View and are never sent, so they remain `NOT_TESTED`. This scan uses logical-name referencing, where writes use SET; WRITE is the short-name equivalent.",
                "",
                "| Operation | OBIS | Class | Member | Name | Access mode | Status |",
                "|---|---|---:|---:|---|---|---|",
            ]
        )
        for obj in profile.get("objects", []):
            for attribute in obj.get("attributes", []):
                if attribute.get("attribute_id") == 1:
                    continue
                rights = attribute.get("access_rights", {})
                if rights.get("read", True) or rights.get("catalogue_probe", False):
                    lines.append(
                        "| GET | {} | {} | {} | {} | {} | {} |".format(
                            _markdown(obj.get("logical_name", "—")),
                            _markdown(obj.get("class_id", "—")),
                            _markdown(attribute.get("attribute_id", "—")),
                            _markdown(attribute.get("name") or "—"),
                            _markdown(attribute.get("advertised_access", "—")),
                            _markdown(attribute.get("outcome") or Outcome.NOT_TESTED.value),
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
                    "| OBIS | Class | Attribute | Name | Public view | Result | Assessment | Decoded value |",
                    "|---|---:|---:|---|---|---|---|---|",
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
                    "| {} | {} | {} | {} | {} | {} | {} | {} |".format(
                        _markdown(result.get("logical_name", "—")),
                        _markdown(result.get("class_id", "—")),
                        _markdown(result.get("attribute_id", "—")),
                        _markdown(result.get("name") or "—"),
                        _markdown(public_view),
                        _markdown(result.get("outcome", "—")),
                        _markdown(result.get("access_assessment", "—")),
                        _markdown(_compact_value(value)),
                    )
                )
            lines.append("")

    if protected_traffic:
        lines.extend(
            [
                "## Protected APDU evidence",
                "",
                "Security-control `0x30` denotes Suite 0 authentication and encryption. Ciphertext below excludes the security-control byte, invocation counter, and 12-byte AES-GCM authentication tag. A complete successfully decoded response also means its authentication tag was verified; `fragment` means only the ciphertext bytes present in that HDLC segment are shown.",
                "",
                "| Seq. | Direction | Operation | Protected command | Security control | Invocation counter | Ciphertext (hex) | Capture | AES-GCM tag (hex) | Result |",
                "|---:|---|---|---|---|---:|---|---|---|---|",
            ]
        )
        for entry in protected_traffic:
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
            lines.append(
                "| {} | {} | {} | {} | {} | {} | {} | {} | {} | {} |".format(
                    _markdown(entry.get("sequence_number", "—")),
                    _markdown(entry.get("direction", "—")),
                    _markdown(entry.get("operation", "—")),
                    _markdown(entry.get("protected_command", "—")),
                    _markdown(entry.get("security_control", "—")),
                    _markdown(entry.get("invocation_counter", "—")),
                    _markdown(entry.get("ciphertext_hex") or "—"),
                    _markdown(capture),
                    _markdown(tag),
                    _markdown(entry.get("result", "—")),
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


def write_summary_report(
    report: dict[str, Any],
    path: str | Path,
    traffic_path: str | Path | None = None,
) -> None:
    protected_traffic = (
        _protected_traffic_entries(traffic_path) if traffic_path is not None else None
    )
    _atomic_write_text(path, render_summary_report(report, protected_traffic))


def write_report(
    report: dict[str, Any],
    path: str | Path,
    traffic_path: str | Path,
    summary_path: str | Path | None = None,
) -> None:
    if summary_path is not None:
        write_summary_report(report, summary_path, traffic_path)
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
    lines = [
        f"Run: {run.get('id', 'unknown')} ({run.get('status', 'unknown')})",
        f"Profile: {profile.get('name', 'not established')}",
        f"Baud rate: {report.get('transport', {}).get('selected_baudrate', 'not found')}",
        f"HDLC server address: {report.get('transport', {}).get('selected_server_address', 'not found')}",
        f"Server Addressing Type: {report.get('transport', {}).get('server_addressing_type', 'not found')}",
        f"Objects: {summary.get('objects', 0)}",
        f"GET: {summary.get('get_success', 0)} success, {summary.get('get_failed', 0)} failed, {summary.get('get_inconclusive', 0)} inconclusive",
        f"GET not tested: {summary.get('get_not_tested', 0)}",
        f"Advertised SET attributes: {summary.get('advertised_set_attributes', 0)} (not tested)",
        f"Advertised ACTION methods: {summary.get('advertised_action_methods', 0)} (not tested)",
        f"Errors: {len(report.get('errors', []))}",
    ]
    association = profile.get("association", {})
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
