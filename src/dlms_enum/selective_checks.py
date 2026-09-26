"""A7: bounded normal-versus-selective Profile Generic buffer reads."""
from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .config import AppConfig, PublicProfile, SecureProfile
from .capability_comparison import normalized_capabilities
from .result_model import classify_exception


def parse_range(start: str | None, end: str | None) -> tuple[datetime, datetime] | None:
    if start is None and end is None:
        return None
    if not start or not end:
        raise ValueError("selective range requires both --selective-range-start and --selective-range-end")
    try:
        bounds = tuple(datetime.fromisoformat(value.replace("Z", "+00:00")) for value in (start, end))
    except ValueError as exc:
        raise ValueError("selective range bounds must be ISO-8601 timestamps") from exc
    if any(value.utcoffset() is None for value in bounds):
        raise ValueError("selective range bounds require explicit timezones")
    first, last = (value.astimezone(timezone.utc) for value in bounds)
    if not 0 < (last - first).total_seconds() <= 3600:
        raise ValueError("selective range must be positive and at most one hour")
    return first, last


def validate_options(config: AppConfig, roles: list[str], limit: int) -> None:
    if not 1 <= limit <= 32:
        raise ValueError("selective target limit must be within 1..32")
    if len(set(roles)) != len(roles) or any(role not in {p.role for p in config.profiles} for role in roles):
        raise ValueError("selective-access roles must be distinct selected configured roles")


def candidates(snapshot: dict[str, Any], limit: int) -> list[dict[str, Any]]:
    results = []
    known = {o["logical_name"] for o in snapshot.get("objects", []) if int(o["class_id"]) == 7
             for a in o.get("attributes", []) if a["attribute_id"] == 2 and "read" in a.get("access_rights", {})}
    for (operation, class_id, name, member), cell in sorted(normalized_capabilities(snapshot).items()):
        if operation == "GET" and class_id == 7 and member == 2 and name in known and (not cell["advertised"] or cell["requirements"]):
            results.append({"logical_name": name, "class_id": 7, "object_version": cell["object_version"],
                            "advertised_rights": cell, "status": "NOT_TESTED", "reads": [],
                            "reason": "target_limit" if len(results) >= limit else None})
    return results


def clock_descriptor(captures: Any, sort: Any) -> str | None:
    from .gurux_adapter import _logical_name
    def descriptor(value: Any) -> tuple[int, str, int, int] | None:
        if not isinstance(value, (list, tuple)) or len(value) != 4:
            return None
        try:
            name = _logical_name(value[1])
            return (int(value[0]), name, int(value[2]), int(value[3])) if name else None
        except (ValueError, TypeError):
            return None
    selected = descriptor(sort)
    if selected is None or selected[0] != 8 or selected[2:] != (2, 0):
        return None
    if not isinstance(captures, (list, tuple)) or selected not in [descriptor(value) for value in captures]:
        return None
    return selected[1]


def execute(session: Any, association: dict[str, Any], config: AppConfig, targets: list[dict[str, Any]],
            budget: Any, bounds: tuple[datetime, datetime] | None, identity: dict[str, Any]) -> dict[str, Any]:
    from .cross_role import rejection_detail
    from .scanner import _set_session_timeout
    result: dict[str, Any] = {"status": "completed", "targets": targets, "health": []}
    profile = config.profile
    expected = {"client_address": profile.client_address,
                "authentication": "none" if isinstance(profile, PublicProfile) else "high_gmac" if isinstance(profile, SecureProfile) else "low"}
    if isinstance(profile, SecureProfile):
        expected.update(hls_validated=True, security="authentication_encryption", security_suite=0,
                        client_system_title=profile.client_system_title.hex().upper())
    meter = association.get("invocation_counter_bootstrap", {}).get("meter_identity")
    mismatch = (any(association.get(k) != v for k, v in expected.items())
                or (identity.get("meter_identity") is not None and meter is not None and identity["meter_identity"] != meter)
                or (identity.get("server_address") is not None and association.get("server_address") is not None
                    and identity["server_address"] != association["server_address"]))
    if mismatch:
        for target in targets:
            if not target["reason"]:
                target["reason"] = "association_identity_mismatch"
        return {**result, "status": "inconclusive"}
    _set_session_timeout(session, config.scan.enumeration_timeout_ms)
    stop = None

    def read(target: Any, attribute: int, label: str, events: list, selector: dict | None = None):
        nonlocal stop
        event: dict[str, Any] = {"kind": label, "attribute_id": attribute, "outcome": "NOT_TESTED", "attempt_count": 0}
        events.append(event)
        if stop:
            event["reason"] = stop
            return event, None
        try:
            packets = session.prepare_profile_read(target, attribute, selector)
        except Exception as exc:
            event.update(outcome="ARGUMENT_GENERATION_FAILED", error_type=type(exc).__name__)
            stop = "argument_generation_failed"
            return event, None
        if not budget.take():
            stop = "transmission_limit"
            event["reason"] = stop
            return event, None
        event["attempt_count"] = 1
        try:
            value = session.send_profile_read(packets, target, attribute, selector)
        except Exception as exc:
            event.update(outcome=classify_exception(exc).value, error_type=type(exc).__name__)
            if event["outcome"] == "DLMS_ERROR":
                event.update(rejection_detail(exc))
            else:
                stop = "inconclusive_exchange"
            return event, None
        event["outcome"] = "SUCCESS"
        if attribute == 2:
            if not isinstance(value, (list, tuple)) or any(not isinstance(row, (list, tuple)) for row in value):
                event.update(outcome="PROTOCOL_ERROR", reason="invalid_buffer_shape")
                stop = "inconclusive_exchange"
            else:
                event["row_count"] = len(value)
                event["data_present"] = any(len(row) > 0 for row in value)
        return event, value

    try:
        health = session.create_object(15, "0.0.40.0.0.255")
        event, _ = read(health, 1, "health", result["health"])
        if event["outcome"] != "SUCCESS":
            stop = stop or "health_failed"
    except Exception as exc:
        stop = "health_object_failed"
        result["health"].append({"outcome": "ARGUMENT_GENERATION_FAILED", "error_type": type(exc).__name__})
    for item in targets:
        if item["reason"]:
            continue
        if stop:
            item["reason"] = stop
            continue
        try:
            target = session.create_object(7, item["logical_name"])
            target.version = item["object_version"]
        except Exception as exc:
            item.update(status="INCONCLUSIVE", reason="object_creation_failed", error_type=type(exc).__name__)
            continue
        normal, _ = read(target, 2, "normal", item["reads"])
        if normal["outcome"] == "SUCCESS":
            item.update(status="NORMAL_READ_ALLOWED", reason="normal_read_not_denied")
            continue
        if normal.get("rejection") != "access_denied":
            item.update(status="INCONCLUSIVE", reason="normal_access_denial_not_confirmed")
            continue
        entry, _ = read(target, 2, "entry", item["reads"], {"kind": "entry"})
        if entry.get("row_count", 0) > 1:
            entry["selector_limit_ignored"] = True
        entry["selector"] = {"id": 2, "first_entry": 1, "count": 1}
        if bounds is None:
            item["reads"].append({"kind": "range", "outcome": "NOT_TESTED", "attempt_count": 0, "reason": "range_not_configured"})
        elif not stop:
            capture_event, captures = read(target, 3, "capture_objects", item["reads"])
            sort_event, sort = read(target, 6, "sort_object", item["reads"]) if capture_event["outcome"] == "SUCCESS" else ({}, None)
            clock = clock_descriptor(captures, sort) if sort_event.get("outcome") == "SUCCESS" else None
            if clock:
                selection = {"kind": "range", "clock_logical_name": clock, "start": bounds[0], "end": bounds[1]}
                event, _ = read(target, 2, "range", item["reads"], selection)
                event["selector"] = {"id": 1, "clock_logical_name": clock, "attribute_id": 2, "data_index": 0,
                                     "start": bounds[0].isoformat(), "end": bounds[1].isoformat()}
            else:
                item["reads"].append({"kind": "range", "outcome": "NOT_TESTED", "attempt_count": 0,
                                      "reason": stop or "valid_clock_metadata_unavailable"})
        else:
            item["reads"].append({"kind": "range", "outcome": "NOT_TESTED", "attempt_count": 0, "reason": stop})
        probes = [e for e in item["reads"] if e["kind"] in {"entry", "range"}]
        for event in probes:
            if event["outcome"] == "SUCCESS":
                event["assessment"] = "DATA_AFTER_NORMAL_DENIAL" if event.get("data_present", False) else "EMPTY_RESPONSE"
        item["status"] = ("DATA_AFTER_NORMAL_DENIAL" if any(e.get("assessment") == "DATA_AFTER_NORMAL_DENIAL" for e in probes)
                          else "INCONCLUSIVE" if stop or any(e["outcome"] == "NOT_TESTED" and e.get("reason") != "range_not_configured" for e in probes) else "EMPTY_RESPONSE" if any(e.get("assessment") == "EMPTY_RESPONSE" for e in probes)
                          else "SELECTIVE_READS_REJECTED" if all(e["outcome"] == "DLMS_ERROR" for e in probes if e["outcome"] != "NOT_TESTED")
                          else "INCONCLUSIVE")
    if stop or any(item["status"] == "INCONCLUSIVE" for item in targets):
        result["status"] = "inconclusive"
    return result


def run_selective_checks(config: AppConfig, snapshots: dict, reports: dict, roles: list[str], limit: int,
                         bounds: tuple[datetime, datetime] | None, budget: Any, directory: Path,
                         interrupted: bool = False) -> list[dict[str, Any]]:
    from .scanner import scan
    from .traffic_logger import TrafficLogger
    from .reporter import write_report
    validate_options(config, roles, limit)
    results = []
    profiles = {p.role: p for p in config.profiles}
    for role in roles:
        record = {"rule_id": "A7", "role": role, "status": "NOT_TESTED", "targets": []}
        results.append(record)
        snapshot = snapshots.get(role)
        if interrupted:
            record["reason"] = "interrupted"
            continue
        if not snapshot or role not in reports:
            record["reason"] = "view_unavailable"
            continue
        identity = snapshot.get("identity", {})
        if identity.get("role") != role or identity.get("client_address") != profiles[role].client_address:
            record["reason"] = "role_identity_mismatch"
            continue
        record["targets"] = candidates(snapshot, limit)
        if not record["targets"]:
            record.update(status="completed", reason="no_restricted_buffers")
            continue
        if budget.limit - budget.used < 3:
            record["reason"] = "transmission_limit"
            continue
        transport = reports[role]["transport"]
        profile = replace(profiles[role], server_logical_address=transport["selected_server_logical_address"],
            server_physical_address=transport["selected_server_physical_address"], server_address_size=transport["server_address_size"])
        runtime = replace(config.for_profile(profile), transport=replace(config.transport, baudrate=transport["selected_baudrate"]),
                          scan=replace(config.scan, union_profile_test=False), output=replace(config.output, redact_secrets=True))
        stem = f"selective-access-{len(results)}"
        traffic_path = directory / f"{stem}-traffic.jsonl"
        logger = TrafficLogger(traffic_path, redact_secrets=True)
        try:
            report = scan(runtime, logger, session_task=lambda session, association: execute(
                session, association, runtime, record["targets"], budget, bounds, identity))
        finally:
            logger.close()
        record.update(report=f"{stem}.json", traffic=traffic_path.name)
        write_report(report, directory / record["report"], traffic_path)
        if report["run"]["status"] == "interrupted":
            interrupted = True
            record.update(status="inconclusive", reason="interrupted")
        elif "access_check" in report:
            record.update(report["access_check"])
        else:
            record.update(status="inconclusive", reason="association_failed")
    return results


def render_selective_checks(results: list[dict[str, Any]]) -> str:
    lines = ["## Selective-access checks (A7)", "", "Buffer contents are omitted. Data after denial requires policy review.", ""]
    for record in results:
        lines.append(f"- {record['role']}: {record['status']} ({record.get('reason', 'see targets')})")
        for item in record["targets"]:
            lines.append(f"  - {item['logical_name']}: {item['status']} ({item.get('reason') or 'see reads'})")
            for event in item["reads"]:
                lines.append(f"    - {event['kind']}: {event['outcome']}; {event.get('assessment', event.get('reason', event.get('rejection', '')))}; rows={event.get('row_count', 'unknown')}")
    return "\n".join(lines) + "\n"
