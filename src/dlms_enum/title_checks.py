"""Bounded A6 comparisons with one independently protected session per title."""
from __future__ import annotations

from dataclasses import replace
from pathlib import Path
from typing import Any

from .association_checks import association_snapshot
from .association_view import compare_snapshots
from .capability_comparison import build_role_matrix
from .config import AppConfig, SecureProfile
from .result_model import classify_exception


def parse_titles(values: list[str], config: AppConfig, limit: int) -> dict[str, list[bytes]]:
    if not 1 <= limit <= 32:
        raise ValueError("title variant limit must be within 1..32")
    if len(values) > limit:
        raise ValueError("system-title variants exceed --title-limit")
    profiles = {p.role: p for p in config.profiles}
    result: dict[str, list[bytes]] = {}
    for value in values:
        role, separator, encoded = value.partition(":")
        profile = profiles.get(role)
        if not separator or not isinstance(profile, SecureProfile):
            raise ValueError("--system-title requires a selected HLS-GMAC role and ROLE:HEX")
        if len(encoded) != 16 or any(c not in "0123456789abcdefABCDEF" for c in encoded):
            raise ValueError("system title must contain exactly 16 hexadecimal digits")
        title = bytes.fromhex(encoded)
        if title == profile.client_system_title or title in result.get(role, []):
            raise ValueError("system-title variants must be distinct from each other and the configured title")
        if profile.invocation_counter.unsafe_override is not None:
            raise ValueError("system-title checks require public counter bootstrap without unsafe_override")
        result.setdefault(role, []).append(title)
    return result


def read_view(session: Any, association: dict[str, Any], config: AppConfig, budget: Any,
              expected_server_title: str | None = None, expected_identity: dict[str, Any] | None = None) -> dict[str, Any]:
    from .scanner import _set_session_timeout
    from .cross_role import rejection_detail

    result: dict[str, Any] = {"status": "INCONCLUSIVE", "association": association, "attempts": []}
    expected = {"authentication": "high_gmac", "client_address": config.profile.client_address,
                "client_system_title": config.profile.client_system_title.hex().upper(),
                "hls_validated": True, "security": "authentication_encryption", "security_suite": 0}
    if any(association.get(key) != value for key, value in expected.items()):
        return {**result, "reason": "association_properties_mismatch"}
    if expected_server_title is not None and association.get("server_system_title") != expected_server_title:
        return {**result, "reason": "server_identity_mismatch"}
    identity = expected_identity or {}
    observed_meter = association.get("invocation_counter_bootstrap", {}).get("meter_identity")
    if (identity.get("meter_identity") is not None and observed_meter is not None
            and identity["meter_identity"] != observed_meter):
        return {**result, "reason": "meter_identity_mismatch"}
    if (identity.get("server_address") is not None and association.get("server_address") is not None
            and identity["server_address"] != association["server_address"]):
        return {**result, "reason": "server_endpoint_mismatch"}
    try:
        target = session.create_object(15, "0.0.40.0.0.255")
    except Exception as exc:
        return {**result, "reason": "object_creation_failed", "error_type": type(exc).__name__}
    _set_session_timeout(session, config.scan.enumeration_timeout_ms)
    for stage, attribute in (("baseline_get", 1), ("association_view", 2)):
        for attempt in range(1, config.scan.total_get_attempts + 1):
            if not budget.take():
                return {**result, "reason": "transmission_limit"}
            event = {"stage": stage, "attempt": attempt}
            result["attempts"].append(event)
            try:
                if attribute == 1:
                    session.read_attribute(target, 1, attempt,
                                           phase="system_title_check", purpose="title_baseline")
                else:
                    raw = session.read_association_objects("0.0.40.0.0.255", attempt)
                    view = association_snapshot(raw, "0.0.40.0.0.255", {})
                    view["source"] = "system_title_association_view"
                    for obj in view["objects"]:
                        obj["discovery_sources"] = ["system_title_association_view"]
                    result["view"] = view
            except Exception as exc:
                event.update(outcome=classify_exception(exc).value, error_type=type(exc).__name__)
                if event["outcome"] == "DLMS_ERROR":
                    event.update(rejection_detail(exc))
                    return {**result, "reason": f"{stage}_rejected"}
                # No reconnect or weaker association fallback in a title experiment.
                if event["outcome"] != "TIMEOUT" or attempt >= min(config.scan.total_get_attempts, config.scan.timeout_breaker_threshold):
                    return {**result, "reason": f"{stage}_failed"}
            else:
                event["outcome"] = "SUCCESS"
                break
    if not result["view"]["rights_encoding_known"]:
        return {**result, "reason": "rights_encoding_unknown"}
    result["status"] = "VIEW_READ"
    return result


def run_title_checks(config: AppConfig, snapshots: dict[str, dict[str, Any]], reports: dict[str, dict[str, Any]],
                     titles: dict[str, list[bytes]], budget: Any, directory: Path) -> list[dict[str, Any]]:
    from .scanner import scan
    from .traffic_logger import TrafficLogger
    from .reporter import write_report

    results = []
    profiles = {p.role: p for p in config.profiles}
    interrupted = False
    for role, variants in titles.items():
        profile = profiles[role]
        record: dict[str, Any] = {"rule_id": "A6", "role": role, "client_address": profile.client_address,
                                  "baseline": None, "variants": []}
        results.append(record)
        snapshot = snapshots.get(role)
        identity = (snapshot or {}).get("identity", {})
        baseline = None
        for index, title in enumerate([profile.client_system_title, *variants]):
            entry: dict[str, Any] = {"client_system_title": title.hex().upper(), "status": "NOT_TESTED"}
            if index == 0:
                record["baseline"] = entry
            else:
                record["variants"].append(entry)
            if interrupted:
                entry["reason"] = "interrupted"
                continue
            if not snapshot or role not in reports:
                entry["reason"] = "view_unavailable"
                continue
            if identity.get("role") != role or identity.get("client_address") != profile.client_address:
                entry["reason"] = "role_identity_mismatch"
                continue
            if index and (baseline is None or baseline["status"] != "VIEW_READ"):
                entry["reason"] = "baseline_failed"
                continue
            if budget.limit - budget.used < 2:
                entry["reason"] = "transmission_limit"
                continue
            transport = reports[role]["transport"]
            variant_profile = replace(profile, client_system_title=title,
                server_logical_address=transport["selected_server_logical_address"],
                server_physical_address=transport["selected_server_physical_address"],
                server_address_size=transport["server_address_size"])
            runtime = replace(config.for_profile(variant_profile),
                transport=replace(config.transport, baudrate=transport["selected_baudrate"]),
                scan=replace(config.scan, union_profile_test=False), output=replace(config.output, redact_secrets=True))
            stem = f"system-title-{len(results)}-{index}"
            traffic_path = directory / f"{stem}-traffic.jsonl"
            logger = TrafficLogger(traffic_path, redact_secrets=True)
            expected_server = baseline["association"].get("server_system_title") if index else None
            try:
                report = scan(runtime, logger, session_task=lambda session, association: read_view(
                    session, association, runtime, budget, expected_server, identity))
            finally:
                logger.close()
            entry.update(report=f"{stem}.json", traffic=traffic_path.name, run_status=report["run"]["status"])
            write_report(report, directory / entry["report"], traffic_path)
            if report["run"]["status"] == "interrupted":
                interrupted = True
                entry.update(status="INCONCLUSIVE", reason="interrupted")
                continue
            check = report.get("access_check")
            if check is None:
                rejection = report.get("secure_association_failure", {})
                entry.update(status="ASSOCIATION_REJECTED" if rejection.get("association_result") in (1, 2) else "INCONCLUSIVE",
                             reason="secure_association_failed", association_failure=rejection)
                continue
            entry.update(check)
            if not index:
                baseline = entry
            elif entry["status"] == "VIEW_READ":
                left, right = baseline["view"], entry["view"]
                left["identity"] = {**identity, "client_system_title": profile.client_system_title.hex().upper()}
                right["identity"] = {**identity, "client_system_title": title.hex().upper()}
                delta = compare_snapshots(left, right)
                entry.update(status="VIEW_UNCHANGED" if delta["matches"] else "VIEW_CHANGED",
                             changes=delta, comparison=build_role_matrix(
                                 {"configured_title": left, "variant_title": right}, ["configured_title", "variant_title"]),
                             assessment="review_required" if not delta["matches"] else "no_difference_observed")
    return results


def render_title_checks(results: list[dict[str, Any]]) -> str:
    from .capability_comparison import render_role_matrix
    lines = ["## System-title view checks (A6)", "",
             "Same SAP, credentials and protection; only the client title changes. Changed views require review, not automatic vulnerability classification.", ""]
    for record in results:
        lines.append(f"### {record['role']} (SAP {record['client_address']})")
        lines.append("")
        for label, entry in [("Configured title", record["baseline"]), *[("Variant", v) for v in record["variants"]]]:
            lines.append(f"- {label} `{entry['client_system_title']}`: {entry['status']} ({entry.get('reason', entry.get('assessment', 'baseline'))})")
            if "comparison" in entry:
                lines.extend(["", render_role_matrix(entry["comparison"])])
    return "\n".join(lines) + "\n"
