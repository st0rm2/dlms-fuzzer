"""Explicit, bounded, directed GET checks between configured roles."""
from __future__ import annotations

from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any

from .access_policy import assess_capability
from .association_checks import hidden_requests, association_snapshot, control_findings
from .capability_comparison import compatible_identities, normalized_capabilities
from .config import AppConfig, PublicProfile, SecureProfile
from .result_model import Outcome, classify_exception


@dataclass
class GetBudget:
    limit: int
    used: int = 0

    def take(self) -> bool:
        if self.used >= self.limit:
            return False
        self.used += 1
        return True


def parse_pairs(values: list[str], roles: set[str]) -> list[tuple[str, str]]:
    pairs = []
    for value in values:
        parts = value.split(":")
        if len(parts) != 2 or parts[0] == parts[1] or any(p not in roles for p in parts):
            raise ValueError("each --pair must be SOURCE:PROBE with two distinct selected roles")
        pair = (parts[0], parts[1])
        if pair in pairs:
            raise ValueError("duplicate --pair")
        pairs.append(pair)
    return sorted(pairs)


def plan_checks(config: AppConfig, snapshots: dict[str, dict[str, Any]],
                pairs: list[tuple[str, str]], pair_limit: int) -> dict[str, Any]:
    if pair_limit < 1:
        raise ValueError("pair limit must be positive")
    profiles = {profile.role: profile for profile in config.profiles}
    models = {role: normalized_capabilities(snapshot) for role, snapshot in snapshots.items()}
    merged: dict[tuple[Any, ...], dict[str, Any]] = {}
    pair_records = []
    for source, probe in sorted(pairs):
        if source not in profiles or probe not in profiles or source == probe:
            raise ValueError("invalid role pair")
        pair = {"source_role": source, "probe_role": probe, "status": "planned", "candidates": []}
        pair_records.append(pair)
        if source not in models or probe not in models:
            pair.update(status="NOT_TESTED", reason="view_unavailable")
            continue
        if any(snapshots[role].get("identity", {}).get("role") != role
               or snapshots[role].get("identity", {}).get("client_address") != profiles[role].client_address
               for role in (source, probe)):
            pair.update(status="NOT_TESTED", reason="role_identity_mismatch")
            continue
        if not compatible_identities(snapshots[source].get("identity", {}), snapshots[probe].get("identity", {})):
            pair.update(status="NOT_TESTED", reason="identity_mismatch")
            continue
        selected = 0
        for key, cell in sorted(models[source].items()):
            operation, class_id, logical_name, member_id = key
            if operation != "GET" or member_id == 1 or not cell["advertised"]:
                continue
            destination = models[probe].get(key)
            policy = assess_capability(config.access_policy, probe, isinstance(profiles[probe], PublicProfile),
                                       class_id, logical_name, operation, member_id)
            forbidden = policy is not None and policy["assessment"] == "policy_exposure"
            if destination and destination["advertised"] and not destination["requirements"] and not forbidden:
                continue
            candidate = {"class_id": class_id, "logical_name": logical_name, "attribute_id": member_id,
                "object_version": cell["object_version"], "probe_role": probe, "source_role": source,
                "source_advertised": True, "probe_rights": destination, "policy": policy,
                "outcome": "NOT_TESTED", "attempt_count": 0, "attempts": []}
            reason = None
            if destination and destination["object_version"] != cell["object_version"]:
                reason = "version_mismatch"
            elif selected >= pair_limit:
                reason = "pair_limit"
            if reason:
                candidate["reason"] = reason
            else:
                selected += 1
                request_key = (probe, class_id, logical_name, member_id)
                previous = merged.get(request_key)
                if previous is not None and previous["object_version"] != cell["object_version"]:
                    candidate["reason"] = "version_mismatch"
                    previous["reason"] = "version_mismatch"
                    previous["selected"] = False
                elif previous is not None:
                    previous["source_roles"].append(source)
                else:
                    merged[request_key] = {**candidate, "source_roles": [source], "selected": True}
            pair["candidates"].append(candidate)
        pair["candidate_gets"] = len(pair["candidates"])
        pair["selected_gets"] = selected
    return {"schema_version": 1, "type": "cross_role_get_plan", "pairs": pair_records,
            "requests": [merged[key] for key in sorted(merged)]}


def rejection_detail(exc: Exception) -> dict[str, Any]:
    """Use protocol error codes, never infer an access denial from an exception string."""
    raw = getattr(exc, "errorCode", None)
    try:
        code = int(raw) if raw is not None else None
    except (ValueError, TypeError):
        code = None
    return {"dlms_error_code": code, "rejection": "access_denied" if code == 3
            else "object_unavailable" if code in {4, 9, 11} else "other_dlms_error"}


def execute_destination(session: Any, association: dict[str, Any], *, config: AppConfig,
                        requests: list[dict[str, Any]], baseline: dict[str, Any], budget: GetBudget) -> dict[str, Any]:
    """A baseline GET and at most one reconnect; all service GET attempts share a budget."""
    from .scanner import _GetRetryPolicy, _set_session_timeout

    _set_session_timeout(session, config.scan.enumeration_timeout_ms)
    result = {"role": config.profile.role, "client_address": config.profile.client_address,
              "baseline": [], "recovery": [], "results": requests, "status": "completed"}
    expected_auth = "none" if isinstance(config.profile, PublicProfile) else "low" if config.profile.name == "lls" else "high_gmac"
    def valid_association(details: dict[str, Any]) -> bool:
        return (details.get("authentication") == expected_auth
                and details.get("client_address") == config.profile.client_address
                and (not isinstance(config.profile, SecureProfile)
                     or (details.get("hls_validated") is True
                         and details.get("security") == "authentication_encryption")))

    if not valid_association(association):
        for request in requests:
            request["reason"] = "association_identity_mismatch"
        result["status"] = "inconclusive"
        return result
    retry = _GetRetryPolicy()
    consecutive = 0
    recovered_once = False
    stop = None

    def health(stage: str) -> bool:
        try:
            target = session.create_object(baseline["class_id"], baseline["logical_name"])
        except Exception as exc:
            result["baseline"].append({"stage": stage, "outcome": "ARGUMENT_GENERATION_FAILED", "error_type": type(exc).__name__})
            return False
        if not budget.take():
            result["baseline"].append({"stage": stage, "outcome": "NOT_TESTED", "reason": "transmission_limit"})
            return False
        event = {"stage": stage, **baseline}
        result["baseline"].append(event)
        try:
            session.read_attribute(target, baseline["attribute_id"], 1,
                                   phase="access_check_health", purpose="cross_role_baseline")
        except Exception as exc:
            event.update(outcome=classify_exception(exc).value, error_type=type(exc).__name__)
            return False
        event["outcome"] = "SUCCESS"
        return True

    if not health("before_probes"):
        stop = "baseline_failed_or_budget_exhausted"
    for request in requests:
        if not request.get("selected", True):
            continue
        if stop:
            request["reason"] = stop
            continue
        if request.get("kind") == "hidden_association" and request["attribute_id"] == 2:
            presence = next(r for r in requests if r.get("kind") == "hidden_association"
                            and r["logical_name"] == request["logical_name"] and r["attribute_id"] == 1)
            if presence["outcome"] != "SUCCESS":
                request["reason"] = "presence_not_confirmed"
                continue
        try:
            target = session.create_object(request["class_id"], request["logical_name"])
            target.version = request["object_version"]
        except Exception as exc:
            request.update(outcome="ARGUMENT_GENERATION_FAILED", assessment="INCONCLUSIVE",
                           reason="object_creation_failed", error_type=type(exc).__name__)
            continue
        for attempt in range(1, min(config.scan.total_get_attempts, retry.attempts_for_next_get(config.scan.total_get_attempts)) + 1):
            if not budget.take():
                stop = "transmission_limit"
                request["reason"] = stop
                break
            request["attempt_count"] += 1
            try:
                if request.get("kind") == "hidden_association" and request["attribute_id"] == 2:
                    objects = list(session.read_association_objects(request["logical_name"], attempt))
                    request["discovered_view"] = association_snapshot(objects, request["logical_name"],
                        {"role": config.profile.role, "client_address": config.profile.client_address})
                else:
                    session.read_attribute(target, request["attribute_id"], attempt,
                                           phase="access_check", purpose="hidden_association_presence"
                                           if request.get("kind") == "hidden_association" else "cross_role_verification")
            except Exception as exc:
                outcome = classify_exception(exc)
                event = {"attempt": attempt, "outcome": outcome.value, "error_type": type(exc).__name__}
                if outcome == Outcome.DLMS_ERROR:
                    event.update(rejection_detail(exc))
                    request.update(rejection_detail(exc))
                request["attempts"].append(event)
                request["outcome"] = outcome.value
                request["assessment"] = "REJECTED" if outcome == Outcome.DLMS_ERROR else "INCONCLUSIVE"
                retry.record(outcome)
                consecutive = consecutive + 1 if outcome == Outcome.TIMEOUT else 0
                if outcome == Outcome.DLMS_ERROR or consecutive >= config.scan.timeout_breaker_threshold:
                    break
            else:
                request["attempts"].append({"attempt": attempt, "outcome": "SUCCESS"})
                request["outcome"] = "SUCCESS"
                request["assessment"] = ("VERIFIED_POLICY_VIOLATION" if
                    (request.get("policy") or {}).get("assessment") == "policy_exposure" else "VERIFIED_ACCESS")
                if request.get("kind") == "hidden_association":
                    request["assessment"] = ("HIDDEN_ASSOCIATION_PRESENT" if request["attribute_id"] == 1
                                             else "HIDDEN_ASSOCIATION_LIST_READABLE")
                consecutive = 0
                retry.record(Outcome.SUCCESS)
                break
        if consecutive >= config.scan.timeout_breaker_threshold:
            if recovered_once:
                stop = "timeout_circuit_open"
            elif health("circuit_health"):
                consecutive = 0
                retry.reset()
                recovered_once = True
            elif budget.used < budget.limit:
                recovered_once = True
                try:
                    new_association = session.reconnect()
                    if not valid_association(new_association):
                        raise ValueError("recovery association identity mismatch")
                    result["recovery"].append({"outcome": "connected"})
                except Exception as exc:
                    result["recovery"].append({"outcome": "failed", "error_type": type(exc).__name__})
                    stop = "reconnect_failed"
                else:
                    if health("after_reconnect"):
                        consecutive = 0
                        retry.reset()
                    else:
                        stop = "recovery_health_failed"
            else:
                stop = "transmission_limit"
    if stop or any(r.get("assessment") == "INCONCLUSIVE" for r in requests):
        result["status"] = "inconclusive"
    return result


def run_checks(config: AppConfig, snapshots: dict[str, dict[str, Any]],
               role_reports: dict[str, dict[str, Any]], pairs: list[tuple[str, str]],
               *, pair_limit: int, transmission_limit: int, directory: Path,
               authorization: dict[str, Any], hidden_roles: list[str] | None = None, control_roles: list[str] | None = None,
               instances: range = range(1, 17)) -> dict[str, Any]:
    from .scanner import scan
    from .traffic_logger import TrafficLogger
    from .reporter import write_report

    if transmission_limit < 1:
        raise ValueError("transmission limit must be positive")
    plan = plan_checks(config, snapshots, pairs, pair_limit)
    if not isinstance(instances, range) or instances.step != 1 or not instances or instances.start < 0 or instances.stop > 256:
        raise ValueError("association instance range must be inclusive within 0..255")
    plan["association_instances"] = {"first": instances.start, "last": instances.stop - 1}
    plan["hidden_roles"] = []
    profiles_by_role = {p.role: p for p in config.profiles}
    for role in sorted(set(hidden_roles or [])):
        if role not in profiles_by_role:
            raise ValueError("unknown hidden-association role")
        snapshot = snapshots.get(role)
        identity = (snapshot or {}).get("identity", {})
        reason = ("view_unavailable" if not snapshot or not snapshot.get("objects") else
                  "role_identity_mismatch" if identity.get("role") != role or
                  identity.get("client_address") != profiles_by_role[role].client_address else None)
        plan["hidden_roles"].append({"role": role, "status": "NOT_TESTED" if reason else "planned", "reason": reason})
        if reason is None:
            plan["requests"].extend(hidden_requests(role, snapshot, instances))
    plan["control_roles"] = []
    for role in sorted(set(control_roles or [])):
        if role not in profiles_by_role:
            raise ValueError("unknown control-instance role")
        snapshot = snapshots.get(role)
        identity = (snapshot or {}).get("identity", {})
        reason = ("view_unavailable" if not snapshot or not snapshot.get("objects") else
                  "role_identity_mismatch" if identity.get("role") != role or
                  identity.get("client_address") != profiles_by_role[role].client_address else None)
        plan["control_roles"].append({"role": role, "status": "NOT_TESTED" if reason else "planned", "reason": reason})
        if reason:
            continue
        names = {finding[key] for finding in control_findings(snapshot, role)
                 if any(d["classification"] == "inconsistent_rights" for d in finding["differences"])
                 for key in ("left_logical_name", "right_logical_name")}
        for obj in snapshot["objects"]:
            if obj["class_id"] != 70 or obj["logical_name"] not in names:
                continue
            existing = next((r for r in plan["requests"] if r["probe_role"] == role and
                             r["class_id"] == 70 and r["logical_name"] == obj["logical_name"] and r["attribute_id"] == 2), None)
            if existing is not None:
                existing["control_instance_check"] = True
                continue
            plan["requests"].append({"class_id": 70, "logical_name": obj["logical_name"],
                "object_version": obj.get("object_version", 0), "attribute_id": 2, "probe_role": role,
                "source_roles": [], "selected": True, "kind": "control_instance", "control_instance_check": True,
                "policy": assess_capability(config.access_policy, role, isinstance(profiles_by_role[role], PublicProfile),
                                            70, obj["logical_name"], "GET", 2),
                "outcome": "NOT_TESTED", "attempt_count": 0, "attempts": []})
    budget = GetBudget(transmission_limit)
    for request in plan["requests"]:
        source_evidence = []
        for role in request["source_roles"]:
            observation = next((attribute for profile in role_reports.get(role, {}).get("profiles", [])
                for obj in profile.get("objects", []) if (obj["class_id"], obj["logical_name"]) == (request["class_id"], request["logical_name"])
                for attribute in obj.get("attributes", []) if attribute["attribute_id"] == request["attribute_id"]), {})
            source_evidence.append({"role": role, "outcome": observation.get("outcome", "NOT_TESTED"),
                                    "attempt_count": observation.get("attempt_count", 0)})
        request["source_get_evidence"] = source_evidence
    destinations = []
    profiles = {p.role: p for p in config.profiles}
    for index, role in enumerate(sorted({r["probe_role"] for r in plan["requests"]}), 1):
        requests = [r for r in plan["requests"] if r["probe_role"] == role]
        for request in requests:
            request["probe_client_address"] = profiles[role].client_address
        if not any(r.get("selected") for r in requests):
            continue
        if budget.used >= budget.limit:
            for request in requests:
                request["reason"] = "transmission_limit"
            continue
        previous = role_reports[role]
        transport = previous["transport"]
        profile = replace(profiles[role], server_logical_address=transport["selected_server_logical_address"],
            server_physical_address=transport["selected_server_physical_address"], server_address_size=transport["server_address_size"])
        runtime = replace(config.for_profile(profile),
            transport=replace(config.transport, baudrate=transport["selected_baudrate"]),
            scan=replace(config.scan, union_profile_test=False), output=replace(config.output, redact_secrets=True))
        # Logical-name attribute 1 is harmless and requires no value retention.
        obj = sorted(snapshots[role]["objects"], key=lambda o: (o["class_id"], o["logical_name"]))[0]
        baseline = {"class_id": obj["class_id"], "logical_name": obj["logical_name"], "attribute_id": 1}
        traffic_path = directory / f"access-check-{index}-traffic.jsonl"
        logger = TrafficLogger(traffic_path, redact_secrets=True)
        try:
            report = scan(runtime, logger, session_task=lambda session, association: execute_destination(
                session, association, config=runtime, requests=requests, baseline=baseline, budget=budget))
        finally:
            logger.close()
        # Values are deliberately absent from access-check results; traffic retains
        # the existing redaction rules and protected-session evidence.
        if "access_check" not in report:
            for request in requests:
                request["reason"] = "destination_association_failed"
        for request in requests:
            request["traffic_file"] = traffic_path.name
        write_report(report, directory / f"access-check-{index}.json", traffic_path)
        destinations.append({"role": role, "status": report["run"]["status"],
            "report": f"access-check-{index}.json", "traffic": traffic_path.name,
            "check": report.get("access_check"), "errors": report.get("errors", [])})
        if report["run"]["status"] == "interrupted":
            for pending in plan["requests"]:
                if pending["outcome"] == "NOT_TESTED" and not pending.get("reason"):
                    pending["reason"] = "interrupted"
            break
    indexed = {(r["probe_role"], r["class_id"], r["logical_name"], r["attribute_id"]): r for r in plan["requests"] if r.get("kind") != "hidden_association"}
    for pair in plan["pairs"]:
        for candidate in pair["candidates"]:
            if candidate.get("reason"):
                continue
            request = indexed.get((candidate["probe_role"], candidate["class_id"], candidate["logical_name"], candidate["attribute_id"]))
            if request:
                candidate.update({k: v for k, v in request.items() if k not in {"source_role", "source_roles"}})
        if pair["status"] != "NOT_TESTED":
            pair["status"] = ("inconclusive" if any(c.get("assessment") == "INCONCLUSIVE" for c in pair["candidates"])
                              else "partial" if any(c["outcome"] == "NOT_TESTED" for c in pair["candidates"])
                              else "completed")
        pair["summary"] = {state: sum(c["outcome"] == state for c in pair["candidates"])
                           for state in ("SUCCESS", "DLMS_ERROR", "TIMEOUT", "PROTOCOL_ERROR", "TRANSPORT_ERROR", "ARGUMENT_GENERATION_FAILED", "NOT_TESTED")}
    from .capability_comparison import build_role_matrix
    hidden_views = []
    for request in plan["requests"]:
        view = request.get("discovered_view")
        if view is not None:
            role = request["probe_role"]
            view["identity"] = dict(snapshots[role]["identity"])
            label = f"{role}@{request['logical_name']}"
            hidden_views.append({"probe_role": role, "source_association": request["logical_name"],
                "rights_scope": "source association advertisement; not verified current-role permissions",
                "comparison": build_role_matrix({role: snapshots[role], label: view}, [role, label])})
    for group, field in ((plan["hidden_roles"], "hidden_association"), (plan["control_roles"], "control_instance")):
        for entry in group:
            if entry["status"] == "planned":
                results = [r for r in plan["requests"] if r["probe_role"] == entry["role"] and
                           (r.get("kind") == field or (field == "control_instance" and r.get("control_instance_check")))]
                entry["status"] = ("inconclusive" if any(r.get("assessment") == "INCONCLUSIVE" for r in results)
                                   else "partial" if any(r["outcome"] == "NOT_TESTED" for r in results) else "completed")
    return {**plan, "hidden_view_comparisons": hidden_views, "type": "cross_role_get_report", "authorization": authorization,
            "policy": config.access_policy.as_dict(), "destinations": destinations,
            "budget": {"pair_target_limit": pair_limit, "get_attempt_limit": budget.limit, "get_attempts": budget.used,
                       "includes": "probe, baseline and recovery GET service attempts; block continuations are not separate attempts",
                       "excludes": "inventory, public identity/counter bootstrap, association/HLS and teardown traffic; recorded in traffic files"}}


def render_checks(report: dict[str, Any]) -> str:
    lines = ["# Cross-role GET verification", "", "GET outcomes and policy assessments are separate. SET and application ACTION were not tested.", "",
             f"Active GET service attempts: {report['budget']['get_attempts']}/{report['budget']['get_attempt_limit']}", "",
             "| Source | Probe role | Target | Outcome | Assessment / reason | Attempts |", "|---|---|---|---|---|---:|"]
    for pair in report["pairs"]:
        if not pair["candidates"]:
            lines.append(f"| {pair['source_role']} | {pair['probe_role']} | — | {pair['status']} | {pair.get('reason', 'no candidates')} | 0 |")
        for item in pair["candidates"]:
            cells = (pair["source_role"], pair["probe_role"], f"{item['class_id']} / {item['logical_name']} / {item['attribute_id']}",
                     item["outcome"], item.get("assessment") or item.get("reason", "not tested"), item["attempt_count"])
            lines.append("| " + " | ".join(str(c).replace("|", "\\|").replace("\n", " ") for c in cells) + " |")
    lines += ["", "## Hidden associations", "", "Presence alone is not a vulnerability. Hidden-list rights describe the source association.", ""]
    for entry in report.get("hidden_roles", []):
        lines.append(f"- {entry['role']}: {entry['status']} ({entry.get('reason') or 'see probes below'})")
    for item in report["requests"]:
        if item.get("kind") == "hidden_association":
            lines.append(f"- {item['probe_role']} / {item['logical_name']} / attribute {item['attribute_id']}: "
                         f"{item['outcome']} — {item.get('assessment') or item.get('reason', 'not tested')}")
    lines += ["", "## Control-instance GET verification", "", "Only output-state GETs are verified; SET/ACTION rights remain passive evidence.", ""]
    for entry in report.get("control_roles", []):
        lines.append(f"- {entry['role']}: {entry['status']} ({entry.get('reason') or 'see probes below'})")
    for item in report["requests"]:
        if item.get("control_instance_check"):
            lines.append(f"- {item['probe_role']} / {item['logical_name']} / attribute 2: "
                         f"{item['outcome']} — {item.get('assessment') or item.get('reason', 'not tested')}")
    from .capability_comparison import render_role_matrix
    for view in report.get("hidden_view_comparisons", []):
        lines.extend(["", f"### {view['probe_role']} / {view['source_association']}",
                      render_role_matrix(view["comparison"])])
    return "\n".join(lines) + "\n"
