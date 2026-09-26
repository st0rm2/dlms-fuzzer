"""Versioned, member-level exposure policy; never transmits meter operations."""
from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any

BASELINE = "public-minimal-v1"
# Exact GET targets: discovery metadata, nameplate and clock time. Other rights
# remain reviewable; class membership alone never grants blanket public access.
PUBLIC_READS = {
    (1, "0.0.42.0.0.255", 2),
    (1, "0.0.96.1.0.255", 2),
    (1, "0.0.96.1.1.255", 2),
    (1, "1.0.0.2.0.255", 2),
    (8, "0.0.1.0.0.255", 2),
}
CONTROL_CLASSES = {70: "disconnect", 64: "security", 9: "scripts", 8: "clock", 20: "calendar", 22: "schedule", 18: "firmware"}


@dataclass(frozen=True)
class PolicyException:
    role: str
    class_id: int
    logical_name: str
    operation: str
    member_id: int
    reason: str


@dataclass(frozen=True)
class AccessPolicy:
    public_baseline: bool = True
    low_privilege_roles: tuple[str, ...] = ()
    exceptions: tuple[PolicyException, ...] = ()

    def as_dict(self) -> dict[str, Any]:
        return {"baseline": BASELINE, **asdict(self)}


def assess_capability(policy: AccessPolicy, role: str, public: bool, class_id: int,
                      logical_name: str, operation: str, member_id: int) -> dict[str, Any] | None:
    rule = None
    if public and policy.public_baseline:
        allowed = operation == "GET" and (
            member_id == 1
            or (class_id, logical_name, member_id) in PUBLIC_READS
            or (class_id == 15 and member_id in {2, 3, 4, 5, 6, 8, 9})
            or (class_id == 17 and member_id == 2)
        )
        if not allowed:
            rule = "A1.public_non_baseline"
    if (public or role in policy.low_privilege_roles) and operation in {"SET", "ACTION"} and class_id in CONTROL_CLASSES:
        rule = "A2.low_privilege_" + CONTROL_CLASSES[class_id] + "_control"
    if rule is None:
        return None
    exception = next((item for item in policy.exceptions if (
        item.role, item.class_id, item.logical_name, item.operation, item.member_id
    ) == (role, class_id, logical_name, operation, member_id)), None)
    category = (
        "profile_buffer" if class_id == 7 and member_id == 2
        else "register_data" if class_id in {3, 4, 5}
        else CONTROL_CLASSES.get(class_id, "unclassified_non_baseline")
    )
    return {"rule": rule, "baseline": BASELINE, "category": category,
            "assessment": "exception" if exception else "policy_exposure",
            "exception_reason": exception.reason if exception else None}


def evaluate_profile(profile: dict[str, Any], policy: AccessPolicy) -> dict[str, Any]:
    """Keep advertised exposure, observed reads, and policy exceptions separate."""
    role = profile["name"]
    public = profile.get("association", {}).get("authentication") == "none"
    findings = []
    for obj in profile.get("objects", []):
        advertised_object = "association_view" in obj.get("discovery_sources", [])
        for kind, members in (("attribute", obj.get("attributes", [])), ("method", obj.get("methods", []))):
            for member in members:
                member_id = int(member[kind + "_id"])
                rights = member.get("access_rights", {})
                operations = (("ACTION", "action"),) if kind == "method" else (("GET", "read"), ("SET", "write"))
                for operation, permission in operations:
                    advertised = advertised_object and bool(rights.get(permission))
                    verified = operation == "GET" and member.get("outcome") == "SUCCESS"
                    if not advertised and not verified:
                        continue
                    assessment = assess_capability(policy, role, public, int(obj["class_id"]), obj["logical_name"], operation, member_id)
                    if assessment is None:
                        continue
                    findings.append({**assessment, "role": role, "class_id": obj["class_id"],
                        "logical_name": obj["logical_name"], "member_id": member_id,
                        "object_version": obj.get("object_version", 0), "description": obj.get("description"),
                        "operation": operation, "advertised": advertised, "verified": verified,
                        "requirements": rights.get("requirements", []),
                        "outcome": member.get("outcome", "NOT_TESTED"),
                        "evidence": f"objects/{obj['class_id']}/{obj['logical_name']}/{kind}/{member_id}",
                        "related_posture": int(obj["class_id"]) in {64, 18}})
    return {"policy": policy.as_dict(), "findings": findings,
            "summary": {"exposures": sum(f["assessment"] == "policy_exposure" for f in findings),
                        "verified": sum(f["verified"] and f["assessment"] == "policy_exposure" for f in findings),
                        "exceptions": sum(f["assessment"] == "exception" for f in findings)}}
