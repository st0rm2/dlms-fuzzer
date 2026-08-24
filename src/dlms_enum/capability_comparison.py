"""Side-by-side passive comparison of Association View permissions."""

from __future__ import annotations

import json
from collections import Counter
from pathlib import Path
from typing import Any


CapabilityKey = tuple[str, int, str, int]


def _requirements(rights: dict[str, Any]) -> tuple[str, ...]:
    return tuple(sorted({str(item) for item in rights.get("requirements", [])}))


def _side(
    *,
    advertised: bool,
    rights: dict[str, Any] | None,
    object_present: bool,
    member_present: bool,
) -> dict[str, Any]:
    rights = rights or {}
    return {
        "object_present": object_present,
        "member_present": member_present,
        "advertised": advertised,
        "mode": rights.get("mode"),
        "requirements": list(_requirements(rights)),
        "raw": rights.get("raw"),
    }


def _snapshot_model(
    snapshot: dict[str, Any],
) -> tuple[
    set[tuple[int, str]],
    set[tuple[str, int, str, int]],
    dict[CapabilityKey, dict[str, Any]],
]:
    objects: set[tuple[int, str]] = set()
    members: set[tuple[str, int, str, int]] = set()
    capabilities: dict[CapabilityKey, dict[str, Any]] = {}
    for obj in snapshot.get("objects", []):
        class_id = int(obj["class_id"])
        logical_name = str(obj["logical_name"])
        objects.add((class_id, logical_name))
        for attribute in obj.get("attributes", []):
            member_id = int(attribute["attribute_id"])
            members.add(("attribute", class_id, logical_name, member_id))
            rights = dict(attribute.get("access_rights", {}))
            base = {
                "class_id": class_id,
                "logical_name": logical_name,
                "object_version": int(obj.get("object_version", 0)),
                "member_kind": "attribute",
                "member_id": member_id,
                "member_name": attribute.get("name"),
                "rights": rights,
            }
            if rights.get("read"):
                capabilities[("GET", class_id, logical_name, member_id)] = base
            if rights.get("write"):
                capabilities[("SET", class_id, logical_name, member_id)] = base
        for method in obj.get("methods", []):
            member_id = int(method["method_id"])
            members.add(("method", class_id, logical_name, member_id))
            rights = dict(method.get("access_rights", {}))
            if rights.get("action"):
                capabilities[("ACTION", class_id, logical_name, member_id)] = {
                    "class_id": class_id,
                    "logical_name": logical_name,
                    "object_version": int(obj.get("object_version", 0)),
                    "member_kind": "method",
                    "member_id": member_id,
                    "member_name": method.get("name"),
                    "rights": rights,
                }
    return objects, members, capabilities


def _classification(
    public: dict[str, Any] | None,
    authenticated: dict[str, Any] | None,
) -> str:
    if public is None:
        return "authenticated_only"
    if authenticated is None:
        return "public_only"
    public_requirements = set(_requirements(public["rights"]))
    authenticated_requirements = set(_requirements(authenticated["rights"]))
    if public_requirements == authenticated_requirements:
        return "same"
    if public_requirements < authenticated_requirements:
        return "public_broader"
    if authenticated_requirements < public_requirements:
        return "authenticated_broader"
    return "requirements_differ"


def _direct_public_results(role_report: dict[str, Any] | None) -> dict[CapabilityKey, dict[str, Any]]:
    if not role_report:
        return {}
    return {
        (
            "GET",
            int(item["class_id"]),
            str(item["logical_name"]),
            int(item["attribute_id"]),
        ): {
            "tested": bool(item.get("attempt_count", 0)),
            "outcome": item.get("outcome"),
            "assessment": item.get("access_assessment"),
        }
        for item in role_report.get("public_union_test", {}).get("results", [])
    }


def compare_role_capabilities(
    public_snapshot: dict[str, Any],
    authenticated_snapshot: dict[str, Any],
    *,
    role_report: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Compare all advertised GET, SET and ACTION rights for two roles."""

    public_objects, public_members, public_capabilities = _snapshot_model(public_snapshot)
    auth_objects, auth_members, auth_capabilities = _snapshot_model(authenticated_snapshot)
    direct_results = _direct_public_results(role_report)
    rows: list[dict[str, Any]] = []
    counts: dict[str, Counter[str]] = {
        operation: Counter() for operation in ("GET", "SET", "ACTION")
    }
    for key in sorted(
        set(public_capabilities) | set(auth_capabilities),
        key=lambda item: (item[0], item[1], item[2], item[3]),
    ):
        operation, class_id, logical_name, member_id = key
        public = public_capabilities.get(key)
        authenticated = auth_capabilities.get(key)
        source = authenticated or public or {}
        member_kind = str(source.get("member_kind", "attribute"))
        member_key = (member_kind, class_id, logical_name, member_id)
        classification = _classification(public, authenticated)
        row = {
            "operation": operation,
            "class_id": class_id,
            "logical_name": logical_name,
            "member_kind": member_kind,
            "member_id": member_id,
            "member_name": source.get("member_name"),
            "classification": classification,
            "public": _side(
                advertised=public is not None,
                rights=public.get("rights") if public else None,
                object_present=(class_id, logical_name) in public_objects,
                member_present=member_key in public_members,
            ),
            "authenticated": _side(
                advertised=authenticated is not None,
                rights=authenticated.get("rights") if authenticated else None,
                object_present=(class_id, logical_name) in auth_objects,
                member_present=member_key in auth_members,
            ),
            "public_get_verification": direct_results.get(key),
        }
        row["unexpected_public_exposure"] = classification in {
            "public_only",
            "public_broader",
        }
        rows.append(row)
        counts[operation]["total"] += 1
        counts[operation][classification] += 1
        counts[operation]["public_advertised"] += int(public is not None)
        counts[operation]["authenticated_advertised"] += int(authenticated is not None)
        if row["public_get_verification"] and row["public_get_verification"].get(
            "assessment"
        ) == "UNEXPECTED_PUBLIC_ACCESS":
            counts[operation]["verified_unexpected_public_access"] += 1

    public_identity = public_snapshot.get("identity", {})
    authenticated_identity = authenticated_snapshot.get("identity", {})
    return {
        "schema_version": 1,
        "type": "role_capability_comparison",
        "public_role": public_identity.get("role"),
        "authenticated_role": authenticated_identity.get("role"),
        "meter_identity": authenticated_identity.get("meter_identity")
        or public_identity.get("meter_identity"),
        "object_presence": {
            "only_public": [
                {"class_id": class_id, "logical_name": logical_name}
                for class_id, logical_name in sorted(public_objects - auth_objects)
            ],
            "only_authenticated": [
                {"class_id": class_id, "logical_name": logical_name}
                for class_id, logical_name in sorted(auth_objects - public_objects)
            ],
            "shared": len(public_objects & auth_objects),
        },
        "summary": {
            operation: dict(counts[operation])
            for operation in ("GET", "SET", "ACTION")
        },
        "capabilities": rows,
    }


def build_workflow_comparison(
    public_snapshot: dict[str, Any],
    authenticated: list[tuple[dict[str, Any], dict[str, Any] | None]],
) -> dict[str, Any]:
    return {
        "schema_version": 1,
        "type": "multi_role_capability_comparison",
        "public_role": public_snapshot.get("identity", {}).get("role"),
        "comparisons": [
            compare_role_capabilities(
                public_snapshot,
                snapshot,
                role_report=role_report,
            )
            for snapshot, role_report in authenticated
        ],
    }


def render_comparison_markdown(report: dict[str, Any]) -> str:
    lines = [
        "# Public versus authenticated permissions",
        "",
        "This is a passive comparison of advertised permissions. Only the separate public GET verification may contain transmitted access tests; SET and ACTION are never sent.",
        "",
    ]
    for comparison in report.get("comparisons", []):
        role = comparison.get("authenticated_role", "authenticated")
        lines.extend(
            [
                f"## Public versus `{role}`",
                "",
                "| Operation | Total | Public | Authenticated | Public broader/only | Authenticated broader/only | Different requirements |",
                "|---|---:|---:|---:|---:|---:|---:|",
            ]
        )
        for operation in ("GET", "SET", "ACTION"):
            summary = comparison.get("summary", {}).get(operation, {})
            lines.append(
                "| {} | {} | {} | {} | {} | {} | {} |".format(
                    operation,
                    summary.get("total", 0),
                    summary.get("public_advertised", 0),
                    summary.get("authenticated_advertised", 0),
                    summary.get("public_only", 0) + summary.get("public_broader", 0),
                    summary.get("authenticated_only", 0)
                    + summary.get("authenticated_broader", 0),
                    summary.get("requirements_differ", 0),
                )
            )
        lines.extend(
            [
                "",
                "| Operation | Class | Logical name | Member | Public mode | Authenticated mode | Difference | Public GET verification |",
                "|---|---:|---|---:|---|---|---|---|",
            ]
        )
        for item in comparison.get("capabilities", []):
            verification = item.get("public_get_verification") or {}
            lines.append(
                "| {} | {} | {} | {} | {} | {} | {} | {} |".format(
                    item.get("operation", "—"),
                    item.get("class_id", "—"),
                    str(item.get("logical_name", "—")).replace("|", "\\|"),
                    item.get("member_id", "—"),
                    item.get("public", {}).get("mode") or "—",
                    item.get("authenticated", {}).get("mode") or "—",
                    item.get("classification", "—"),
                    verification.get("assessment")
                    or verification.get("outcome")
                    or "not tested",
                )
            )
        lines.append("")
    return "\n".join(lines)


def write_workflow_comparison(
    report: dict[str, Any], json_path: str | Path, markdown_path: str | Path
) -> None:
    Path(json_path).write_text(
        json.dumps(report, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    Path(markdown_path).write_text(
        render_comparison_markdown(report), encoding="utf-8"
    )
