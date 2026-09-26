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
    probe_identity = (role_report or {}).get("public_union_test", {}).get("public_association", {})
    public_identity = public_snapshot.get("identity", {})
    if (probe_identity.get("client_address") is not None
            and probe_identity["client_address"] != public_identity.get("client_address")):
        direct_results = {}
    if not compatible_identities(public_identity, authenticated_snapshot.get("identity", {})):
        direct_results = {}
    public_all = normalized_capabilities(public_snapshot)
    authenticated_all = normalized_capabilities(authenticated_snapshot)
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
                rights=public.get("rights") if public else public_all.get(key),
                object_present=(class_id, logical_name) in public_objects,
                member_present=member_key in public_members,
            ),
            "authenticated": _side(
                advertised=authenticated is not None,
                rights=authenticated.get("rights") if authenticated else authenticated_all.get(key),
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
        "# Role permissions",
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
        capabilities = comparison.get("capabilities", [])
        omitted_authenticated_only = sum(
            item.get("classification") == "authenticated_only"
            and not item.get("public_get_verification")
            for item in capabilities
        )
        for item in capabilities:
            if item.get("classification") == "authenticated_only" and not item.get("public_get_verification"):
                continue
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
        if omitted_authenticated_only:
            lines.extend(
                [
                    "",
                    f"{omitted_authenticated_only} authenticated-only rows are omitted from this compact view; the complete list remains in `capability-comparison.json`.",
                ]
            )
        lines.append("")
    if report.get("role_matrix"):
        lines.extend(["", render_role_matrix(report["role_matrix"])])
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


def normalized_capabilities(snapshot: dict[str, Any]) -> dict[CapabilityKey, dict[str, Any]]:
    """Retain denied members and their raw requirements, as well as grants."""
    result = {}
    for obj in snapshot.get("objects", []):
        for kind, members in (("attribute", obj.get("attributes", [])), ("method", obj.get("methods", []))):
            for member in members:
                rights = member.get("access_rights", {})
                operations = (("ACTION", "action"),) if kind == "method" else (("GET", "read"), ("SET", "write"))
                for operation, permission in operations:
                    key = (operation, int(obj["class_id"]), str(obj["logical_name"]), int(member[kind + "_id"]))
                    result[key] = {"object_present": True, "member_present": True,
                        "advertised": bool(rights.get(permission)),
                        "state": "allowed" if rights.get(permission) else "denied",
                        "mode": rights.get("mode"), "raw": rights.get("raw"),
                        "requirements": list(_requirements(rights)),
                        "object_version": obj.get("object_version", 0)}
    return result


def compatible_identities(left: dict[str, Any], right: dict[str, Any]) -> bool:
    """Missing identity is unknown; a known contradiction is incompatible."""
    return all(left.get(key) is None or right.get(key) is None or left[key] == right[key]
               for key in ("device", "meter_identity", "server_address"))


def build_role_matrix(snapshots: dict[str, dict[str, Any]], roles: list[str]) -> dict[str, Any]:
    from itertools import combinations

    models = {role: normalized_capabilities(snapshot) for role, snapshot in snapshots.items()}
    objects = {role: {(int(o["class_id"]), o["logical_name"]) for o in snapshot.get("objects", [])}
               for role, snapshot in snapshots.items()}
    rows = []
    for key in sorted(set().union(*(set(model) for model in models.values()))):
        operation, class_id, logical_name, member_id = key
        cells = {}
        for role in roles:
            cell = models.get(role, {}).get(key)
            if cell is None:
                present = (class_id, logical_name) in objects.get(role, set())
                cell = {"state": "view_unavailable" if role not in models else "member_absent" if present else "object_absent",
                        "object_present": present if role in models else None,
                        "member_present": False if role in models else None,
                        "advertised": None, "requirements": [], "raw": None, "mode": None}
            cells[role] = cell
        rows.append({"operation": operation, "class_id": class_id, "logical_name": logical_name,
                     "member_id": member_id, "roles": cells})
    pairs = []
    for left, right in combinations(roles, 2):
        compatible = compatible_identities(snapshots.get(left, {}).get("identity", {}), snapshots.get(right, {}).get("identity", {}))
        differences = []
        for row in rows:
            a, b = row["roles"][left], row["roles"][right]
            if not compatible:
                classification = "identity_mismatch"
            elif "view_unavailable" in (a["state"], b["state"]):
                classification = "view_unavailable"
            elif a.get("object_version") is not None and b.get("object_version") is not None and a["object_version"] != b["object_version"]:
                classification = "version_mismatch"
            elif a["state"] != b["state"]:
                classification = "rights_or_presence_differ"
            elif a["requirements"] == b["requirements"]:
                classification = "same"
            elif set(a["requirements"]) < set(b["requirements"]):
                classification = "left_broader"
            elif set(b["requirements"]) < set(a["requirements"]):
                classification = "right_broader"
            else:
                classification = "requirements_differ"
            differences.append({k: v for k, v in row.items() if k != "roles"} | {"classification": classification})
        pairs.append({"left_role": left, "right_role": right, "compatible_identity": compatible,
                      "summary": dict(Counter(item["classification"] for item in differences)),
                      "by_operation": {op: dict(Counter(item["classification"] for item in differences if item["operation"] == op))
                                       for op in ("GET", "SET", "ACTION")},
                      "differences": differences})
    return {"schema_version": 1, "roles": [{"role": role,
        "identity": snapshots.get(role, {}).get("identity"),
        "saved_at": snapshots.get(role, {}).get("saved_at"),
        "source": snapshots.get(role, {}).get("source", "unknown"),
        "status": "available" if role in snapshots else "view_unavailable"} for role in roles],
        "capabilities": rows, "pairs": pairs,
        "role_totals": {role: {op: sum(row["roles"][role]["advertised"] is True for row in rows if row["operation"] == op)
                               for op in ("GET", "SET", "ACTION")} for role in roles}}


def render_role_matrix(report: dict[str, Any]) -> str:
    lines = ["## All-role permissions", "", "Advertised rights only. Missing views are unknown, not denial.", "",
             "| Left role | Right role | Differences | Identity compatible |", "|---|---|---:|---|"]
    for pair in report.get("pairs", []):
        lines.append(f"| {str(pair['left_role']).replace('|', '/')} | {str(pair['right_role']).replace('|', '/')} | "
                     f"{sum(v for k, v in pair['summary'].items() if k != 'same')} | {pair['compatible_identity']} |")
    roles = [item["role"] for item in report.get("roles", [])]
    lines += ["", "| Operation | Class | Logical name | Member | " + " | ".join(r.replace("|", "/") for r in roles) + " |",
              "|---|---:|---|---:|" + "---|" * len(roles)]
    for row in report.get("capabilities", []):
        cells = [row["roles"][role] for role in roles]
        lines.append(f"| {row['operation']} | {row['class_id']} | {row['logical_name']} | {row['member_id']} | " +
                     " | ".join(cell["state"] + (": " + ", ".join(cell["requirements"]) if cell["requirements"] else "") for cell in cells) + " |")
    return "\n".join(lines) + "\n"
