"""Hidden Association LN discovery and passive control-instance comparisons."""
from __future__ import annotations

from itertools import combinations
from typing import Any


def parse_instances(value: str) -> range:
    try:
        first, last = (int(part) for part in value.split(":"))
    except (TypeError, ValueError) as exc:
        raise ValueError("association instances must be FIRST:LAST within 0..255") from exc
    if not 0 <= first <= last <= 255:
        raise ValueError("association instances must be FIRST:LAST within 0..255")
    return range(first, last + 1)


def hidden_requests(role: str, snapshot: dict[str, Any], instances: range) -> list[dict[str, Any]]:
    present = {(int(o["class_id"]), o["logical_name"]) for o in snapshot["objects"]}
    requests = []
    for instance in instances:
        name = f"0.0.40.0.{instance}.255"
        if (15, name) in present:
            continue
        for attribute in (1, 2):
            requests.append({"class_id": 15, "logical_name": name, "attribute_id": attribute,
                "object_version": 0, "probe_role": role, "source_roles": [], "selected": True,
                "kind": "hidden_association", "outcome": "NOT_TESTED", "attempt_count": 0,
                "attempts": [], "discovery_sources": ["hidden_association_probe"]})
    return requests


def association_snapshot(objects: list[Any], logical_name: str, identity: dict[str, Any]) -> dict[str, Any]:
    from types import SimpleNamespace
    from .scanner import _attribute_access_rights, _method_access_rights
    from .gurux_adapter import _logical_name

    if not isinstance(objects, (list, tuple)):
        raise ValueError("invalid hidden association list")
    entries = []
    seen = set()
    for entry in objects:
        if not isinstance(entry, (list, tuple)) or len(entry) != 4:
            raise ValueError("invalid hidden association entry")
        class_id, version, raw_name, rights = entry
        name = _logical_name(raw_name)
        if name is None or not isinstance(rights, (list, tuple)) or len(rights) != 2:
            raise ValueError("invalid hidden association metadata")
        key = (int(class_id), name)
        if key in seen:
            raise ValueError("duplicate hidden association object")
        seen.add(key)
        entries.append((int(class_id), int(version), name, rights))
    version = next((v for c, v, name, _ in entries if c == 15 and name == logical_name), None)
    records = []
    for class_id, obj_version, name, rights in entries:
        record = {"class_id": class_id, "logical_name": name, "object_version": obj_version,
                  "attributes": [], "methods": [], "source_association": logical_name,
                  "discovery_sources": ["hidden_association_view"]}
        for member_kind, members in zip(("attribute", "method"), rights):
            if not isinstance(members, (list, tuple)):
                raise ValueError("invalid hidden association rights")
            member_ids = set()
            for member in members:
                if not isinstance(member, (list, tuple)) or len(member) < 2:
                    raise ValueError("invalid hidden association member")
                index, mode = int(member[0]), int(member[1])
                if index <= 0 or index in member_ids:
                    raise ValueError("invalid or duplicate hidden association member")
                member_ids.add(index)
                if version is None:
                    record.setdefault("uninterpreted_rights", []).append(
                        {"kind": member_kind, "member_id": index, "raw": mode})
                    continue
                if member_kind == "attribute":
                    target = SimpleNamespace(getAccess=lambda i, m=mode: m,
                                             getAccess3=lambda i, m=mode: m)
                    access = _attribute_access_rights(target, index, version)
                else:
                    access = _method_access_rights(SimpleNamespace(methodAccess=mode, methodAccess3=mode), version)
                record[member_kind + "s"].append({member_kind + "_id": index, "access_rights": access})
        records.append(record)
    return {"identity": identity, "source": "hidden_association_view", "source_association": logical_name,
            "rights_encoding_known": version is not None, "objects": records, "object_count": len(records)}


def control_findings(snapshot: dict[str, Any], role: str) -> list[dict[str, Any]]:
    from .capability_comparison import normalized_capabilities

    objects = sorted((o for o in snapshot.get("objects", []) if int(o["class_id"]) == 70),
                     key=lambda o: o["logical_name"])
    models = {o["logical_name"]: {(key[0], key[3]): cell for key, cell in
              normalized_capabilities({"objects": [o]}).items()} for o in objects}
    findings = []
    for left, right in combinations(objects, 2):
        a, b = models[left["logical_name"]], models[right["logical_name"]]
        differences = []
        for key in sorted(a.keys() | b.keys()):
            x, y = a.get(key), b.get(key)
            if x is None or y is None:
                classification = "member_metadata_missing"
            elif left.get("object_version", 0) != right.get("object_version", 0):
                classification = "version_mismatch"
            elif (x["advertised"], x["requirements"]) == (y["advertised"], y["requirements"]):
                continue
            else:
                classification = "inconsistent_rights"
            differences.append({"operation": key[0], "member_id": key[1],
                                "classification": classification, "left": x, "right": y})
        if differences:
            findings.append({"rule_id": "A5", "role": role, "class_id": 70,
                "left_logical_name": left["logical_name"], "right_logical_name": right["logical_name"],
                "assessment": "review_required", "differences": differences,
                "source": snapshot.get("source", "association_view"),
                "source_association": snapshot.get("source_association"),
                "note": "Instances may control different outputs; no SET or ACTION was sent."})
    return findings
