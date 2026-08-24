"""Portable Association View snapshots for repeat scans."""

from __future__ import annotations

import hashlib
import json
import os
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

SCHEMA_VERSION = 1


def _safe_name(value: str) -> str:
    candidate = re.sub(r"[^A-Za-z0-9_.-]+", "-", value).strip("-.")
    return candidate or "role"


def default_cache_path(device: str, role: str) -> Path:
    """Return the stable per-device, per-role snapshot location."""

    state_root = Path(
        os.environ.get(
            "XDG_STATE_HOME", str(Path.home() / ".local" / "state")
        )
    )
    device_key = hashlib.sha256(device.encode("utf-8")).hexdigest()[:16]
    return state_root / "dlms-enum" / "association-views" / device_key / (
        _safe_name(role) + ".json"
    )


def snapshot_from_report(report: dict[str, Any]) -> dict[str, Any]:
    """Extract reusable Association View metadata from a completed role report."""

    profiles = report.get("profiles", [])
    if not profiles:
        raise ValueError("report does not contain a scanned profile")
    profile = profiles[0]
    configuration = report.get("effective_configuration", {})
    transport = report.get("transport", {})
    configured_profiles = configuration.get("profiles", [])
    configured_profile = configured_profiles[0] if configured_profiles else {}
    objects: list[dict[str, Any]] = []
    for item in profile.get("objects", []):
        if "association_view" not in item.get("discovery_sources", []):
            continue
        objects.append(
            {
                "class_id": int(item["class_id"]),
                "logical_name": str(item["logical_name"]),
                "object_version": int(item.get("object_version", 0)),
                "description": str(item.get("description", "") or ""),
                "attributes": [
                    {
                        "attribute_id": int(attribute["attribute_id"]),
                        "name": attribute.get("name"),
                        "access_rights": attribute.get("access_rights", {}),
                    }
                    for attribute in item.get("attributes", [])
                ],
                "methods": [
                    {
                        "method_id": int(method["method_id"]),
                        "name": method.get("name"),
                        "access_rights": method.get("access_rights", {}),
                    }
                    for method in item.get("methods", [])
                ],
            }
        )
    if not objects:
        raise ValueError("report does not contain Association View objects")
    return {
        "schema_version": SCHEMA_VERSION,
        "type": "dlms_association_view",
        "saved_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "identity": {
            "device": transport.get("device"),
            "meter_identity": report.get("preflight", {}).get("meter_identity"),
            "role": profile.get("name"),
            "profile": configured_profile.get("name", profile.get("type")),
            "client_address": profile.get("association", {}).get(
                "client_address", configured_profile.get("client_address")
            ),
            "server_address": transport.get("selected_server_address"),
        },
        "object_count": len(objects),
        "objects": objects,
    }


def validate_snapshot(
    snapshot: dict[str, Any],
    *,
    device: str,
    role: str,
    client_address: int,
    meter_identity: str | None = None,
    profile: str | None = None,
) -> None:
    if (
        snapshot.get("schema_version") != SCHEMA_VERSION
        or snapshot.get("type") != "dlms_association_view"
        or not isinstance(snapshot.get("objects"), list)
    ):
        raise ValueError("unsupported Association View snapshot")
    identity = snapshot.get("identity", {})
    expected = {
        "device": device,
        "role": role,
        "client_address": int(client_address),
    }
    if meter_identity is not None:
        expected["meter_identity"] = meter_identity
    if profile is not None:
        expected["profile"] = profile
    mismatches = [
        f"{key}={identity.get(key)!r} (expected {value!r})"
        for key, value in expected.items()
        if identity.get(key) != value
    ]
    if mismatches:
        raise ValueError("Association View snapshot identity mismatch: " + ", ".join(mismatches))
    objects = snapshot["objects"]
    if snapshot.get("object_count") != len(objects):
        raise ValueError("Association View snapshot object count is inconsistent")
    seen: set[tuple[int, str]] = set()
    for item in objects:
        try:
            key = (int(item["class_id"]), str(item["logical_name"]))
            attributes = item.get("attributes", [])
            methods = item.get("methods", [])
        except (KeyError, TypeError, ValueError) as exc:
            raise ValueError("Association View snapshot contains an invalid object") from exc
        if key in seen:
            raise ValueError(f"Association View snapshot repeats object {key}")
        if not isinstance(attributes, list) or not isinstance(methods, list):
            raise ValueError(f"Association View snapshot has invalid rights for {key}")
        seen.add(key)


def load_snapshot(path: str | Path) -> dict[str, Any]:
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError("Association View snapshot must be a JSON object")
    return data


def write_snapshot(snapshot: dict[str, Any], path: str | Path) -> None:
    destination = Path(path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary = destination.with_suffix(destination.suffix + ".tmp")
    temporary.write_text(
        json.dumps(snapshot, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    temporary.replace(destination)


def compare_snapshots(
    saved: dict[str, Any], current: dict[str, Any]
) -> dict[str, Any]:
    """Compare object versions and advertised access metadata."""

    def indexed(snapshot: dict[str, Any]) -> dict[tuple[int, str], dict[str, Any]]:
        return {
            (int(item["class_id"]), str(item["logical_name"])): item
            for item in snapshot.get("objects", [])
        }

    old = indexed(saved)
    new = indexed(current)
    added = sorted(new.keys() - old.keys())
    removed = sorted(old.keys() - new.keys())
    changed: list[dict[str, Any]] = []

    def rights(items: list[dict[str, Any]], id_key: str) -> list[dict[str, Any]]:
        return sorted(
            (
                {
                    id_key: int(item[id_key]),
                    "access_rights": item.get("access_rights", {}),
                }
                for item in items
            ),
            key=lambda item: item[id_key],
        )

    for key in sorted(old.keys() & new.keys()):
        before = old[key]
        after = new[key]
        comparable_before = {
            "object_version": before.get("object_version", 0),
            "attributes": rights(before.get("attributes", []), "attribute_id"),
            "methods": rights(before.get("methods", []), "method_id"),
        }
        comparable_after = {
            "object_version": after.get("object_version", 0),
            "attributes": rights(after.get("attributes", []), "attribute_id"),
            "methods": rights(after.get("methods", []), "method_id"),
        }
        if comparable_before != comparable_after:
            changed.append({"class_id": key[0], "logical_name": key[1]})
    return {
        "matches": not (added or removed or changed),
        "saved_object_count": len(old),
        "current_object_count": len(new),
        "added": [
            {"class_id": class_id, "logical_name": logical_name}
            for class_id, logical_name in added
        ],
        "removed": [
            {"class_id": class_id, "logical_name": logical_name}
            for class_id, logical_name in removed
        ],
        "changed": changed,
    }
