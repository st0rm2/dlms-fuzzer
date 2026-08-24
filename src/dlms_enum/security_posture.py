"""Read-only security and firmware-update posture derived from scan evidence."""

from __future__ import annotations

from typing import Any

from .result_model import Outcome


SECURITY_ATTRIBUTE_NAMES = {
    2: "security_policy",
    3: "security_suite",
    4: "client_system_title",
    5: "server_system_title",
    6: "certificates",
}
SECURITY_METHOD_NAMES = {
    1: "activate_security",
    2: "transfer_global_keys",
    3: "key_agreement",
    4: "generate_key_pair",
    5: "generate_certificate_request",
    6: "import_certificate",
    7: "export_certificate",
    8: "remove_certificate",
}
IMAGE_ATTRIBUTE_NAMES = {
    2: "image_block_size",
    3: "transferred_blocks_status",
    4: "first_not_transferred_block",
    5: "image_transfer_enabled",
    6: "image_transfer_status",
}
IMAGE_METHOD_NAMES = {
    1: "initiate_image_transfer",
    2: "transfer_image_block",
    3: "verify_image",
    4: "activate_image",
}


def _value(attribute: dict[str, Any]) -> Any:
    if attribute.get("outcome") != Outcome.SUCCESS.value:
        return None
    decoded = attribute.get("decoded", {})
    return decoded.get("value") if isinstance(decoded, dict) else None


def _object_posture(
    obj: dict[str, Any],
    *,
    attribute_names: dict[int, str],
    method_names: dict[int, str],
) -> dict[str, Any]:
    attributes = []
    for attribute in obj.get("attributes", []):
        attribute_id = int(attribute.get("attribute_id", -1))
        if attribute_id not in attribute_names:
            continue
        rights = attribute.get("access_rights", {})
        attributes.append(
            {
                "attribute_id": attribute_id,
                "name": attribute_names[attribute_id],
                "read_advertised": bool(rights.get("read")),
                "write_advertised": bool(rights.get("write")),
                "requirements": list(rights.get("requirements", [])),
                "outcome": attribute.get("outcome") or Outcome.NOT_TESTED.value,
                "value": _value(attribute),
            }
        )
    methods = []
    indexed_methods = {
        int(method.get("method_id", -1)): method for method in obj.get("methods", [])
    }
    for method_id, name in method_names.items():
        method = indexed_methods.get(method_id, {})
        rights = method.get("access_rights", {})
        methods.append(
            {
                "method_id": method_id,
                "name": name,
                "advertised": bool(rights.get("action")),
                "requirements": list(rights.get("requirements", [])),
                "tested": False,
            }
        )
    return {
        "class_id": int(obj["class_id"]),
        "logical_name": obj["logical_name"],
        "object_version": int(obj.get("object_version", 0)),
        "description": obj.get("description"),
        "attributes": attributes,
        "methods": methods,
    }


def build_security_posture(profile: dict[str, Any]) -> dict[str, Any]:
    """Summarize class 64 and class 18 without sending modifying operations."""

    public_role = profile.get("association", {}).get("authentication") == "none"
    security_setups = [
        _object_posture(
            obj,
            attribute_names=SECURITY_ATTRIBUTE_NAMES,
            method_names=SECURITY_METHOD_NAMES,
        )
        for obj in profile.get("objects", [])
        if int(obj.get("class_id", -1)) == 64
    ]
    image_transfers = [
        _object_posture(
            obj,
            attribute_names=IMAGE_ATTRIBUTE_NAMES,
            method_names=IMAGE_METHOD_NAMES,
        )
        for obj in profile.get("objects", [])
        if int(obj.get("class_id", -1)) == 18
    ]
    findings: list[dict[str, Any]] = []
    for item in security_setups:
        writable = [
            attribute["name"]
            for attribute in item["attributes"]
            if attribute["write_advertised"]
        ]
        actions = [method["name"] for method in item["methods"] if method["advertised"]]
        if public_role and writable:
            findings.append(
                {
                    "severity": "high",
                    "category": "public_security_write",
                    "logical_name": item["logical_name"],
                    "message": "Public role advertises writable Security Setup attributes: "
                    + ", ".join(writable),
                    "passive_evidence": True,
                }
            )
        if public_role and actions:
            findings.append(
                {
                    "severity": "high",
                    "category": "public_key_management_action",
                    "logical_name": item["logical_name"],
                    "message": "Public role advertises Security Setup actions: "
                    + ", ".join(actions),
                    "passive_evidence": True,
                }
            )
    for item in image_transfers:
        writable = [
            attribute["name"]
            for attribute in item["attributes"]
            if attribute["write_advertised"]
        ]
        actions = [method["name"] for method in item["methods"] if method["advertised"]]
        if public_role and (writable or actions):
            findings.append(
                {
                    "severity": "high",
                    "category": "public_firmware_update_control",
                    "logical_name": item["logical_name"],
                    "message": "Public role advertises firmware-update control: "
                    + ", ".join(writable + actions),
                    "passive_evidence": True,
                }
            )
    return {
        "mode": "read_only_passive",
        "role": profile.get("name"),
        "public_role": public_role,
        "security_setup_objects": security_setups,
        "image_transfer_objects": image_transfers,
        "findings": findings,
        "summary": {
            "security_setup_objects": len(security_setups),
            "image_transfer_objects": len(image_transfers),
            "high_findings": sum(
                item.get("severity") == "high" for item in findings
            ),
        },
        "limitations": (
            "Advertised permissions are passive evidence. No SET, key-management "
            "ACTION, or Image Transfer ACTION was sent, so this does not prove that "
            "a modifying operation would succeed."
        ),
    }
