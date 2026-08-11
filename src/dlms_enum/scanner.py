"""Public-profile association discovery and GET-only scan orchestration."""

from __future__ import annotations

import getpass
import os
import shlex
import stat
from collections.abc import Callable
from pathlib import Path
from typing import Any

from . import __version__
from .catalogues import COMMON_OBIS
from .config import AppConfig
from .result_model import Outcome, classify_exception, enum_name, error_record, utc_now

ProgressCallback = Callable[[dict[str, Any]], None]


def _serial_permission_message(device_stat: os.stat_result, device: str) -> str:
    """Describe how the current user can obtain access to a serial device."""

    user = getpass.getuser()
    group_name: str | None = None
    owner_name = str(device_stat.st_uid)
    try:
        import grp
        import pwd

        group_name = grp.getgrgid(device_stat.st_gid).gr_name
        owner_name = pwd.getpwuid(device_stat.st_uid).pw_name
    except (ImportError, KeyError):
        pass

    group_label = group_name or str(device_stat.st_gid)
    details = (
        f"device mode {stat.filemode(device_stat.st_mode)}, "
        f"owner {owner_name}:{group_label}"
    )
    message = (
        f"Permission denied for serial device {device}: user {user!r} needs read and write access "
        f"({details})."
    )

    current_groups = set(os.getgroups())
    current_groups.add(os.getegid())
    if group_name and group_name != "root" and device_stat.st_gid not in current_groups:
        command = "sudo usermod -aG {} {}".format(
            shlex.quote(group_name), shlex.quote(user)
        )
        return (
            f"{message} Add {user!r} to the {group_name!r} group (for example: {command}), "
            "then log out and back in before retrying."
        )
    return f"{message} Grant access with an appropriate device-group membership, udev rule, or ACL before retrying."


def validate_serial_device(device: str) -> str:
    if os.name == "nt":
        return device
    path = Path(device)
    try:
        device_stat = path.stat()
    except FileNotFoundError as exc:
        raise ValueError(
            f"Serial device {device} does not exist. Reconnect it or select an available device, "
            "preferably using its stable /dev/serial/by-id path."
        ) from exc
    if not stat.S_ISCHR(device_stat.st_mode):
        raise ValueError(f"Serial device {device} is not a character device.")
    if not os.access(path, os.R_OK | os.W_OK):
        raise PermissionError(_serial_permission_message(device_stat, device))
    return device


def _attribute_name(target: Any, attribute_id: int) -> str | None:
    try:
        names = target.getNames()
    except Exception:
        return "logical_name" if attribute_id == 1 else None
    if 0 < attribute_id <= len(names):
        return str(names[attribute_id - 1])
    return None


def _class_name(target: Any) -> str:
    return enum_name(getattr(target, "objectType", None)) or type(target).__name__


def _association_version(objects: list[Any]) -> int:
    for target in objects:
        if int(target.objectType) == 15 and str(target.logicalName) == "0.0.40.0.0.255":
            return int(getattr(target, "version", 0))
    return 2


def _access_details(target: Any, attribute_id: int, association_version: int) -> tuple[bool, str]:
    if association_version >= 3:
        mode = int(target.getAccess3(attribute_id))
        base = mode & 0x03
        return base in (1, 3), f"access3:0x{mode:02X}"
    mode = int(target.getAccess(attribute_id))
    names = {
        0: "none",
        1: "read",
        2: "write",
        3: "read_write",
        4: "authenticated_read",
        5: "authenticated_write",
        6: "authenticated_read_write",
    }
    return mode in (1, 3, 4, 6), names.get(mode, f"mode_{mode}")


def _advertised_attributes(target: Any, association_version: int) -> dict[int, str]:
    explicit = {int(item.index) for item in getattr(target, "attributes", ())}
    explicit.add(1)  # the logical-name attribute is implicitly readable
    if len(explicit) == 1:
        try:
            explicit.update(range(1, int(target.getAttributeCount()) + 1))
        except Exception:
            pass
    readable: dict[int, str] = {}
    for attribute_id in sorted(explicit):
        allowed, access = _access_details(target, attribute_id, association_version)
        if allowed:
            readable[attribute_id] = access
    return readable


def _ordered_attribute_ids(target: Any, attributes: dict[int, str]) -> list[int]:
    """Honor interface-class read order (notably scaler/unit before value)."""

    preferred: list[int] = []
    try:
        preferred = [int(item) for item in target.getAttributeIndexToRead(True)]
    except Exception:
        pass
    ordered = [item for item in preferred if item in attributes]
    ordered.extend(item for item in sorted(attributes) if item not in ordered)
    return ordered


def _object_record(target: Any, sources: set[str]) -> dict[str, Any]:
    return {
        "class_id": int(target.objectType),
        "class_name": _class_name(target),
        "logical_name": str(target.logicalName),
        "object_version": int(getattr(target, "version", 0)),
        "description": str(getattr(target, "description", "") or ""),
        "discovery_sources": sorted(sources),
        "attributes": [],
        "methods": [
            {
                "method_id": int(item.index),
                "advertised_access": {
                    "legacy": str(getattr(item, "methodAccess", "")),
                    "version3": str(getattr(item, "methodAccess3", "")),
                },
                "status": "discovered",
                "note": "ACTION testing is deferred",
            }
            for item in getattr(target, "methodAttributes", ())
        ],
    }


def _baud_rates(config: AppConfig) -> tuple[int, ...]:
    if config.transport.baudrate == "auto":
        return config.transport.baudrate_candidates
    return (int(config.transport.baudrate),)


def _server_address_candidates(config: AppConfig) -> tuple[dict[str, Any], ...]:
    """Return bounded one- and two-byte server-address forms to probe."""

    profile = config.profile
    logical = profile.server_logical_address
    physical = profile.server_physical_address
    candidates: list[tuple[int, int, int]] = []

    # A one-byte address omits the upper/logical component. It is the common
    # direct-HDLC representation of server address 1 used by this meter.
    if 0 < physical < 0x80:
        candidates.append((0, physical, 1))

    if logical < 0x80 and physical < 0x80:
        if logical:
            candidates.append((logical, physical, 2))
        elif physical:
            # Also test the management logical-device form when the configured
            # endpoint already uses one-byte addressing.
            candidates.append((1, physical, 2))
    else:
        # Preserve compatibility with explicitly configured four-byte HDLC
        # addresses, although automatic discovery remains intentionally bounded.
        candidates.append((logical, physical, 4))

    unique: list[dict[str, Any]] = []
    seen: set[tuple[int, int, int]] = set()
    labels = {1: "1-byte addressing", 2: "2-Byte addressing", 4: "4-byte addressing"}
    for candidate_logical, candidate_physical, address_size in candidates:
        identity = (candidate_logical, candidate_physical, address_size)
        if identity in seen:
            continue
        seen.add(identity)
        shift = 14 if address_size == 4 else 7
        unique.append(
            {
                "logical_address": candidate_logical,
                "physical_address": candidate_physical,
                "server_address": (candidate_logical << shift) | candidate_physical,
                "address_size": address_size,
                "server_addressing_type": labels[address_size],
            }
        )
    return tuple(unique)


def scan_public(
    config: AppConfig,
    traffic: Any,
    *,
    progress: ProgressCallback | None = None,
) -> dict[str, Any]:
    """Run a complete public association scan and return the canonical report."""

    progress = progress or (lambda _: None)
    started_at = utc_now()
    run_id = started_at.replace("-", "").replace(":", "").replace(".", "")
    report: dict[str, Any] = {
        "schema_version": 1,
        "tool": {"name": "dlms-enum", "version": __version__},
        "run": {"id": run_id, "started_at": started_at, "finished_at": None, "status": "running"},
        "effective_configuration": config.redacted_dict(),
        "transport": {
            "type": "serial_hdlc",
            "device": config.transport.device,
            "baudrate_strategy": "auto" if config.transport.baudrate == "auto" else "fixed",
            "baudrate_findings": [],
            "endpoint_findings": [],
            "selected_baudrate": None,
            "selected_server_address": None,
            "selected_server_logical_address": None,
            "selected_server_physical_address": None,
            "server_address_size": None,
            "server_addressing_type": None,
        },
        "profiles": [],
        "capability_matrix": [],
        "unknown_objects": [],
        "errors": [],
    }
    session = None
    association: dict[str, Any] = {}
    objects: list[Any] = []

    try:
        validate_serial_device(config.transport.device)
        try:
            from .gurux_adapter import GuruxSession
        except ModuleNotFoundError as exc:
            raise RuntimeError(
                "DLMS runtime dependency missing; install the package with 'python -m pip install -e .'"
            ) from exc

        address_candidates = _server_address_candidates(config)
        for baudrate in _baud_rates(config):
            progress({"phase": "baud_detection", "baudrate": baudrate, "message": f"Trying {baudrate} baud"})
            failed_candidates: list[tuple[BaseException, dict[str, Any]]] = []
            for endpoint in address_candidates:
                progress(
                    {
                        "phase": "server_address_detection",
                        "message": (
                            f"Trying server {endpoint['server_address']} with "
                            f"{endpoint['server_addressing_type']} at {baudrate} baud"
                        ),
                    }
                )
                candidate = GuruxSession(
                    config,
                    baudrate,
                    traffic,
                    server_logical_address=endpoint["logical_address"],
                    server_physical_address=endpoint["physical_address"],
                    server_address_size=endpoint["address_size"],
                )
                try:
                    association = candidate.connect()
                except Exception as exc:
                    finding = {
                        "baudrate": baudrate,
                        **endpoint,
                        "valid": False,
                        "outcome": classify_exception(exc).value,
                        "error": f"{type(exc).__name__}: {exc}",
                    }
                    report["transport"]["endpoint_findings"].append(finding)
                    failed_candidates.append((exc, endpoint))
                    progress(
                        {
                            "phase": "server_address_detection_error",
                            "message": (
                                f"Server {endpoint['server_address']} with "
                                f"{endpoint['server_addressing_type']} failed at {baudrate} baud: "
                                f"{type(exc).__name__}: {exc}"
                            ),
                        }
                    )
                    candidate.close()
                    continue

                finding = {
                    "baudrate": baudrate,
                    **endpoint,
                    "valid": True,
                    "outcome": Outcome.SUCCESS.value,
                }
                report["transport"]["endpoint_findings"].append(finding)
                report["transport"]["baudrate_findings"].append(finding.copy())
                report["transport"].update(
                    {
                        "selected_baudrate": baudrate,
                        "selected_server_address": endpoint["server_address"],
                        "selected_server_logical_address": endpoint["logical_address"],
                        "selected_server_physical_address": endpoint["physical_address"],
                        "server_address_size": endpoint["address_size"],
                        "server_addressing_type": endpoint["server_addressing_type"],
                    }
                )
                progress(
                    {
                        "phase": "server_address_detected",
                        "message": (
                            f"Found server {endpoint['server_address']} using "
                            f"{endpoint['server_addressing_type']} at {baudrate} baud"
                        ),
                    }
                )
                session = candidate
                break

            if session is not None:
                break

            for exc, endpoint in failed_candidates:
                report["errors"].append(
                    error_record(
                        exc,
                        phase="serial_and_baud_discovery",
                        context={"baudrate": baudrate, **endpoint},
                    )
                )
            last_error = failed_candidates[-1][0] if failed_candidates else RuntimeError("no server-address candidates")
            report["transport"]["baudrate_findings"].append(
                {
                    "baudrate": baudrate,
                    "valid": False,
                    "outcome": classify_exception(last_error).value,
                    "error": f"{type(last_error).__name__}: {last_error}",
                }
            )

        if session is None:
            raise RuntimeError("no baud rate and server-address combination produced a valid public DLMS association")

        progress({"phase": "association_view", "message": "Reading Association LN object list"})
        discovery_error: BaseException | None = None
        association_view_attempts = 0
        for attempt in range(1, config.scan.total_get_attempts + 1):
            association_view_attempts = attempt
            try:
                objects = list(session.discover_objects(attempt))
                discovery_error = None
                break
            except Exception as exc:
                discovery_error = exc
                report["errors"].append(
                    error_record(
                        exc,
                        phase="public_reconnaissance",
                        context={"operation": "GET", "logical_name": "0.0.40.0.0.255", "attribute_id": 2, "attempt": attempt},
                    )
                )
                progress(
                    {
                        "phase": "association_view_error",
                        "message": f"Association-view attempt {attempt} failed: {type(exc).__name__}: {exc}",
                    }
                )
                if classify_exception(exc) == Outcome.DLMS_ERROR:
                    break
        if discovery_error is not None:
            raise RuntimeError(f"association-view discovery failed: {discovery_error}")

        version = _association_version(objects)
        inventory: dict[tuple[int, str], dict[str, Any]] = {}
        for target in objects:
            key = (int(target.objectType), str(target.logicalName))
            inventory[key] = {
                "target": target,
                "sources": {"association_view"},
                "attributes": _advertised_attributes(target, version),
            }

        if config.scan.common_catalogue:
            for entry in COMMON_OBIS:
                key = (entry.class_id, entry.logical_name)
                if key not in inventory:
                    target = session.create_object(entry.class_id, entry.logical_name)
                    target.description = entry.description
                    inventory[key] = {"target": target, "sources": {"common_catalogue"}, "attributes": {}}
                else:
                    inventory[key]["sources"].add("common_catalogue")
                for attribute_id in entry.attributes:
                    inventory[key]["attributes"].setdefault(attribute_id, "catalogue_probe")

        object_records: list[dict[str, Any]] = []
        get_success = 0
        get_failed = 0
        profile_result: dict[str, Any] = {
            "name": "public",
            "association": association,
            "identification": {},
            "association_view_object_count": len(objects),
            "association_view_attempt_count": association_view_attempts,
            "objects": object_records,
            "summary": {
                "objects": 0,
                "association_view_objects": len(objects),
                "get_attempted": 0,
                "get_transmissions": 0,
                "get_success": 0,
                "get_failed": 0,
            },
        }
        report["profiles"].append(profile_result)
        get_transmissions = 0
        for (class_id, logical_name), item in sorted(inventory.items(), key=lambda pair: pair[0]):
            target = item["target"]
            object_result = _object_record(target, item["sources"])
            object_records.append(object_result)
            profile_result["summary"]["objects"] = len(object_records)
            if object_result["class_name"] == "GXDLMSObject":
                report["unknown_objects"].append(
                    {
                        "profile": "public",
                        "class_id": class_id,
                        "logical_name": logical_name,
                        "object_version": object_result["object_version"],
                        "source": "association_view",
                    }
                )
            for attribute_id in _ordered_attribute_ids(target, item["attributes"]):
                advertised_access = item["attributes"][attribute_id]
                identity = {
                    "profile": "public",
                    "class_id": class_id,
                    "logical_name": logical_name,
                    "object_version": int(getattr(target, "version", 0)),
                    "attribute_id": attribute_id,
                }
                attribute_result: dict[str, Any] = {
                    "attribute_id": attribute_id,
                    "name": _attribute_name(target, attribute_id),
                    "advertised_access": advertised_access,
                    "lifecycle": "discovered",
                    "outcome": None,
                    "attempt_count": 0,
                    "attempts": [],
                }
                object_result["attributes"].append(attribute_result)

                # Attribute 2 of Association LN has already been read to build
                # this inventory. Preserve it as a successful GET without
                # downloading the potentially large object list twice.
                if class_id == 15 and logical_name == "0.0.40.0.0.255" and attribute_id == 2:
                    attribute_result.update(
                        {
                            "lifecycle": "success",
                            "outcome": Outcome.SUCCESS.value,
                            "attempt_count": 1,
                            "attempts": [{"attempt": 1, "outcome": Outcome.SUCCESS.value}],
                            "decoded": {
                                "value": {"association_object_count": len(objects)},
                                "dlms_data_type": "array",
                            },
                        }
                    )
                    get_success += 1
                    get_transmissions += association_view_attempts
                    profile_result["summary"].update(
                        {
                            "get_attempted": get_success + get_failed,
                            "get_transmissions": get_transmissions,
                            "get_success": get_success,
                            "get_failed": get_failed,
                        }
                    )
                    continue

                last_exception: BaseException | None = None
                for attempt in range(1, config.scan.total_get_attempts + 1):
                    get_transmissions += 1
                    attribute_result["lifecycle"] = "attempted"
                    attribute_result["attempt_count"] = attempt
                    progress(
                        {
                            "phase": "get_scan",
                            "profile": "public",
                            "class_id": class_id,
                            "logical_name": logical_name,
                            "attribute_id": attribute_id,
                            "attempt": attempt,
                            "message": f"GET {logical_name} class {class_id} attribute {attribute_id} ({attempt}/{config.scan.total_get_attempts})",
                        }
                    )
                    try:
                        decoded = session.read_attribute(target, attribute_id, attempt)
                    except Exception as exc:
                        last_exception = exc
                        outcome = classify_exception(exc)
                        attribute_result["attempts"].append(
                            {"attempt": attempt, "outcome": outcome.value, "error": f"{type(exc).__name__}: {exc}"}
                        )
                        report["errors"].append(error_record(exc, phase="get_scan", context={**identity, "attempt": attempt}))
                        progress(
                            {
                                "phase": "get_error",
                                "message": f"GET {logical_name} attribute {attribute_id} failed: {type(exc).__name__}: {exc}",
                            }
                        )
                        if outcome == Outcome.DLMS_ERROR:
                            break
                        continue
                    attribute_result.update(
                        {"lifecycle": "success", "outcome": Outcome.SUCCESS.value, "decoded": decoded}
                    )
                    attribute_result["attempts"].append({"attempt": attempt, "outcome": Outcome.SUCCESS.value})
                    last_exception = None
                    break

                if last_exception is not None:
                    attribute_result.update(
                        {
                            "lifecycle": "failed",
                            "outcome": classify_exception(last_exception).value,
                            "error": f"{type(last_exception).__name__}: {last_exception}",
                        }
                    )
                    get_failed += 1
                else:
                    get_success += 1
                profile_result["summary"].update(
                    {
                        "get_attempted": get_success + get_failed,
                        "get_transmissions": get_transmissions,
                        "get_success": get_success,
                        "get_failed": get_failed,
                    }
                )

            engineering: dict[str, Any] = {}
            for name in ("scaler", "unit"):
                try:
                    value = getattr(target, name)
                except Exception:
                    continue
                if value is not None:
                    engineering[name] = enum_name(value) or value
            if engineering:
                object_result["engineering_metadata"] = engineering

        identification: dict[str, Any] = {}
        identity_names = {
            "0.0.42.0.0.255": "logical_device_name",
            "0.0.96.1.0.255": "serial_number",
            "0.0.96.1.1.255": "serial_number_alternate",
            "1.0.0.2.0.255": "firmware_identifier",
            "0.0.1.0.0.255": "clock",
            "0.0.41.0.0.255": "sap_assignment",
        }
        for obj in object_records:
            key = identity_names.get(obj["logical_name"])
            if not key:
                continue
            for attribute in obj["attributes"]:
                if attribute["attribute_id"] == 2 and attribute["outcome"] == Outcome.SUCCESS.value:
                    identification[key] = attribute.get("decoded", {}).get("value")
                    break

        profile_result["identification"] = identification
        profile_result["summary"].update(
            {
                "objects": len(object_records),
                "get_attempted": get_success + get_failed,
                "get_transmissions": get_transmissions,
                "get_success": get_success,
                "get_failed": get_failed,
            }
        )
        report["run"]["status"] = "completed" if not get_failed else "completed_with_errors"
    except KeyboardInterrupt:
        report["run"]["status"] = "interrupted"
        report["errors"].append(
            {"timestamp": utc_now(), "phase": "scan", "category": "INTERRUPTED", "type": "KeyboardInterrupt", "message": "scan interrupted by user", "context": {}}
        )
    except Exception as exc:
        report["run"]["status"] = "failed"
        error = error_record(exc, phase="scan")
        report["errors"].append(error)
        progress({"phase": "scan_error", "level": "error", "message": error["message"]})
    finally:
        if session is not None:
            for warning in session.close():
                report["errors"].append(
                    {"timestamp": utc_now(), "phase": "finalization", "category": "PROTOCOL_ERROR", "type": "CleanupWarning", "message": warning, "context": {}}
                )
        matrix: list[dict[str, Any]] = []
        for profile in report.get("profiles", []):
            for obj in profile.get("objects", []):
                for attribute in obj.get("attributes", []):
                    matrix.append(
                        {
                            "operation": "GET",
                            "class_id": obj["class_id"],
                            "logical_name": obj["logical_name"],
                            "object_version": obj["object_version"],
                            "attribute_id": attribute["attribute_id"],
                            "profiles": {
                                profile["name"]: {
                                    "outcome": attribute.get("outcome"),
                                    "success": attribute.get("outcome") == Outcome.SUCCESS.value,
                                }
                            },
                        }
                    )
        report["capability_matrix"] = matrix
        report["run"]["finished_at"] = utc_now()
    return report
