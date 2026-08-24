"""DLMS association, authentication, and GET-only scan orchestration."""

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
from .config import (
    AppConfig,
    LlsProfile,
    SERVER_ADDRESSING_TYPES,
    SecureProfile,
    resolve_lls_password,
    resolve_secure_keys,
)
from .counter_state import acquire_counter_lease, counter_identity
from .result_model import Outcome, classify_exception, enum_name, error_record, utc_now

ProgressCallback = Callable[[dict[str, Any]], None]
CONSECUTIVE_TIMEOUTS_BEFORE_RETRY_SUPPRESSION = 2
AUTHENTICATION_MECHANISMS = {
    0: "none",
    1: "low",
    2: "high",
    3: "high_md5",
    4: "high_sha1",
    5: "high_gmac",
    6: "high_sha256",
    7: "high_ecdsa",
}
AUTHENTICATION_DISPLAY_NAMES = {
    "none": "NONE (no authentication)",
    "low": "LLS / LOW",
    "high": "HLS / HIGH",
    "high_md5": "HLS-MD5",
    "high_sha1": "HLS-SHA1",
    "high_gmac": "HLS-GMAC (Suite 0, authenticated + encrypted)",
    "high_sha256": "HLS-SHA256",
    "high_ecdsa": "HLS-ECDSA",
}


class _GetRetryPolicy:
    """Suppress redundant retries while a run of timeouts is in progress."""

    def __init__(self) -> None:
        self.consecutive_timeouts = 0
        self.retries_suppressed = False

    def attempts_for_next_get(self, configured_attempts: int) -> int:
        if self.retries_suppressed:
            return 1
        return configured_attempts

    def record(self, outcome: Outcome) -> None:
        if outcome == Outcome.TIMEOUT:
            self.consecutive_timeouts += 1
            self.retries_suppressed = (
                self.consecutive_timeouts
                >= CONSECUTIVE_TIMEOUTS_BEFORE_RETRY_SUPPRESSION
            )
        else:
            self.reset()

    def reset(self) -> None:
        self.consecutive_timeouts = 0
        self.retries_suppressed = False


class _TimeoutCircuitBreaker:
    """Detect a sustained run of unanswered requests in one scan phase."""

    def __init__(self, threshold: int) -> None:
        self.threshold = threshold
        self.consecutive_timeouts = 0

    @property
    def tripped(self) -> bool:
        return self.consecutive_timeouts >= self.threshold

    def record(self, outcome: Outcome) -> None:
        if outcome == Outcome.TIMEOUT:
            self.consecutive_timeouts += 1
        else:
            self.reset()

    def reset(self) -> None:
        self.consecutive_timeouts = 0


def _set_session_timeout(session: Any, timeout_ms: int) -> bool:
    setter = getattr(session, "set_response_timeout", None)
    if not callable(setter):
        return False
    setter(timeout_ms)
    return True


def _successful_attribute(
    object_record: dict[str, Any], attribute_id: int
) -> dict[str, Any] | None:
    for attribute in object_record.get("attributes", []):
        if (
            attribute.get("attribute_id") == attribute_id
            and attribute.get("outcome") == Outcome.SUCCESS.value
        ):
            return attribute
    return None


def _authentication_mechanism_id(attribute: dict[str, Any] | None) -> int | None:
    if attribute is None:
        return None
    decoded = attribute.get("decoded", {})
    raw = decoded.get("raw_value", {})
    raw_hex = raw.get("hex") if isinstance(raw, dict) else None
    if isinstance(raw_hex, str):
        try:
            value = bytes.fromhex(raw_hex)
        except ValueError:
            value = b""
        # COSEM authentication-mechanism-name OID:
        # 2.16.756.5.8.2.<mechanism-id>
        if len(value) == 7 and value[:6] == bytes.fromhex("608574050802"):
            return int(value[-1])
    display = decoded.get("value", {})
    if isinstance(display, dict):
        display = display.get("display")
    if isinstance(display, str):
        try:
            parts = [int(item) for item in display.split()]
        except ValueError:
            return None
        if len(parts) == 7 and parts[:6] == [0, 0, 0, 5, 8, 2]:
            return parts[-1]
    return None


def _associated_partners(
    attribute: dict[str, Any] | None,
) -> tuple[int | None, int | None]:
    if attribute is None:
        return None, None
    value = attribute.get("decoded", {}).get("value")
    if (
        isinstance(value, list)
        and len(value) >= 2
        and all(isinstance(item, int) and not isinstance(item, bool) for item in value[:2])
    ):
        return int(value[0]), int(value[1])
    return None, None


def _authentication_enumeration(
    object_records: list[dict[str, Any]], association: dict[str, Any]
) -> dict[str, Any]:
    """Summarize verified and Association-LN-advertised authentication methods."""

    advertised: list[dict[str, Any]] = []
    observed: set[str] = set()
    for obj in object_records:
        if int(obj.get("class_id", -1)) != 15:
            continue
        mechanism_attribute = _successful_attribute(obj, 6)
        mechanism_id = _authentication_mechanism_id(mechanism_attribute)
        if mechanism_id is None:
            continue
        mechanism = AUTHENTICATION_MECHANISMS.get(
            mechanism_id, f"unknown_{mechanism_id}"
        )
        client_sap, server_sap = _associated_partners(
            _successful_attribute(obj, 3)
        )
        advertised.append(
            {
                "logical_name": obj.get("logical_name"),
                "client_sap": client_sap,
                "server_sap": server_sap,
                "mechanism_id": mechanism_id,
                "mechanism": mechanism,
                "evidence": "association_ln_attribute_6",
            }
        )
        observed.add(mechanism)

    active_mechanism = str(association.get("authentication", "unknown"))
    if active_mechanism != "unknown":
        observed.add(active_mechanism)
    return {
        "active_verification": {
            "mechanism": active_mechanism,
            "client_sap": association.get("client_address"),
            "association_established": True,
            "hls_validated": association.get("hls_validated"),
        },
        "advertised_associations": advertised,
        "observed_methods": sorted(observed),
        "complete": False,
        "limitation": (
            "Only the active association and readable Association LN objects are "
            "reported; hidden client SAPs and mechanisms are not guessed."
        ),
    }


def _timeout_policy_scope(
    config: AppConfig, *, enumeration_timeout_applied: bool
) -> dict[str, Any]:
    return {
        "validation_timeout_ms": config.transport.response_timeout_ms,
        "enumeration_timeout_ms": config.scan.enumeration_timeout_ms,
        "enumeration_timeout_applied": enumeration_timeout_applied,
        "circuit_breaker_threshold": config.scan.timeout_breaker_threshold,
        "trips": 0,
        "health_check_transmissions": 0,
        "successful_health_checks": 0,
        "failed_health_checks": 0,
        "recoveries_without_reconnect": 0,
        "reconnect_attempts": 0,
        "successful_reconnects": 0,
        "stopped": False,
        "stop_reason": None,
        "last_health_probe": None,
    }


def _health_probe_description(
    health_probe: tuple[str, Any | None, int | None]
) -> dict[str, Any]:
    kind, target, attribute_id = health_probe
    if kind == "association_view":
        return {
            "kind": kind,
            "class_id": 15,
            "logical_name": "0.0.40.0.0.255",
            "attribute_id": 2,
        }
    return {
        "kind": kind,
        "class_id": int(target.objectType),
        "logical_name": str(target.logicalName),
        "attribute_id": int(attribute_id),
    }


def _run_health_probe(
    session: Any,
    health_probe: tuple[str, Any | None, int | None],
    attempt: int,
) -> None:
    kind, target, attribute_id = health_probe
    if kind == "association_view":
        list(session.discover_objects(attempt))
        return
    session.read_attribute(
        target,
        int(attribute_id),
        attempt,
        phase="get_health_check",
        purpose="timeout_circuit_health_check",
    )


def _recover_timeout_circuit(
    session: Any,
    config: AppConfig,
    retry_policy: _GetRetryPolicy,
    circuit: _TimeoutCircuitBreaker,
    health_probe: tuple[str, Any | None, int | None],
    circuit_scope: dict[str, Any],
    report: dict[str, Any],
    progress: ProgressCallback,
    *,
    profile_name: str,
    phase: str,
) -> tuple[bool, int]:
    """Probe and, if necessary, reconnect after the timeout threshold."""

    if not circuit.tripped:
        return True, 0

    transmissions = 0
    circuit_scope["trips"] += 1
    circuit_scope["last_health_probe"] = _health_probe_description(health_probe)
    progress(
        {
            "phase": "timeout_circuit_open",
            "profile": profile_name,
            "consecutive_timeouts": circuit.consecutive_timeouts,
            "message": (
                f"Timeout circuit opened after {circuit.consecutive_timeouts} "
                "unanswered requests; checking a known-good GET"
            ),
        }
    )

    def probe(label: str) -> bool:
        nonlocal transmissions
        transmissions += 1
        circuit_scope["health_check_transmissions"] += 1
        try:
            _run_health_probe(session, health_probe, 1)
        except Exception as exc:
            circuit_scope["failed_health_checks"] += 1
            report["errors"].append(
                error_record(
                    exc,
                    phase=phase,
                    context={
                        "operation": "GET_HEALTH_CHECK",
                        "stage": label,
                        **_health_probe_description(health_probe),
                    },
                )
            )
            progress(
                {
                    "phase": "timeout_health_check_failed",
                    "profile": profile_name,
                    "message": f"Known-good GET failed: {type(exc).__name__}: {exc}",
                }
            )
            return False
        circuit_scope["successful_health_checks"] += 1
        return True

    if probe("before_reconnect"):
        circuit.reset()
        retry_policy.reset()
        circuit_scope["recoveries_without_reconnect"] += 1
        progress(
            {
                "phase": "timeout_circuit_recovered",
                "profile": profile_name,
                "message": "Known-good GET succeeded; resuming the scan",
            }
        )
        return True, transmissions

    reconnect = getattr(session, "reconnect", None)
    if not callable(reconnect):
        circuit_scope["stopped"] = True
        circuit_scope["stop_reason"] = "session does not support reconnect"
        return False, transmissions

    circuit_scope["reconnect_attempts"] += 1
    progress(
        {
            "phase": "timeout_reconnect",
            "profile": profile_name,
            "message": "Known-good GET also failed; reconnecting once",
        }
    )
    try:
        _set_session_timeout(session, config.transport.response_timeout_ms)
        reconnect()
    except Exception as exc:
        _set_session_timeout(session, config.scan.enumeration_timeout_ms)
        circuit_scope["stopped"] = True
        circuit_scope["stop_reason"] = f"reconnect failed: {type(exc).__name__}: {exc}"
        report["errors"].append(
            error_record(exc, phase=phase, context={"operation": "RECONNECT"})
        )
        progress(
            {
                "phase": "timeout_reconnect_failed",
                "profile": profile_name,
                "message": circuit_scope["stop_reason"],
            }
        )
        return False, transmissions

    _set_session_timeout(session, config.scan.enumeration_timeout_ms)
    circuit_scope["successful_reconnects"] += 1
    if probe("after_reconnect"):
        circuit.reset()
        retry_policy.reset()
        progress(
            {
                "phase": "timeout_circuit_recovered",
                "profile": profile_name,
                "message": "Reconnect and known-good GET succeeded; resuming the scan",
            }
        )
        return True, transmissions

    circuit_scope["stopped"] = True
    circuit_scope["stop_reason"] = "known-good GET failed after reconnect"
    progress(
        {
            "phase": "timeout_circuit_stopped",
            "profile": profile_name,
            "message": "Meter remained unresponsive after reconnect; remaining GETs are inconclusive",
        }
    )
    return False, transmissions


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


def _attribute_access_rights(
    target: Any, attribute_id: int, association_version: int
) -> dict[str, Any]:
    if association_version >= 3:
        mode = int(target.getAccess3(attribute_id))
        base = mode & 0x03
        requirements = [
            name
            for bit, name in (
                (0x04, "authenticated_request"),
                (0x08, "encrypted_request"),
                (0x10, "digitally_signed_request"),
                (0x20, "authenticated_response"),
                (0x40, "encrypted_response"),
                (0x80, "digitally_signed_response"),
            )
            if mode & bit
        ]
        return {
            "advertised": True,
            "read": base in (1, 3),
            "write": base in (2, 3),
            "requires_authentication": bool(mode & 0x04),
            "requirements": requirements,
            "mode": f"access3:0x{mode:02X}",
            "raw": mode,
        }
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
    return {
        "advertised": True,
        "read": mode in (1, 3, 4, 6),
        "write": mode in (2, 3, 5, 6),
        "requires_authentication": mode in (4, 5, 6),
        "requirements": ["authenticated_request"] if mode in (4, 5, 6) else [],
        "mode": names.get(mode, f"mode_{mode}"),
        "raw": mode,
    }


def _advertised_attributes(target: Any, association_version: int) -> dict[int, dict[str, Any]]:
    explicit = {int(item.index) for item in getattr(target, "attributes", ())}
    explicit.add(1)  # the logical-name attribute is implicitly readable
    if len(explicit) == 1:
        try:
            explicit.update(range(1, int(target.getAttributeCount()) + 1))
        except Exception:
            pass
    advertised: dict[int, dict[str, Any]] = {}
    for attribute_id in sorted(explicit):
        advertised[attribute_id] = _attribute_access_rights(
            target, attribute_id, association_version
        )
    return advertised


def _ordered_attribute_ids(target: Any, attributes: dict[int, Any]) -> list[int]:
    """Honor interface-class read order (notably scaler/unit before value)."""

    preferred: list[int] = []
    try:
        preferred = [int(item) for item in target.getAttributeIndexToRead(True)]
    except Exception:
        pass
    ordered = [item for item in preferred if item in attributes]
    ordered.extend(item for item in sorted(attributes) if item not in ordered)
    return ordered


def _method_name(target: Any, method_id: int) -> str | None:
    try:
        names = target.getMethodNames()
    except Exception:
        return None
    if 0 < method_id <= len(names):
        return str(names[method_id - 1])
    return None


def _method_access_rights(item: Any, association_version: int) -> dict[str, Any]:
    if association_version >= 3:
        mode = int(getattr(item, "methodAccess3", 0))
        requirements = [
            name
            for bit, name in (
                (0x04, "authenticated_request"),
                (0x08, "encrypted_request"),
                (0x10, "digitally_signed_request"),
                (0x40, "encrypted_response"),
                (0x80, "digitally_signed_response"),
            )
            if mode & bit
        ]
        return {
            "action": bool(mode & 0x01),
            "requires_authentication": bool(mode & 0x04),
            "requirements": requirements,
            "mode": f"method_access3:0x{mode:02X}",
            "raw": mode,
        }
    mode = int(getattr(item, "methodAccess", 0))
    return {
        "action": mode in (1, 2),
        "requires_authentication": mode == 2,
        "requirements": ["authenticated_request"] if mode == 2 else [],
        "mode": {
            0: "none",
            1: "access",
            2: "authenticated_access",
        }.get(mode, f"mode_{mode}"),
        "raw": mode,
    }


def _object_record(
    target: Any, sources: set[str], association_version: int
) -> dict[str, Any]:
    methods = []
    for item in getattr(target, "methodAttributes", ()):
        method_id = int(item.index)
        rights = _method_access_rights(item, association_version)
        methods.append(
            {
                "method_id": method_id,
                "name": _method_name(target, method_id),
                "advertised_access": rights["mode"],
                "access_rights": rights,
                "advertised_operations": ["ACTION"] if rights["action"] else [],
                "status": "advertised" if rights["action"] else "not_advertised",
                "tested": False,
                "note": "Passive Association View evidence; ACTION was not sent",
            }
        )
    return {
        "class_id": int(target.objectType),
        "class_name": _class_name(target),
        "logical_name": str(target.logicalName),
        "object_version": int(getattr(target, "version", 0)),
        "description": str(getattr(target, "description", "") or ""),
        "discovery_sources": sorted(sources),
        "attributes": [],
        "methods": methods,
    }


def _baud_rates(config: AppConfig) -> tuple[int, ...]:
    if config.transport.baudrate == "auto":
        return config.transport.baudrate_candidates
    return (int(config.transport.baudrate),)


def _record_cleanup_warnings(
    report: dict[str, Any], warnings: list[str], *, phase: str
) -> None:
    for warning in warnings:
        report["errors"].append(
            {
                "timestamp": utc_now(),
                "phase": phase,
                "category": Outcome.PROTOCOL_ERROR.value,
                "type": "CleanupWarning",
                "message": warning,
                "context": {},
            }
        )


def _discover_association_view(
    session: Any,
    config: AppConfig,
    report: dict[str, Any],
    progress: ProgressCallback,
    *,
    error_phase: str,
) -> tuple[list[Any], int, BaseException | None]:
    objects: list[Any] = []
    last_error: BaseException | None = None
    attempts = 0
    for attempt in range(1, config.scan.total_get_attempts + 1):
        attempts = attempt
        try:
            objects = list(session.discover_objects(attempt))
            last_error = None
            break
        except Exception as exc:
            last_error = exc
            report["errors"].append(
                error_record(
                    exc,
                    phase=error_phase,
                    context={
                        "operation": "GET",
                        "logical_name": "0.0.40.0.0.255",
                        "attribute_id": 2,
                        "attempt": attempt,
                    },
                )
            )
            progress(
                {
                    "phase": "association_view_error",
                    "message": (
                        f"Association-view attempt {attempt} failed: "
                        f"{type(exc).__name__}: {exc}"
                    ),
                }
            )
            if classify_exception(exc) == Outcome.DLMS_ERROR:
                break
    return objects, attempts, last_error


def _objects_from_association_snapshot(
    session: Any, snapshot: dict[str, Any]
) -> tuple[list[Any], dict[tuple[int, str], dict[int, dict[str, Any]]]]:
    """Rebuild Gurux objects and access metadata from a saved view."""

    objects: list[Any] = []
    advertised: dict[tuple[int, str], dict[int, dict[str, Any]]] = {}
    association_version = next(
        (
            int(item.get("object_version", 0))
            for item in snapshot.get("objects", [])
            if int(item.get("class_id", -1)) == 15
            and item.get("logical_name") == "0.0.40.0.0.255"
        ),
        2,
    )
    for item in snapshot.get("objects", []):
        class_id = int(item["class_id"])
        logical_name = str(item["logical_name"])
        target = session.create_object(class_id, logical_name)
        target.version = int(item.get("object_version", 0))
        target.description = str(item.get("description", "") or "")
        rights_by_attribute: dict[int, dict[str, Any]] = {}
        for attribute in item.get("attributes", []):
            attribute_id = int(attribute["attribute_id"])
            rights = dict(attribute.get("access_rights", {}))
            rights_by_attribute[attribute_id] = rights
            raw = rights.get("raw")
            if raw is not None:
                setter_name = "setAccess3" if association_version >= 3 else "setAccess"
                setter = getattr(target, setter_name, None)
                if callable(setter):
                    setter(attribute_id, int(raw))
        for method in item.get("methods", []):
            method_id = int(method["method_id"])
            raw = method.get("access_rights", {}).get("raw")
            if raw is not None:
                setter_name = (
                    "setMethodAccess3" if association_version >= 3 else "setMethodAccess"
                )
                setter = getattr(target, setter_name, None)
                if callable(setter):
                    setter(method_id, int(raw))
        objects.append(target)
        advertised[(class_id, logical_name)] = rights_by_attribute
    return objects, advertised


def _public_access_rights(
    objects: list[Any],
) -> tuple[set[tuple[int, str]], dict[tuple[tuple[int, str], int], dict[str, Any]]]:
    """Return objects and attribute rights advertised to the public role."""

    version = _association_version(objects)
    object_keys: set[tuple[int, str]] = set()
    capabilities: dict[tuple[tuple[int, str], int], dict[str, Any]] = {}
    for target in objects:
        key = (int(target.objectType), str(target.logicalName))
        object_keys.add(key)
        for attribute_id, rights in _advertised_attributes(target, version).items():
            capabilities[(key, attribute_id)] = rights
    return object_keys, capabilities


def _public_union_candidates(
    inventory: dict[tuple[int, str], dict[str, Any]],
    public_objects: set[tuple[int, str]],
    public_capabilities: dict[tuple[tuple[int, str], int], dict[str, Any]],
    *,
    source_profile: str,
) -> list[dict[str, Any]]:
    """Map authenticated-readable attributes not advertised as publicly readable."""

    candidates: list[dict[str, Any]] = []
    for key, item in sorted(inventory.items(), key=lambda pair: pair[0]):
        if "association_view" not in item["sources"]:
            continue
        target = item["target"]
        for attribute_id in _ordered_attribute_ids(target, item["attributes"]):
            # The Association View already identifies every object by its
            # logical-name attribute. Do not probe that same value again.
            if attribute_id == 1:
                continue
            rights = item["attributes"][attribute_id]
            if not (rights.get("advertised") and rights.get("read")):
                continue
            public_rights = public_capabilities.get((key, attribute_id))
            if (
                public_rights is not None
                and public_rights.get("read")
                and not public_rights.get("requirements")
            ):
                continue
            candidates.append(
                {
                    "class_id": key[0],
                    "logical_name": key[1],
                    "object_version": int(getattr(target, "version", 0)),
                    "attribute_id": attribute_id,
                    "name": _attribute_name(target, attribute_id),
                    "source_profiles": [source_profile],
                    "source_advertised_access": rights["mode"],
                    "public_object_advertised": key in public_objects,
                    "public_advertised_access": (
                        public_rights.get("mode") if public_rights else None
                    ),
                    "public_advertised": public_rights is not None,
                }
            )
    return candidates


def _run_public_union_gets(
    session: Any,
    candidates: list[dict[str, Any]],
    config: AppConfig,
    report: dict[str, Any],
    progress: ProgressCallback,
    *,
    candidate_count: int | None = None,
) -> dict[str, Any]:
    results: list[dict[str, Any]] = []
    unexpected_access = rejected = inconclusive = transmissions = 0
    retry_policy = _GetRetryPolicy()
    timeout_circuit = _TimeoutCircuitBreaker(
        config.scan.timeout_breaker_threshold
    )
    enumeration_timeout_applied = _set_session_timeout(
        session, config.scan.enumeration_timeout_ms
    )
    circuit_scope = _timeout_policy_scope(
        config, enumeration_timeout_applied=enumeration_timeout_applied
    )
    health_probe: tuple[str, Any | None, int | None] = (
        "association_view",
        None,
        None,
    )
    candidate_count = len(candidates) if candidate_count is None else candidate_count
    progress(
        {
            "phase": "public_union_plan",
            "total": len(candidates),
            "message": (
                f"Testing {len(candidates)} of {candidate_count} additional "
                "authenticated GET targets as public"
            ),
        }
    )
    for candidate_index, candidate in enumerate(candidates):
        result = {**candidate, "attempt_count": 0, "attempts": []}
        target = session.create_object(candidate["class_id"], candidate["logical_name"])
        last_exception: BaseException | None = None
        allowed_attempts = retry_policy.attempts_for_next_get(
            config.scan.total_get_attempts
        )
        result["retry_suppressed"] = allowed_attempts == 1
        for attempt in range(1, allowed_attempts + 1):
            transmissions += 1
            result["attempt_count"] = attempt
            progress(
                {
                    "phase": "public_union_get",
                    **candidate,
                    "attempt": attempt,
                    "message": (
                        f"Public GET {candidate['logical_name']} class {candidate['class_id']} "
                        f"attribute {candidate['attribute_id']} ({attempt}/{allowed_attempts})"
                    ),
                }
            )
            try:
                decoded = session.read_attribute(
                    target,
                    candidate["attribute_id"],
                    attempt,
                    phase="public_union_test",
                    purpose="cross_profile_access_test",
                )
            except Exception as exc:
                last_exception = exc
                outcome = classify_exception(exc)
                retry_policy.record(outcome)
                timeout_circuit.record(outcome)
                result["attempts"].append(
                    {
                        "attempt": attempt,
                        "outcome": outcome.value,
                        "error": f"{type(exc).__name__}: {exc}",
                    }
                )
                if outcome == Outcome.DLMS_ERROR:
                    break
                continue
            result.update(
                {
                    "outcome": Outcome.SUCCESS.value,
                    "access_assessment": "UNEXPECTED_PUBLIC_ACCESS",
                    "unexpected_public_access": True,
                    "decoded": decoded,
                }
            )
            result["attempts"].append(
                {"attempt": attempt, "outcome": Outcome.SUCCESS.value}
            )
            retry_policy.record(Outcome.SUCCESS)
            timeout_circuit.record(Outcome.SUCCESS)
            health_probe = ("attribute", target, candidate["attribute_id"])
            last_exception = None
            unexpected_access += 1
            break

        if last_exception is not None:
            outcome = classify_exception(last_exception)
            result.update(
                {
                    "outcome": outcome.value,
                    "access_assessment": (
                        "PUBLIC_ACCESS_REJECTED"
                        if outcome == Outcome.DLMS_ERROR
                        else "INCONCLUSIVE"
                    ),
                    "unexpected_public_access": False,
                    "error": f"{type(last_exception).__name__}: {last_exception}",
                }
            )
            if outcome == Outcome.DLMS_ERROR:
                rejected += 1
            else:
                inconclusive += 1
                report["errors"].append(
                    error_record(
                        last_exception,
                        phase="public_union_test",
                        context={
                            "operation": "GET",
                            "class_id": candidate["class_id"],
                            "logical_name": candidate["logical_name"],
                            "attribute_id": candidate["attribute_id"],
                        },
                    )
                )
        results.append(result)
        progress(
            {
                "phase": "public_union_complete",
                **candidate,
                "outcome": result["outcome"],
            }
        )

        if (
            last_exception is not None
            and classify_exception(last_exception) == Outcome.TIMEOUT
            and timeout_circuit.tripped
        ):
            recovered, probe_transmissions = _recover_timeout_circuit(
                session,
                config,
                retry_policy,
                timeout_circuit,
                health_probe,
                circuit_scope,
                report,
                progress,
                profile_name="public",
                phase="public_union_timeout_circuit",
            )
            transmissions += probe_transmissions
            if not recovered:
                for remaining in candidates[candidate_index + 1 :]:
                    remaining_result = {
                        **remaining,
                        "attempt_count": 0,
                        "attempts": [],
                        "outcome": Outcome.INCONCLUSIVE.value,
                        "access_assessment": "INCONCLUSIVE",
                        "unexpected_public_access": False,
                        "inconclusive_reason": circuit_scope["stop_reason"],
                    }
                    results.append(remaining_result)
                    inconclusive += 1
                    progress(
                        {
                            "phase": "public_union_complete",
                            **remaining,
                            "outcome": Outcome.INCONCLUSIVE.value,
                        }
                    )
                break

    return {
        "status": "inconclusive" if inconclusive else "completed",
        "candidate_gets": candidate_count,
        "selected_gets": len(candidates),
        "attempted_gets": sum(item["attempt_count"] > 0 for item in results),
        "get_transmissions": transmissions,
        "unexpected_public_access": unexpected_access,
        "public_access_rejected": rejected,
        "inconclusive": inconclusive,
        "timeout_policy": circuit_scope,
        "results": results,
    }


def _server_address_candidates(config: AppConfig) -> tuple[dict[str, Any], ...]:
    """Return bounded one- and two-byte server-address forms to probe."""

    profile = config.profile
    logical = profile.server_logical_address
    physical = profile.server_physical_address
    configured_size = profile.server_address_size
    candidates: list[tuple[int, int, int]] = []

    if configured_size != "auto":
        candidates.append((logical, physical, int(configured_size)))
    else:
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
                "server_addressing_type": SERVER_ADDRESSING_TYPES[address_size],
            }
        )
    return tuple(unique)


def _authentication_probe_record(
    mechanism: str,
    *,
    session: Any | None = None,
    association: dict[str, Any] | None = None,
    error: BaseException | None = None,
    supported: bool = True,
    attempted: bool | None = None,
    security_policy: str = "none",
) -> dict[str, Any]:
    attempted = supported if attempted is None else attempted
    aarq_accepted = bool(
        association is not None or getattr(session, "aarq_accepted", False)
    )
    if not supported:
        status = "unsupported"
    elif not attempted:
        status = "prerequisite_failed"
    elif association is not None:
        status = "authenticated"
    elif aarq_accepted:
        status = "hls_validation_failed"
    else:
        status = "rejected"
    return {
        "mechanism": mechanism,
        "supported_by_tool": supported,
        "attempted": attempted,
        "status": status,
        "aarq_accepted": aarq_accepted if attempted else None,
        "fully_authenticated": association is not None if attempted else None,
        "security_policy": security_policy,
        "outcome": (
            Outcome.SUCCESS.value
            if association is not None
            else Outcome.NOT_TESTED.value
            if not attempted
            else classify_exception(error or RuntimeError(status)).value
        ),
        "association": association,
        "error": (
            f"{type(error).__name__}: {error}" if error is not None else None
        ),
    }


def run_authentication_scan(
    config: AppConfig,
    traffic: Any,
    *,
    transport: dict[str, Any],
    meter_identity: str | None,
    counter_candidates: tuple[Any, ...] | list[Any],
    progress: ProgressCallback,
) -> dict[str, Any]:
    """Probe one configured role after its ordinary scan has completed."""

    from gurux_dlms.enums import Authentication

    from .gurux_adapter import (
        GuruxAuthenticationProbeSession,
        GuruxSecureSession,
        GuruxSession,
    )

    profile = config.profile
    if not config.authentication_scan.enabled:
        raise ValueError("authentication scanning is not enabled")
    password = resolve_lls_password(config.authentication_scan)

    endpoint = {
        "server_logical_address": int(
            transport["selected_server_logical_address"]
        ),
        "server_physical_address": int(
            transport["selected_server_physical_address"]
        ),
        "server_address_size": int(transport["server_address_size"]),
    }
    baudrate = int(transport["selected_baudrate"])
    report: dict[str, Any] = {"errors": []}
    meter_counter: int | None = None
    counter_error: BaseException | None = None
    if isinstance(profile, SecureProfile):
        configured_counter = profile.invocation_counter
        selected_counter = next(
            (
                item
                for item in counter_candidates
                if int(item.class_id) == configured_counter.class_id
                and item.logical_name == configured_counter.logical_name
                and int(item.attribute_id) == configured_counter.attribute_id
            ),
            None,
        )
        if selected_counter is not None:
            meter_counter = int(selected_counter.value)
        elif configured_counter.unsafe_override is None:
            counter_error = RuntimeError(
                "validated public invocation-counter value is unavailable"
            )

    results: list[dict[str, Any]] = []
    mechanisms = (
        ("none", None),
        ("low", Authentication.LOW),
        ("high", Authentication.HIGH),
        ("high_md5", Authentication.HIGH_MD5),
        ("high_sha1", Authentication.HIGH_SHA1),
        ("high_sha256", Authentication.HIGH_SHA256),
    )
    authentication_probe_total = len(mechanisms) + 1
    for sequence, (mechanism, authentication) in enumerate(mechanisms, 1):
        display_name = AUTHENTICATION_DISPLAY_NAMES[mechanism]
        progress(
            {
                "phase": "authentication_scan_attempt",
                "role": profile.role,
                "client_address": profile.client_address,
                "mechanism": mechanism,
                "sequence": sequence,
                "total": authentication_probe_total,
                "message": (
                    f"Testing {profile.role} / client {profile.client_address} / "
                    f"{display_name}"
                ),
            }
        )
        probe = None
        try:
            if authentication is None:
                probe = GuruxSession(
                    config,
                    baudrate,
                    traffic,
                    client_address=profile.client_address,
                    profile_name=profile.role,
                    **endpoint,
                )
            else:
                probe = GuruxAuthenticationProbeSession(
                    config,
                    baudrate,
                    traffic,
                    authentication,
                    client_address=profile.client_address,
                    profile_name=profile.role,
                    password=password,
                    client_system_title=(
                        profile.client_system_title
                        if isinstance(profile, SecureProfile)
                        else None
                    ),
                    **endpoint,
                )
            association = probe.connect()
            result = _authentication_probe_record(
                mechanism, session=probe, association=association
            )
        except Exception as exc:
            result = _authentication_probe_record(
                mechanism, session=probe, error=exc
            )
        finally:
            if probe is not None:
                _record_cleanup_warnings(
                    report,
                    probe.close(),
                    phase=f"authentication_scan_{mechanism}_finalization",
                )
        results.append(result)
        progress(
            {
                "phase": "authentication_scan_result",
                "role": profile.role,
                "client_address": profile.client_address,
                "mechanism": mechanism,
                "status": result["status"],
                "sequence": sequence,
                "total": authentication_probe_total,
                "message": (
                    f"{profile.role} / client {profile.client_address} / "
                    f"{display_name}: {result['status']}"
                ),
            }
        )

    progress(
        {
            "phase": "authentication_scan_attempt",
            "role": profile.role,
            "client_address": profile.client_address,
            "mechanism": "high_gmac",
            "sequence": authentication_probe_total,
            "total": authentication_probe_total,
            "message": (
                f"Testing {profile.role} / client {profile.client_address} / "
                f"{AUTHENTICATION_DISPLAY_NAMES['high_gmac']}"
            ),
        }
    )
    gmac_session = None
    counter_lease = None
    counter_refreshes: list[dict[str, Any]] = []
    gmac_attempts: list[dict[str, Any]] = []

    def refresh_meter_counter() -> int | None:
        if not isinstance(profile, SecureProfile):
            return None
        refresh_session = None
        progress(
            {
                "phase": "authentication_counter_refresh",
                "role": profile.role,
                "message": (
                    f"Refreshing the public invocation counter for {profile.role}"
                ),
            }
        )
        try:
            refresh_session = GuruxSession(
                config,
                baudrate,
                traffic,
                client_address=profile.invocation_counter.public_client_address,
                profile_name=f"{profile.role}_counter_refresh",
                **endpoint,
            )
            refresh_session.connect()
            value = refresh_session.read_invocation_counter(profile)
            counter_refreshes.append({"status": "success", "value": value})
            return value
        except Exception as exc:
            counter_refreshes.append(
                {
                    "status": "failed",
                    "error": f"{type(exc).__name__}: {exc}",
                }
            )
            return None
        finally:
            if refresh_session is not None:
                _record_cleanup_warnings(
                    report,
                    refresh_session.close(),
                    phase="authentication_counter_refresh_finalization",
                )

    try:
        if not isinstance(profile, SecureProfile):
            raise RuntimeError(
                "HIGH_GMAC requires an hls_gmac_suite0 role with system title and keys"
            )
        refreshed_counter = refresh_meter_counter()
        if refreshed_counter is not None:
            meter_counter = refreshed_counter
            counter_error = None
        if counter_error is not None and profile.invocation_counter.unsafe_override is None:
            raise RuntimeError(
                "public invocation-counter bootstrap failed; high_gmac cannot be tested"
            ) from counter_error
        if meter_identity is None:
            raise RuntimeError(
                "meter identity is unavailable; high_gmac counter state cannot be isolated"
            )
        identity = counter_identity(
            meter_identity=meter_identity,
            client_system_title=profile.client_system_title,
            client_address=profile.client_address,
            server_address=int(transport["selected_server_address"]),
        )
        counter_lease = acquire_counter_lease(
            profile.invocation_counter.state_file,
            identity,
            meter_reported_counter=meter_counter,
            unsafe_override=profile.invocation_counter.unsafe_override,
        )
        gak, guek = resolve_secure_keys(profile)
        association = None
        gmac_error = None
        for attempt in (1, 2):
            if attempt > 1:
                progress(
                    {
                        "phase": "authentication_scan_retry",
                        "role": profile.role,
                        "mechanism": "high_gmac",
                        "attempt": attempt,
                        "message": (
                            f"Retrying {profile.role} HLS-GMAC with a freshly "
                            "bootstrapped counter"
                        ),
                    }
                )
            gmac_session = GuruxSecureSession(
                config,
                baudrate,
                traffic,
                counter_lease,
                gak,
                guek,
                **endpoint,
            )
            try:
                association = gmac_session.connect()
            except Exception as exc:
                gmac_error = exc
                aarq_accepted = bool(getattr(gmac_session, "aarq_accepted", False))
                gmac_attempts.append(
                    {
                        "attempt": attempt,
                        "status": (
                            "hls_validation_failed" if aarq_accepted else "rejected"
                        ),
                        "error": f"{type(exc).__name__}: {exc}",
                    }
                )
                if aarq_accepted or attempt == 2:
                    break
                _record_cleanup_warnings(
                    report,
                    gmac_session.close(),
                    phase="authentication_scan_high_gmac_retry_finalization",
                )
                gmac_session = None
                refreshed_counter = refresh_meter_counter()
                if refreshed_counter is not None:
                    counter_lease.persist_next(
                        max(counter_lease.next_counter, refreshed_counter + 1)
                    )
            else:
                gmac_attempts.append(
                    {"attempt": attempt, "status": "authenticated", "error": None}
                )
                break
        gmac_result = _authentication_probe_record(
            "high_gmac",
            session=gmac_session,
            association=association,
            error=gmac_error if association is None else None,
            security_policy="authentication_encryption",
        )
    except Exception as exc:
        gmac_result = _authentication_probe_record(
            "high_gmac",
            session=gmac_session,
            error=exc,
            attempted=isinstance(profile, SecureProfile) and gmac_session is not None,
            security_policy="authentication_encryption",
        )
    finally:
        if gmac_session is not None:
            _record_cleanup_warnings(
                report,
                gmac_session.close(),
                phase="authentication_scan_high_gmac_finalization",
            )
        if counter_lease is not None:
            counter_lease.close()
    gmac_result["attempt_count"] = len(gmac_attempts)
    gmac_result["attempts"] = gmac_attempts
    gmac_result["counter_refreshes"] = counter_refreshes
    results.append(gmac_result)
    progress(
        {
            "phase": "authentication_scan_result",
            "role": profile.role,
            "client_address": profile.client_address,
            "mechanism": "high_gmac",
            "status": gmac_result["status"],
            "sequence": authentication_probe_total,
            "total": authentication_probe_total,
            "message": (
                f"{profile.role} / client {profile.client_address} / "
                f"{AUTHENTICATION_DISPLAY_NAMES['high_gmac']}: "
                f"{gmac_result['status']}"
            ),
        }
    )

    results.append(
        _authentication_probe_record(
            "high_ecdsa", supported=False, security_policy="implementation_defined"
        )
    )
    accepted = [
        item["mechanism"] for item in results if item["fully_authenticated"] is True
    ]
    return {
        "name": profile.name,
        "role": profile.role,
        "client_address": profile.client_address,
        "authentication_scan": {
            "results": results,
            "accepted_mechanisms": accepted,
            "complete": True,
            "high_ecdsa_limitation": (
                "Not attempted because signing-key and certificate credentials are not supported."
            ),
        },
        "errors": report["errors"],
    }


def scan_public(
    config: AppConfig,
    traffic: Any,
    *,
    progress: ProgressCallback | None = None,
    invocation_counter_reuse_test: bool = False,
    association_view_mode: str = "live",
    association_view_snapshot: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Run the configured public, LLS, or secure read-only scan."""

    progress = progress or (lambda _: None)
    started_at = utc_now()
    run_id = started_at.replace("-", "").replace(":", "").replace(".", "")
    if association_view_mode not in {"live", "reuse", "compare"}:
        raise ValueError("association_view_mode must be live, reuse, or compare")
    if association_view_mode in {"reuse", "compare"} and association_view_snapshot is None:
        raise ValueError(f"Association View mode {association_view_mode!r} requires a snapshot")
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
            "validation_response_timeout_ms": config.transport.response_timeout_ms,
            "enumeration_response_timeout_ms": config.scan.enumeration_timeout_ms,
        },
        "profiles": [],
        "association_view": {
            "mode": association_view_mode,
            "source": "saved_snapshot" if association_view_mode == "reuse" else "meter",
            "snapshot_saved_at": (
                association_view_snapshot.get("saved_at")
                if association_view_snapshot is not None
                else None
            ),
        },
        "capability_matrix": [],
        "public_union_test": {
            "enabled": config.scan.union_profile_test,
            "status": "pending" if config.scan.union_profile_test else "disabled",
        },
        "unknown_objects": [],
        "errors": [],
    }
    session = None
    secure_session = None
    counter_lease = None
    association: dict[str, Any] = {}
    objects: list[Any] = []
    public_objects: set[tuple[int, str]] | None = None
    public_capabilities: dict[tuple[tuple[int, str], int], dict[str, Any]] | None = None
    union_candidates: list[dict[str, Any]] | None = None
    cached_access: dict[tuple[int, str], dict[int, dict[str, Any]]] = {}

    try:
        progress({"phase": "scan_start"})
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
                candidate_arguments: dict[str, Any] = {
                    "server_logical_address": endpoint["logical_address"],
                    "server_physical_address": endpoint["physical_address"],
                    "server_address_size": endpoint["address_size"],
                }
                if isinstance(config.profile, SecureProfile):
                    candidate_arguments.update(
                        {
                            "client_address": config.profile.invocation_counter.public_client_address,
                            "profile_name": "public",
                        }
                    )
                if isinstance(config.profile, LlsProfile):
                    from .gurux_adapter import GuruxLlsSession

                    candidate = GuruxLlsSession(
                        config, baudrate, traffic, **candidate_arguments
                    )
                else:
                    candidate = GuruxSession(
                        config, baudrate, traffic, **candidate_arguments
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
            raise RuntimeError(
                "no baud rate and server-address combination produced a valid "
                f"{config.profile.name} DLMS association"
            )

        profile_name = config.profile.role
        if isinstance(config.profile, SecureProfile):
            from .gurux_adapter import GuruxSecureSession

            bootstrap_session = session
            endpoint = {
                "logical_address": report["transport"]["selected_server_logical_address"],
                "physical_address": report["transport"]["selected_server_physical_address"],
                "address_size": report["transport"]["server_address_size"],
                "server_address": report["transport"]["selected_server_address"],
            }
            progress(
                {
                    "phase": "invocation_counter_bootstrap",
                    "message": "Reading meter identity and invocation counter through the public association",
                }
            )
            if config.scan.union_profile_test:
                progress(
                    {
                        "phase": "public_union_inventory",
                        "message": "Reading the public Association View for cross-profile comparison",
                    }
                )
                public_view_objects, public_view_attempts, public_view_error = (
                    _discover_association_view(
                        bootstrap_session,
                        config,
                        report,
                        progress,
                        error_phase="public_union_reconnaissance",
                    )
                )
                if public_view_error is None:
                    public_objects, public_capabilities = _public_access_rights(
                        public_view_objects
                    )
                    report["public_union_test"].update(
                        {
                            "status": "inventory_complete",
                            "public_association": association.copy(),
                            "public_association_view_objects": len(public_view_objects),
                            "public_association_view_attempts": public_view_attempts,
                        }
                    )
                else:
                    report["public_union_test"].update(
                        {
                            "status": "public_inventory_failed",
                            "error": f"{type(public_view_error).__name__}: {public_view_error}",
                            "results": [],
                        }
                    )
            meter_identity = config.profile.invocation_counter.meter_identity
            if meter_identity is None:
                meter_identity = bootstrap_session.read_meter_identity()
            meter_counter: int | None
            try:
                meter_counter = bootstrap_session.read_invocation_counter(config.profile)
            except Exception as exc:
                if config.profile.invocation_counter.unsafe_override is None:
                    raise RuntimeError(
                        "public invocation-counter bootstrap failed; configure the advanced "
                        "invocation_counter.unsafe_override only if a safe next value is known"
                    ) from exc
                meter_counter = None
                report["errors"].append(
                    error_record(
                        exc,
                        phase="invocation_counter_bootstrap",
                        context={"override_used": True},
                    )
                )
                progress(
                    {
                        "phase": "invocation_counter_bootstrap_warning",
                        "message": "Public counter read failed; using the explicitly configured unsafe override",
                    }
                )
            _record_cleanup_warnings(
                report,
                bootstrap_session.close(),
                phase="public_bootstrap_finalization",
            )
            session = None

            identity = counter_identity(
                meter_identity=meter_identity,
                client_system_title=config.profile.client_system_title,
                client_address=config.profile.client_address,
                server_address=int(endpoint["server_address"]),
            )
            counter_lease = acquire_counter_lease(
                config.profile.invocation_counter.state_file,
                identity,
                meter_reported_counter=meter_counter,
                unsafe_override=config.profile.invocation_counter.unsafe_override,
            )
            starting_counter = counter_lease.next_counter
            gak, guek = resolve_secure_keys(config.profile)
            secure_session = GuruxSecureSession(
                config,
                int(report["transport"]["selected_baudrate"]),
                traffic,
                counter_lease,
                gak,
                guek,
                server_logical_address=int(endpoint["logical_address"]),
                server_physical_address=int(endpoint["physical_address"]),
                server_address_size=int(endpoint["address_size"]),
            )
            session = secure_session
            association = secure_session.connect()
            association["invocation_counter_bootstrap"] = {
                "meter_reported_counter": meter_counter,
                "first_secure_counter": starting_counter,
                "strictly_greater_than_meter": (
                    starting_counter > meter_counter if meter_counter is not None else None
                ),
                "unsafe_override_used": meter_counter is None,
                "counter_identity_key": counter_lease.identity_key,
                "meter_identity": meter_identity,
            }
            association["invocation_counter_reuse_test"] = {
                "enabled": invocation_counter_reuse_test,
                "status": "not_requested",
            }

        if association_view_mode == "reuse":
            progress(
                {
                    "phase": "association_view",
                    "message": "Loading saved Association View; meter download skipped",
                }
            )
            objects, cached_access = _objects_from_association_snapshot(
                session, association_view_snapshot or {}
            )
            association_view_attempts = 0
            discovery_error = None
        else:
            progress({"phase": "association_view", "message": "Reading Association LN object list"})
            objects, association_view_attempts, discovery_error = _discover_association_view(
                session,
                config,
                report,
                progress,
                error_phase=f"{profile_name}_reconnaissance",
            )
            if discovery_error is not None:
                raise RuntimeError(f"association-view discovery failed: {discovery_error}")

        enumeration_timeout_applied = _set_session_timeout(
            session, config.scan.enumeration_timeout_ms
        )
        progress(
            {
                "phase": "enumeration_timeout",
                "profile": profile_name,
                "timeout_ms": config.scan.enumeration_timeout_ms,
                "message": (
                    f"Association View validated; using {config.scan.enumeration_timeout_ms} ms "
                    "timeouts for enumeration GETs"
                ),
            }
        )

        version = _association_version(objects)
        inventory: dict[tuple[int, str], dict[str, Any]] = {}
        for target in objects:
            key = (int(target.objectType), str(target.logicalName))
            inventory[key] = {
                "target": target,
                "sources": {"association_view"},
                "attributes": (
                    cached_access.get(key, {})
                    if association_view_mode == "reuse"
                    else _advertised_attributes(target, version)
                ),
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
                    rights = inventory[key]["attributes"].get(attribute_id)
                    if rights is None:
                        inventory[key]["attributes"][attribute_id] = {
                            "advertised": False,
                            "read": True,
                            "write": False,
                            "requires_authentication": False,
                            "requirements": [],
                            "mode": "catalogue_probe",
                            "raw": None,
                            "catalogue_probe": True,
                        }
                    else:
                        # Preserve the Association View rights while retaining
                        # the pre-existing, read-only common-catalogue probe.
                        rights["catalogue_probe"] = True

        association_order_items = list(inventory.items())
        all_items = sorted(inventory.items(), key=lambda pair: pair[0])
        if public_objects is not None and public_capabilities is not None:
            union_candidates = _public_union_candidates(
                inventory,
                public_objects,
                public_capabilities,
                source_profile=profile_name,
            )
            report["public_union_test"]["candidate_gets"] = len(union_candidates)
            report["public_union_test"]["selected_gets"] = (
                min(len(union_candidates), config.scan.get_limit)
                if config.scan.get_limit is not None
                else len(union_candidates)
            )
        all_get_capabilities = [
            (key, attribute_id)
            for key, item in all_items
            for attribute_id in _ordered_attribute_ids(
                item["target"], item["attributes"]
            )
            if attribute_id != 1
            and (
                item["attributes"][attribute_id].get("read")
                or item["attributes"][attribute_id].get("catalogue_probe")
            )
        ]
        testable_get_capabilities = list(all_get_capabilities)
        association_view_get = ((15, "0.0.40.0.0.255"), 2)
        if association_view_mode == "reuse":
            if association_view_get in testable_get_capabilities:
                testable_get_capabilities.remove(association_view_get)
        elif association_view_get in testable_get_capabilities:
            testable_get_capabilities.remove(association_view_get)
            testable_get_capabilities.insert(0, association_view_get)
        # Read the associated-partners and authentication-mechanism attributes
        # early for every Association LN visible in this association. This
        # produces a bounded, evidence-based mechanism inventory without
        # guessing client SAPs, passwords, HLS secrets, keys, or certificates.
        authentication_capabilities = [
            capability
            for capability in testable_get_capabilities
            if capability[0][0] == 15 and capability[1] in (3, 6)
        ]
        for capability in reversed(authentication_capabilities):
            testable_get_capabilities.remove(capability)
            testable_get_capabilities.insert(
                1 if association_view_get in testable_get_capabilities else 0,
                capability,
            )

        # A class-7 buffer is otherwise typically thousands of capabilities
        # into a large Association View. Reserve one short-test slot for a
        # likely event log so block-transfer decoding and row rendering are
        # exercised without adding to the operator's GET budget or downloading
        # every potentially large profile buffer.
        prioritized_profile_buffer = None
        if config.scan.get_limit is not None:
            profile_buffers = [
                capability
                for capability in testable_get_capabilities
                if capability[0][0] == 7 and capability[1] == 2
            ]
            if profile_buffers:
                prioritized_profile_buffer = next(
                    (
                        capability
                        for capability in profile_buffers
                        if "event" in str(
                            getattr(
                                inventory[capability[0]]["target"],
                                "description",
                                "",
                            )
                        ).lower()
                        or "log" in str(
                            getattr(
                                inventory[capability[0]]["target"],
                                "description",
                                "",
                            )
                        ).lower()
                    ),
                    profile_buffers[0],
                )
                testable_get_capabilities.remove(prioritized_profile_buffer)
                priority_index = (
                    (1 if association_view_get in testable_get_capabilities else 0)
                    + len(authentication_capabilities)
                )
                testable_get_capabilities.insert(
                    priority_index, prioritized_profile_buffer
                )

        if config.scan.object_limit is not None:
            selected_inventory_items = association_order_items[: config.scan.object_limit]
            selected_object_keys = {key for key, _ in selected_inventory_items}
            selected_get_capabilities = {
                (key, attribute_id)
                for key, item in selected_inventory_items
                for attribute_id in _ordered_attribute_ids(
                    item["target"], item["attributes"]
                )
                if (
                    attribute_id != 1
                    and (
                        item["attributes"][attribute_id].get("read")
                        or item["attributes"][attribute_id].get("catalogue_probe")
                    )
                )
            }
            if association_view_get in testable_get_capabilities:
                selected_get_capabilities.add(association_view_get)
            progress(
                {
                    "phase": "short_test_selected",
                    "profile": profile_name,
                    "object_limit": config.scan.object_limit,
                    "association_view_objects": len(objects),
                    "selected_objects": len(selected_object_keys),
                    "selected_gets": len(selected_get_capabilities),
                    "message": (
                        f"Short test: testing GET capabilities from the first "
                        f"{len(selected_object_keys)} of {len(objects)} Association View objects"
                    ),
                }
            )
        elif config.scan.get_limit is not None:
            selected_get_capabilities = set(
                testable_get_capabilities[: config.scan.get_limit]
            )
            selected_object_keys = {
                key for key, _ in selected_get_capabilities
            }
            progress(
                {
                    "phase": "short_test_selected",
                    "profile": profile_name,
                    "get_limit": config.scan.get_limit,
                    "association_view_objects": len(objects),
                    "selected_objects": len(selected_object_keys),
                    "selected_gets": len(selected_get_capabilities),
                    "message": (
                        f"Short test: testing {len(selected_get_capabilities)} of "
                        f"{len(testable_get_capabilities)} testable GET capabilities"
                    ),
                }
            )
        else:
            selected_get_capabilities = set(testable_get_capabilities)
            selected_object_keys = {key for key, _ in all_items}

        if association_view_mode == "reuse":
            # The saved object list is inventory evidence, not a fresh GET.
            # This also covers object-limited scans, whose selection is built
            # directly from inventory rather than from testable capabilities.
            selected_get_capabilities.discard(association_view_get)

        planned_attributes = len(selected_get_capabilities)
        progress(
            {
                "phase": "get_plan",
                "profile": profile_name,
                "total": planned_attributes,
                "message": f"Scanning {planned_attributes} readable attributes",
            }
        )

        object_records: list[dict[str, Any]] = []
        get_success = 0
        get_failed = 0
        profile_result: dict[str, Any] = {
            "name": profile_name,
            "type": config.profile.name,
            "association": association,
            "identification": {},
            "association_view_object_count": len(objects),
            "association_view_attempt_count": association_view_attempts,
            "association_view_source": (
                "saved_snapshot" if association_view_mode == "reuse" else "meter"
            ),
            "scan_scope": {
                "short_test": (
                    config.scan.object_limit is not None
                    or config.scan.get_limit is not None
                ),
                "object_limit": config.scan.object_limit,
                "get_limit": config.scan.get_limit,
                "association_view_objects": len(objects),
                "inventory_objects": len(inventory),
                "mapped_objects": len(all_items),
                "selected_objects": len(selected_object_keys),
                "mapped_gets": len(all_get_capabilities),
                "testable_gets": len(testable_get_capabilities),
                "selected_gets": len(selected_get_capabilities),
                "prioritized_profile_buffer": (
                    {
                        "class_id": prioritized_profile_buffer[0][0],
                        "logical_name": prioritized_profile_buffer[0][1],
                        "attribute_id": prioritized_profile_buffer[1],
                    }
                    if prioritized_profile_buffer in selected_get_capabilities
                    else None
                ),
                "get_with_list": {
                    "requested_batch_size": config.scan.batch_size,
                    "negotiated": "multiple_references"
                    in association.get("negotiated_conformance", []),
                    "negotiated_pdu_item_limit": None,
                    "effective_batch_size": 1,
                    "attempted_batches": 0,
                    "successful_batches": 0,
                    "fallback_batches": 0,
                },
                "timeout_policy": _timeout_policy_scope(
                    config,
                    enumeration_timeout_applied=enumeration_timeout_applied,
                ),
            },
            "objects": object_records,
            "summary": {
                "objects": 0,
                "association_view_objects": len(objects),
                "inventory_objects": len(inventory),
                "selected_objects": len(selected_object_keys),
                "object_limit": config.scan.object_limit,
                "get_limit": config.scan.get_limit,
                "mapped_gets": len(all_get_capabilities),
                "testable_gets": len(testable_get_capabilities),
                "selected_gets": len(selected_get_capabilities),
                "get_attempted": 0,
                "get_transmissions": 0,
                "get_success": 0,
                "get_failed": 0,
                "get_inconclusive": 0,
                "get_not_tested": len(all_get_capabilities),
            },
        }
        report["profiles"].append(profile_result)
        get_transmissions = 0
        retry_policy = _GetRetryPolicy()
        timeout_circuit = _TimeoutCircuitBreaker(
            config.scan.timeout_breaker_threshold
        )
        circuit_scope = profile_result["scan_scope"]["timeout_policy"]
        health_probe: tuple[str, Any | None, int | None] = (
            "association_view",
            None,
            None,
        )
        phase_inconclusive = False
        get_inconclusive = 0
        batch_results: dict[tuple[tuple[int, str], int], dict[str, Any]] = {}
        batch_scope = profile_result["scan_scope"]["get_with_list"]
        multiple_references = bool(batch_scope["negotiated"])
        batch_reader = getattr(session, "read_attributes", None)
        max_pdu_size = association.get("max_receive_pdu_size")
        pdu_item_limit = (
            max(1, min(10, (int(max_pdu_size) - 12) // 10))
            if max_pdu_size is not None
            else 10
        )
        batch_scope["negotiated_pdu_item_limit"] = pdu_item_limit
        effective_batch_size = (
            min(config.scan.batch_size, pdu_item_limit)
            if config.scan.batch_size > 1
            and multiple_references
            and callable(batch_reader)
            and pdu_item_limit > 1
            else 1
        )
        batch_scope["effective_batch_size"] = effective_batch_size

        # Only Association View-advertised reads are safe to combine. Catalogue
        # probes remain individual requests because their access is speculative.
        item_by_key = dict(all_items)
        batch_capabilities = [
            capability
            for capability in testable_get_capabilities
            if capability in selected_get_capabilities
            and capability != association_view_get
            and item_by_key[capability[0]]["attributes"][capability[1]].get("read")
            and not item_by_key[capability[0]]["attributes"][capability[1]].get(
                "catalogue_probe"
            )
        ]
        if effective_batch_size > 1:
            for start in range(0, len(batch_capabilities), effective_batch_size):
                if phase_inconclusive:
                    break
                chunk = batch_capabilities[start : start + effective_batch_size]
                # A one-item list adds complexity without reducing round trips.
                if len(chunk) < 2:
                    continue
                requests = [
                    (item_by_key[key]["target"], attribute_id)
                    for key, attribute_id in chunk
                ]
                batch_scope["attempted_batches"] += 1
                get_transmissions += 1
                progress(
                    {
                        "phase": "get_list_scan",
                        "profile": profile_name,
                        "items": len(chunk),
                        "message": f"GET-with-list for {len(chunk)} attributes",
                    }
                )
                try:
                    decoded_items = batch_reader(requests, 1)
                    if len(decoded_items) != len(chunk):
                        raise ValueError(
                            "GET-with-list returned "
                            f"{len(decoded_items)} values for {len(chunk)} requests"
                        )
                except Exception as exc:
                    batch_scope["fallback_batches"] += 1
                    outcome = classify_exception(exc)
                    retry_policy.record(outcome)
                    timeout_circuit.record(outcome)
                    progress(
                        {
                            "phase": "get_list_fallback",
                            "profile": profile_name,
                            "items": len(chunk),
                            "message": (
                                f"GET-with-list failed ({type(exc).__name__}: {exc}); "
                                "retrying each attribute individually"
                            ),
                        }
                    )
                    if timeout_circuit.tripped:
                        recovered, probe_transmissions = _recover_timeout_circuit(
                            session,
                            config,
                            retry_policy,
                            timeout_circuit,
                            health_probe,
                            circuit_scope,
                            report,
                            progress,
                            profile_name=profile_name,
                            phase="get_scan_timeout_circuit",
                        )
                        get_transmissions += probe_transmissions
                        phase_inconclusive = not recovered
                    continue
                batch_scope["successful_batches"] += 1
                batch_results.update(zip(chunk, decoded_items, strict=True))
                retry_policy.record(Outcome.SUCCESS)
                timeout_circuit.record(Outcome.SUCCESS)
                health_probe = ("attribute", requests[0][0], requests[0][1])

        for (class_id, logical_name), item in all_items:
            target = item["target"]
            object_result = _object_record(target, item["sources"], version)
            object_records.append(object_result)
            profile_result["summary"]["objects"] = len(object_records)
            if object_result["class_name"] == "GXDLMSObject":
                report["unknown_objects"].append(
                    {
                        "profile": profile_name,
                        "class_id": class_id,
                        "logical_name": logical_name,
                        "object_version": object_result["object_version"],
                        "source": (
                            "association_view"
                            if "association_view" in item["sources"]
                            else object_result["discovery_sources"][0]
                        ),
                    }
                )
            for attribute_id in _ordered_attribute_ids(target, item["attributes"]):
                # Attribute 1 repeats the logical name already stored on the
                # object record. Omit it from all result and capability output.
                if attribute_id == 1:
                    continue
                access_rights = item["attributes"][attribute_id]
                advertised_operations = []
                if access_rights.get("advertised", True) and access_rights.get("read"):
                    advertised_operations.append("GET")
                if access_rights.get("write"):
                    advertised_operations.append("SET")
                identity = {
                    "profile": profile_name,
                    "class_id": class_id,
                    "logical_name": logical_name,
                    "object_version": int(getattr(target, "version", 0)),
                    "attribute_id": attribute_id,
                }
                attribute_result: dict[str, Any] = {
                    "attribute_id": attribute_id,
                    "name": _attribute_name(target, attribute_id),
                    "advertised_access": access_rights.get("mode", "unknown"),
                    "access_rights": access_rights,
                    "advertised_operations": advertised_operations,
                    "write_service": "SET" if access_rights.get("write") else None,
                    "write_tested": False,
                    "lifecycle": "discovered",
                    "outcome": None,
                    "attempt_count": 0,
                    "attempts": [],
                }
                object_result["attributes"].append(attribute_result)

                # Preserve write-only attributes as passive Association View
                # capabilities, but never issue a modifying SET during enumeration.
                if not (
                    access_rights.get("read")
                    or access_rights.get("catalogue_probe")
                ):
                    attribute_result["lifecycle"] = "not_readable"
                    continue

                if ((class_id, logical_name), attribute_id) not in selected_get_capabilities:
                    attribute_result.update(
                        {
                            "lifecycle": "not_tested",
                            "outcome": Outcome.NOT_TESTED.value,
                        }
                    )
                    continue

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
                    progress(
                        {
                            "phase": "get_complete",
                            "profile": profile_name,
                            "logical_name": logical_name,
                            "class_id": class_id,
                            "attribute_id": attribute_id,
                            "outcome": Outcome.SUCCESS.value,
                        }
                    )
                    continue

                capability = ((class_id, logical_name), attribute_id)
                if capability in batch_results:
                    attribute_result.update(
                        {
                            "lifecycle": "success",
                            "outcome": Outcome.SUCCESS.value,
                            "attempt_count": 1,
                            "attempts": [
                                {
                                    "attempt": 1,
                                    "outcome": Outcome.SUCCESS.value,
                                    "get_with_list": True,
                                }
                            ],
                            "decoded": batch_results[capability],
                        }
                    )
                    get_success += 1
                    retry_policy.record(Outcome.SUCCESS)
                    profile_result["summary"].update(
                        {
                            "get_attempted": get_success + get_failed,
                            "get_transmissions": get_transmissions,
                            "get_success": get_success,
                            "get_failed": get_failed,
                        }
                    )
                    progress(
                        {
                            "phase": "get_complete",
                            "profile": profile_name,
                            "logical_name": logical_name,
                            "class_id": class_id,
                            "attribute_id": attribute_id,
                            "outcome": Outcome.SUCCESS.value,
                            "get_with_list": True,
                        }
                    )
                    continue

                if phase_inconclusive:
                    attribute_result.update(
                        {
                            "lifecycle": "inconclusive",
                            "outcome": Outcome.INCONCLUSIVE.value,
                            "inconclusive_reason": circuit_scope["stop_reason"],
                        }
                    )
                    get_inconclusive += 1
                    progress(
                        {
                            "phase": "get_complete",
                            "profile": profile_name,
                            "logical_name": logical_name,
                            "class_id": class_id,
                            "attribute_id": attribute_id,
                            "outcome": Outcome.INCONCLUSIVE.value,
                        }
                    )
                    continue

                last_exception: BaseException | None = None
                allowed_attempts = retry_policy.attempts_for_next_get(
                    config.scan.total_get_attempts
                )
                attribute_result["retry_suppressed"] = allowed_attempts == 1
                for attempt in range(1, allowed_attempts + 1):
                    get_transmissions += 1
                    attribute_result["lifecycle"] = "attempted"
                    attribute_result["attempt_count"] = attempt
                    progress(
                        {
                            "phase": "get_scan",
                            "profile": profile_name,
                            "class_id": class_id,
                            "logical_name": logical_name,
                            "attribute_id": attribute_id,
                            "attempt": attempt,
                            "message": f"GET {logical_name} class {class_id} attribute {attribute_id} ({attempt}/{allowed_attempts})",
                        }
                    )
                    try:
                        decoded = session.read_attribute(target, attribute_id, attempt)
                    except Exception as exc:
                        last_exception = exc
                        outcome = classify_exception(exc)
                        retry_policy.record(outcome)
                        timeout_circuit.record(outcome)
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
                    retry_policy.record(Outcome.SUCCESS)
                    timeout_circuit.record(Outcome.SUCCESS)
                    health_probe = ("attribute", target, attribute_id)
                    last_exception = None
                    break

                if (
                    last_exception is not None
                    and classify_exception(last_exception) == Outcome.TIMEOUT
                    and timeout_circuit.tripped
                ):
                    recovered, probe_transmissions = _recover_timeout_circuit(
                        session,
                        config,
                        retry_policy,
                        timeout_circuit,
                        health_probe,
                        circuit_scope,
                        report,
                        progress,
                        profile_name=profile_name,
                        phase="get_scan_timeout_circuit",
                    )
                    get_transmissions += probe_transmissions
                    phase_inconclusive = not recovered

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
                        "get_inconclusive": get_inconclusive,
                    }
                )
                progress(
                    {
                        "phase": "get_complete",
                        "profile": profile_name,
                        "logical_name": logical_name,
                        "class_id": class_id,
                        "attribute_id": attribute_id,
                        "outcome": attribute_result["outcome"],
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
        profile_result["authentication_enumeration"] = _authentication_enumeration(
            object_records, association
        )
        profile_result["summary"].update(
            {
                "objects": len(object_records),
                "get_attempted": get_success + get_failed,
                "get_transmissions": get_transmissions,
                "get_success": get_success,
                "get_failed": get_failed,
                "get_inconclusive": get_inconclusive,
                "get_not_tested": sum(
                    attribute.get("outcome") == Outcome.NOT_TESTED.value
                    for obj in object_records
                    for attribute in obj.get("attributes", [])
                ),
                "advertised_set_attributes": sum(
                    bool(attribute.get("access_rights", {}).get("write"))
                    for obj in object_records
                    for attribute in obj.get("attributes", [])
                ),
                "advertised_action_methods": sum(
                    bool(method.get("access_rights", {}).get("action"))
                    for obj in object_records
                    for method in obj.get("methods", [])
                ),
                "profile_buffers_read": sum(
                    int(obj.get("class_id", -1)) == 7
                    and attribute.get("attribute_id") == 2
                    and attribute.get("outcome") == Outcome.SUCCESS.value
                    and isinstance(attribute.get("decoded", {}).get("value"), list)
                    for obj in object_records
                    for attribute in obj.get("attributes", [])
                ),
                "profile_rows_read": sum(
                    len(attribute.get("decoded", {}).get("value", []))
                    for obj in object_records
                    for attribute in obj.get("attributes", [])
                    if int(obj.get("class_id", -1)) == 7
                    and attribute.get("attribute_id") == 2
                    and attribute.get("outcome") == Outcome.SUCCESS.value
                    and isinstance(attribute.get("decoded", {}).get("value"), list)
                ),
            }
        )
        if config.scan.union_profile_test and union_candidates == []:
            report["public_union_test"].update(
                {
                    "status": "no_additional_targets",
                    "attempted_gets": 0,
                    "selected_gets": 0,
                    "get_transmissions": 0,
                    "unexpected_public_access": 0,
                    "public_access_rejected": 0,
                    "inconclusive": 0,
                    "results": [],
                }
            )
        elif config.scan.union_profile_test and union_candidates is not None:
            profile_result["association"]["next_client_invocation_counter"] = int(
                secure_session.client.ciphering.invocationCounter
            )
            _record_cleanup_warnings(
                report,
                secure_session.close(),
                phase="secure_profile_finalization",
            )
            session = None
            progress(
                {
                    "phase": "public_union_connect",
                    "message": "Reopening the public association for cross-profile GET tests",
                }
            )
            try:
                public_probe = GuruxSession(
                    config,
                    int(report["transport"]["selected_baudrate"]),
                    traffic,
                    server_logical_address=int(endpoint["logical_address"]),
                    server_physical_address=int(endpoint["physical_address"]),
                    server_address_size=int(endpoint["address_size"]),
                    client_address=config.profile.invocation_counter.public_client_address,
                    profile_name="public",
                )
                session = public_probe
                probe_association = public_probe.connect()
            except Exception as exc:
                report["errors"].append(
                    error_record(exc, phase="public_union_connection")
                )
                report["public_union_test"].update(
                    {
                        "status": "public_connection_failed",
                        "error": f"{type(exc).__name__}: {exc}",
                        "results": [],
                    }
                )
            else:
                report["public_union_test"].update(
                    {
                        "public_probe_association": probe_association,
                        **_run_public_union_gets(
                            public_probe,
                            (
                                union_candidates[: config.scan.get_limit]
                                if config.scan.get_limit is not None
                                else union_candidates
                            ),
                            config,
                            report,
                            progress,
                            candidate_count=len(union_candidates),
                        ),
                    }
                )
        if invocation_counter_reuse_test and secure_session is not None:
            if session is not secure_session:
                if session is not None:
                    _record_cleanup_warnings(
                        report,
                        session.close(),
                        phase="public_union_finalization",
                    )
                    session = None
                secure_session.reconnect()
                session = secure_session
            _set_session_timeout(
                secure_session, config.scan.enumeration_timeout_ms
            )
            progress({"phase": "invocation_counter_reuse_start"})
            reuse_result = secure_session.test_invocation_counter_reuse(
                progress=progress
            )
            association["invocation_counter_reuse_test"] = reuse_result
            if not reuse_result.get("association_restored"):
                raise RuntimeError(
                    "secure association could not be restored after the "
                    "invocation-counter reuse test"
                )
        report["run"]["status"] = (
            "completed" if not get_failed and not report["errors"] else "completed_with_errors"
        )
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
            _record_cleanup_warnings(report, session.close(), phase="finalization")
        if secure_session is not None and report.get("profiles"):
            report["profiles"][0]["association"]["next_client_invocation_counter"] = int(
                secure_session.client.ciphering.invocationCounter
            )
        if counter_lease is not None:
            counter_lease.close()
        if report["run"]["status"] == "completed" and report["errors"]:
            report["run"]["status"] = "completed_with_errors"
        matrix: list[dict[str, Any]] = []
        for profile in report.get("profiles", []):
            for obj in profile.get("objects", []):
                for attribute in obj.get("attributes", []):
                    rights = attribute.get("access_rights", {})
                    if rights.get("read", True) or rights.get("catalogue_probe"):
                        outcome = attribute.get("outcome") or Outcome.NOT_TESTED.value
                        tested = attribute.get("attempt_count", 0) > 0
                        matrix.append({
                            "operation": "GET",
                            "class_id": obj["class_id"],
                            "logical_name": obj["logical_name"],
                            "object_version": obj["object_version"],
                            "attribute_id": attribute["attribute_id"],
                            "member_name": attribute.get("name"),
                            "advertised_access": attribute.get("advertised_access"),
                            "profiles": {
                                profile["name"]: {
                                    "status": outcome,
                                    "outcome": outcome,
                                    "success": (
                                        outcome == Outcome.SUCCESS.value
                                        if tested
                                        else None
                                    ),
                                    "advertised": bool(
                                        rights.get("advertised", True)
                                        and rights.get("read", True)
                                    ),
                                    "tested": tested,
                                }
                            },
                        })
                    if rights.get("write"):
                        matrix.append({
                            "operation": "SET",
                            "class_id": obj["class_id"],
                            "logical_name": obj["logical_name"],
                            "object_version": obj["object_version"],
                            "attribute_id": attribute["attribute_id"],
                            "member_name": attribute.get("name"),
                            "advertised_access": attribute.get("advertised_access"),
                            "profiles": {
                                profile["name"]: {
                                    "status": Outcome.NOT_TESTED.value,
                                    "advertised": True,
                                    "tested": False,
                                    "outcome": Outcome.NOT_TESTED.value,
                                    "success": None,
                                }
                            },
                        })
                for method in obj.get("methods", []):
                    if method.get("access_rights", {}).get("action"):
                        matrix.append({
                            "operation": "ACTION",
                            "class_id": obj["class_id"],
                            "logical_name": obj["logical_name"],
                            "object_version": obj["object_version"],
                            "method_id": method["method_id"],
                            "member_name": method.get("name"),
                            "advertised_access": method.get("advertised_access"),
                            "profiles": {
                                profile["name"]: {
                                    "status": Outcome.NOT_TESTED.value,
                                    "advertised": True,
                                    "tested": False,
                                    "outcome": Outcome.NOT_TESTED.value,
                                    "success": None,
                                }
                            },
                        })
        get_rows = {
            (row["class_id"], row["logical_name"], row["attribute_id"]): row
            for row in matrix
            if row["operation"] == "GET"
        }
        for candidate in union_candidates or []:
            row = get_rows.get(
                (
                    candidate["class_id"],
                    candidate["logical_name"],
                    candidate["attribute_id"],
                )
            )
            if row is None:
                continue
            row["profiles"]["public"] = {
                "status": Outcome.NOT_TESTED.value,
                "outcome": Outcome.NOT_TESTED.value,
                "success": None,
                "advertised": candidate["public_advertised"],
                "advertised_access": candidate.get("public_advertised_access"),
                "tested": False,
                "cross_profile_probe": True,
                "access_assessment": None,
            }
        for result in report.get("public_union_test", {}).get("results", []):
            row = get_rows.get(
                (
                    result["class_id"],
                    result["logical_name"],
                    result["attribute_id"],
                )
            )
            if row is None:
                continue
            row["profiles"]["public"] = {
                "status": result["outcome"],
                "outcome": result["outcome"],
                "success": result["outcome"] == Outcome.SUCCESS.value,
                "advertised": False,
                "advertised_access": result.get("public_advertised_access"),
                "tested": True,
                "cross_profile_probe": True,
                "access_assessment": result["access_assessment"],
            }
        report["capability_matrix"] = matrix
        report["run"]["finished_at"] = utc_now()
    return report


scan = scan_public
