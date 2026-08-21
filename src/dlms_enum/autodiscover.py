"""Standalone, read-only public DLMS/HDLC connection discovery.

The discovery workflow deliberately stops at unauthenticated public GETs.  It
does not guess credentials, send SET/ACTION requests, or attempt a protected
association.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from collections import Counter
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Iterable

import yaml
from rich.console import Console

from .config import (
    DEFAULT_BAUD_RATES,
    AppConfig,
    AuthenticationScanConfig,
    OutputConfig,
    PublicProfile,
    ScanConfig,
    SerialSettings,
    TransportConfig,
)
from .result_model import Outcome, classify_exception, utc_now
from .scanner import (
    _advertised_attributes,
    _association_version,
    _discover_association_view,
    validate_serial_device,
)
from .traffic_logger import TrafficLogger


DEFAULT_PUBLIC_CLIENTS = (16, 1, 2, 4, 8, 32, 48, 64)
DEFAULT_LOGICAL_ADDRESSES = (1, 0, 16)
DEFAULT_PHYSICAL_ADDRESSES = tuple(range(0, 32))
DEEP_PHYSICAL_ADDRESSES = tuple(range(0, 128))
DEFAULT_SECURITY_SETUP_INSTANCES = tuple(range(0, 16))
# Invocation counters use the 0-b:43.1.e.255 family. The B/channel field is
# not fixed to zero; meters can expose role-specific counters on channels such
# as 1, 2, or 4.
_COUNTER_LOGICAL_NAME = re.compile(r"^0\.\d+\.43\.1\.\d+\.255$")


@dataclass(frozen=True)
class DiscoveryOptions:
    device: str
    baudrates: tuple[int, ...] = DEFAULT_BAUD_RATES
    client_addresses: tuple[int, ...] = DEFAULT_PUBLIC_CLIENTS
    logical_addresses: tuple[int, ...] = DEFAULT_LOGICAL_ADDRESSES
    physical_addresses: tuple[int, ...] = DEFAULT_PHYSICAL_ADDRESSES
    serial: SerialSettings = SerialSettings()
    probe_timeout_ms: int = 350
    inspection_timeout_ms: int = 1500
    security_setup_instances: tuple[int, ...] = DEFAULT_SECURITY_SETUP_INSTANCES


ProgressCallback = Callable[[dict[str, Any]], None]


def _unique(values: Iterable[int]) -> tuple[int, ...]:
    return tuple(dict.fromkeys(int(value) for value in values))


def server_address_candidates(
    logical_addresses: Iterable[int], physical_addresses: Iterable[int]
) -> tuple[dict[str, int | str], ...]:
    """Return deterministic HDLC server candidates, with common forms first."""

    logical = _unique(logical_addresses)
    physical = _unique(physical_addresses)
    available_logical = set(logical)
    available_physical = set(physical)
    raw: list[tuple[int, int, int]] = []

    # These cover the overwhelmingly common direct-HDLC forms and the
    # logical-1/physical-17 endpoint observed in the supplied notification.
    priority = (
        (0, 1, 1),
        (1, 1, 2),
        (1, 17, 2),
        (0, 17, 1),
        (1, 0, 2),
        (0, 16, 1),
        (1, 16, 2),
    )
    for item in priority:
        candidate_logical, candidate_physical, _ = item
        if (
            candidate_physical in available_physical
            and (candidate_logical == 0 or candidate_logical in available_logical)
        ):
            raw.append(item)

    for candidate_physical in physical:
        if 0 < candidate_physical < 0x80:
            raw.append((0, candidate_physical, 1))
    for candidate_logical in logical:
        if not 0 <= candidate_logical < 0x80:
            continue
        for candidate_physical in physical:
            if 0 <= candidate_physical < 0x80:
                raw.append((candidate_logical, candidate_physical, 2))

    result: list[dict[str, int | str]] = []
    seen: set[tuple[int, int, int]] = set()
    for candidate_logical, candidate_physical, address_size in raw:
        identity = (candidate_logical, candidate_physical, address_size)
        if identity in seen:
            continue
        seen.add(identity)
        result.append(
            {
                "logical_address": candidate_logical,
                "physical_address": candidate_physical,
                "server_address": (
                    candidate_physical
                    if address_size == 1
                    else (candidate_logical << 7) | candidate_physical
                ),
                "address_size": address_size,
                "server_addressing_type": f"{address_size}-byte addressing",
            }
        )
    return tuple(result)


def _runtime_config(
    options: DiscoveryOptions,
    *,
    baudrate: int,
    client_address: int,
    endpoint: dict[str, Any],
    timeout_ms: int,
) -> AppConfig:
    return AppConfig(
        version=1,
        transport=TransportConfig(
            device=options.device,
            baudrate=baudrate,
            baudrate_candidates=(baudrate,),
            serial=options.serial,
            response_timeout_ms=timeout_ms,
            inter_request_delay_ms=0,
            session_guard_ms=0,
        ),
        scan=ScanConfig(
            total_get_attempts=1,
            common_catalogue=False,
            enumeration_timeout_ms=options.inspection_timeout_ms,
        ),
        authentication_scan=AuthenticationScanConfig(),
        profiles=(
            PublicProfile(
                client_address=client_address,
                server_logical_address=int(endpoint["logical_address"]),
                server_physical_address=int(endpoint["physical_address"]),
                server_address_size=int(endpoint["address_size"]),
            ),
        ),
        output=OutputConfig(),
    )


def _octet_string_hex(value: Any) -> str | None:
    if not isinstance(value, dict):
        return None
    if value.get("encoding") != "octet-string" or value.get("length") != 8:
        return None
    candidate = value.get("hex")
    return str(candidate).upper() if candidate else None


def retrieve_system_titles(
    session: Any,
    association: dict[str, Any],
    objects: list[Any],
    association_version: int | None,
    *,
    direct_instances: Iterable[int] = DEFAULT_SECURITY_SETUP_INSTANCES,
    progress: ProgressCallback | None = None,
) -> dict[str, Any]:
    """Retrieve titles exposed by AARE or public Security Setup attributes.

    Advertised class-64 objects are inspected first. If no server title has
    been obtained, common Security Setup logical names are addressed directly;
    some meters allow a GET even though the object is omitted from the public
    Association View. Explicit DLMS rejection is negative evidence, not an
    operational error. Two consecutive silent probes stop the bounded sweep.
    """

    progress = progress or (lambda _: None)
    titles: list[dict[str, Any]] = []
    probes: list[dict[str, Any]] = []
    errors: list[dict[str, Any]] = []
    attempted: set[tuple[str, int]] = set()

    aare_title = association.get("server_system_title")
    probes.append(
        {
            "source": "public_aare",
            "kind": "server",
            "outcome": Outcome.SUCCESS.value if aare_title else Outcome.NOT_TESTED.value,
            "reason": None if aare_title else "not_present_in_public_aare",
        }
    )
    if aare_title:
        titles.append(
            {
                "kind": "server",
                "hex": str(aare_title).upper(),
                "source": "public_aare",
                "confidence": "negotiated",
            }
        )

    advertised: dict[str, Any] = {
        str(target.logicalName): target
        for target in objects
        if int(target.objectType) == 64
    }

    def read_title(
        target: Any,
        attribute_id: int,
        kind: str,
        *,
        source: str,
    ) -> tuple[bool, Outcome]:
        logical_name = str(target.logicalName)
        attempted.add((logical_name, attribute_id))
        probe = {
            "source": source,
            "kind": kind,
            "class_id": 64,
            "logical_name": logical_name,
            "attribute_id": attribute_id,
        }
        progress(
            {
                "phase": "system_title_probe",
                "logical_name": logical_name,
                "attribute_id": attribute_id,
                "message": (
                    f"Public GET Security Setup {logical_name} attribute "
                    f"{attribute_id} ({kind} system title)"
                ),
            }
        )
        try:
            decoded = session.read_attribute(
                target,
                attribute_id,
                1,
                phase="auto_discovery",
                purpose="security_setup_system_title_read",
            )
        except Exception as exc:
            outcome = classify_exception(exc)
            probe.update(
                {
                    "outcome": outcome.value,
                    "error": f"{type(exc).__name__}: {exc}",
                }
            )
            if outcome != Outcome.DLMS_ERROR:
                errors.append(
                    {
                        "phase": "security_setup_system_title",
                        "logical_name": logical_name,
                        "attribute_id": attribute_id,
                        "category": outcome.value,
                        "type": type(exc).__name__,
                        "message": str(exc),
                    }
                )
            probes.append(probe)
            return False, outcome

        title = _octet_string_hex(decoded.get("value"))
        if title is None:
            probe.update(
                {
                    "outcome": Outcome.PROTOCOL_ERROR.value,
                    "error": "response was not an eight-octet system title",
                }
            )
            errors.append(
                {
                    "phase": "security_setup_system_title",
                    "logical_name": logical_name,
                    "attribute_id": attribute_id,
                    "category": Outcome.PROTOCOL_ERROR.value,
                    "type": "InvalidSystemTitle",
                    "message": "response was not an eight-octet system title",
                }
            )
            probes.append(probe)
            return False, Outcome.PROTOCOL_ERROR

        probe.update({"outcome": Outcome.SUCCESS.value, "hex": title})
        probes.append(probe)
        titles.append(
            {
                "kind": kind,
                "hex": title,
                "source": source,
                "logical_name": logical_name,
                "attribute_id": attribute_id,
                "confidence": "public_read",
            }
        )
        return True, Outcome.SUCCESS

    if association_version is not None:
        for logical_name, target in sorted(advertised.items()):
            rights = _advertised_attributes(target, association_version)
            for attribute_id, kind in ((5, "server"), (4, "client")):
                attribute_rights = rights.get(attribute_id)
                if not (
                    attribute_rights
                    and attribute_rights.get("read")
                    and not attribute_rights.get("requirements")
                ):
                    probes.append(
                        {
                            "source": "advertised_security_setup",
                            "kind": kind,
                            "class_id": 64,
                            "logical_name": logical_name,
                            "attribute_id": attribute_id,
                            "outcome": Outcome.NOT_TESTED.value,
                            "reason": "not_publicly_readable",
                        }
                    )
                    continue
                read_title(
                    target,
                    attribute_id,
                    kind,
                    source="advertised_security_setup",
                )

    has_server_title = any(item["kind"] == "server" for item in titles)
    consecutive_timeouts = 0
    direct_stopped_reason = None
    if not has_server_title:
        for instance in _unique(direct_instances):
            logical_name = f"0.0.43.0.{instance}.255"
            if (logical_name, 5) in attempted or logical_name in advertised:
                continue
            target = session.create_object(64, logical_name)
            found, outcome = read_title(
                target,
                5,
                "server",
                source="direct_security_setup_probe",
            )
            consecutive_timeouts = (
                consecutive_timeouts + 1 if outcome == Outcome.TIMEOUT else 0
            )
            if consecutive_timeouts >= 2:
                direct_stopped_reason = "two_consecutive_timeouts"
                break
            if not found:
                continue
            # A matching client title, when exposed, belongs to this Security
            # Setup instance. It is metadata only and is not assumed to be the
            # operator's secure-client identity.
            read_title(
                target,
                4,
                "client",
                source="direct_security_setup_probe",
            )
            break

    unique_titles: list[dict[str, Any]] = []
    seen_titles: set[tuple[str, str]] = set()
    for item in titles:
        identity = (str(item["kind"]), str(item["hex"]))
        if identity not in seen_titles:
            seen_titles.add(identity)
            unique_titles.append(item)

    return {
        "titles": unique_titles,
        "probes": probes,
        "configured_direct_probe_instances": list(_unique(direct_instances)),
        "direct_probes_attempted": sum(
            item.get("source") == "direct_security_setup_probe"
            for item in probes
        ),
        "direct_probe_stopped_reason": direct_stopped_reason,
        "errors": errors,
    }


def _inspect_public_session(
    session: Any,
    config: AppConfig,
    association: dict[str, Any],
    progress: ProgressCallback,
    *,
    security_setup_instances: Iterable[int] = DEFAULT_SECURITY_SETUP_INSTANCES,
) -> dict[str, Any]:
    """Read connection metadata that the public Association View permits."""

    errors: list[dict[str, Any]] = []
    report_stub: dict[str, Any] = {"errors": []}
    objects, association_attempts, _discovery_error = _discover_association_view(
        session,
        config,
        report_stub,
        progress,
        error_phase="auto_discovery_association_view",
    )
    errors.extend(report_stub["errors"])

    meter_identity = None
    try:
        meter_identity = session.read_meter_identity()
    except Exception as exc:
        errors.append(
            {
                "phase": "meter_identity",
                "category": classify_exception(exc).value,
                "type": type(exc).__name__,
                "message": str(exc),
            }
        )

    association_version = _association_version(objects) if objects else None
    class_counts = Counter(int(target.objectType) for target in objects)
    class_version_counts = Counter(
        (int(target.objectType), int(getattr(target, "version", 0)))
        for target in objects
    )
    association_logical_names = sorted(
        str(target.logicalName) for target in objects if int(target.objectType) == 15
    )
    counter_candidates: list[dict[str, Any]] = []
    if association_version is not None:
        for target in objects:
            class_id = int(target.objectType)
            logical_name = str(target.logicalName)
            rights = _advertised_attributes(target, association_version)

            if class_id == 1 and _COUNTER_LOGICAL_NAME.fullmatch(logical_name):
                attribute_rights = rights.get(2)
                if (
                    attribute_rights
                    and attribute_rights.get("read")
                    and not attribute_rights.get("requirements")
                ):
                    try:
                        decoded = session.read_attribute(
                            target,
                            2,
                            1,
                            phase="auto_discovery",
                            purpose="invocation_counter_candidate_read",
                        )
                    except Exception as exc:
                        errors.append(
                            {
                                "phase": "invocation_counter_candidate",
                                "logical_name": logical_name,
                                "category": classify_exception(exc).value,
                                "type": type(exc).__name__,
                                "message": str(exc),
                            }
                        )
                    else:
                        value = decoded.get("value")
                        if (
                            isinstance(value, int)
                            and not isinstance(value, bool)
                            and 0 <= value <= 0xFFFFFFFF
                        ):
                            counter_candidates.append(
                                {
                                    "class_id": 1,
                                    "logical_name": logical_name,
                                    "attribute_id": 2,
                                    "value": value,
                                    "value_hex": f"0x{value:08X}",
                                    "description": str(
                                        getattr(target, "description", "") or ""
                                    )
                                    or None,
                                    "mapping_verified": False,
                                }
                            )

    system_title_retrieval = retrieve_system_titles(
        session,
        association,
        objects,
        association_version,
        direct_instances=security_setup_instances,
        progress=progress,
    )
    errors.extend(system_title_retrieval["errors"])

    return {
        "meter_identity": meter_identity,
        "system_titles": system_title_retrieval["titles"],
        "system_title_retrieval": {
            key: value
            for key, value in system_title_retrieval.items()
            if key not in ("titles", "errors")
        },
        "invocation_counter_candidates": counter_candidates,
        "association_view": {
            "available": bool(objects),
            "object_count": len(objects),
            "read_attempts": association_attempts,
            "association_ln_version": association_version,
            "association_logical_names": association_logical_names,
            "interface_class_counts": {
                str(class_id): count for class_id, count in sorted(class_counts.items())
            },
            "interface_class_version_counts": {
                f"{class_id}:v{version}": count
                for (class_id, version), count in sorted(class_version_counts.items())
            },
        },
        "errors": errors,
    }


def suggested_public_config(result: dict[str, Any]) -> dict[str, Any] | None:
    connection = result.get("connection")
    if not connection:
        return None
    return {
        "version": 1,
        "transport": {
            "type": "serial_hdlc",
            "device": result["device"],
            "baudrate": connection["baudrate"],
            "serial": connection["serial"],
            "response_timeout_ms": 1000,
            "inter_request_delay_ms": 100,
            "session_guard_ms": 500,
        },
        "scan": {
            "mode": "get",
            "total_get_attempts": 2,
            "association_view_first": True,
            "common_catalogue": True,
            "enumeration_timeout_ms": 1000,
            "timeout_breaker_threshold": 4,
        },
        "profiles": [
            {
                "name": "public",
                "role": "public",
                "client_address": connection["client_address"],
                "server": {
                    "logical_address": connection["server_logical_address"],
                    "physical_address": connection["server_physical_address"],
                },
                "hdlc": {"address_size": connection["server_address_size"]},
                "authentication": {"mechanism": "none"},
                "security": {"policy": "none"},
                "proposed_max_pdu_size": 65535,
            }
        ],
        "output": {
            "directory": "./runs",
            "report_file": "report.json",
            "summary_file": "summary.md",
            "traffic_file": "traffic.jsonl",
            "redact_secrets": True,
        },
    }


def discover_public_device(
    options: DiscoveryOptions,
    traffic: TrafficLogger,
    *,
    progress: ProgressCallback | None = None,
    session_factory: Callable[..., Any] | None = None,
) -> dict[str, Any]:
    """Find and inspect the first working unauthenticated public association."""

    validate_serial_device(options.device)
    if session_factory is None:
        from .gurux_adapter import GuruxSession

        session_factory = GuruxSession
    progress = progress or (lambda _: None)
    endpoints = server_address_candidates(
        options.logical_addresses, options.physical_addresses
    )
    attempts: list[dict[str, Any]] = []
    selected_session = None
    selected_config = None
    selected_association = None
    selected_endpoint = None
    selected_baudrate = None
    selected_client = None

    try:
        for baudrate in options.baudrates:
            for endpoint in endpoints:
                # SAP 16 is the standard public client. Other configured client
                # candidates are tried only after this endpoint answered SNRM,
                # avoiding a multiplicative sweep across the entire address space.
                clients = options.client_addresses[:1]
                client_index = 0
                while client_index < len(clients):
                    client_address = clients[client_index]
                    progress(
                        {
                            "phase": "connection_probe",
                            "attempt": len(attempts) + 1,
                            "baudrate": baudrate,
                            "client_address": client_address,
                            **endpoint,
                            "message": (
                                f"{baudrate} baud, client {client_address}, "
                                f"server {endpoint['server_address']}"
                            ),
                        }
                    )
                    config = _runtime_config(
                        options,
                        baudrate=baudrate,
                        client_address=client_address,
                        endpoint=endpoint,
                        timeout_ms=options.probe_timeout_ms,
                    )
                    candidate = session_factory(
                        config,
                        baudrate,
                        traffic,
                        server_logical_address=int(endpoint["logical_address"]),
                        server_physical_address=int(endpoint["physical_address"]),
                        server_address_size=int(endpoint["address_size"]),
                        client_address=client_address,
                        profile_name="public_auto_discovery",
                    )
                    try:
                        association = candidate.connect()
                    except Exception as exc:
                        linked = bool(getattr(candidate, "_linked", False))
                        attempts.append(
                            {
                                "baudrate": baudrate,
                                "client_address": client_address,
                                **endpoint,
                                "hdlc_link_responded": linked,
                                "outcome": classify_exception(exc).value,
                                "error": f"{type(exc).__name__}: {exc}",
                            }
                        )
                        candidate.close()
                        if linked and len(clients) == 1:
                            clients = options.client_addresses
                        client_index += 1
                        continue

                    attempts.append(
                        {
                            "baudrate": baudrate,
                            "client_address": client_address,
                            **endpoint,
                            "hdlc_link_responded": True,
                            "outcome": Outcome.SUCCESS.value,
                        }
                    )
                    selected_session = candidate
                    selected_config = config
                    selected_association = association
                    selected_endpoint = endpoint
                    selected_baudrate = baudrate
                    selected_client = client_address
                    break
                if selected_session is not None:
                    break
            if selected_session is not None:
                break

        failure_counts = Counter(item["outcome"] for item in attempts)
        base_result: dict[str, Any] = {
            "schema_version": 1,
            "generated_at": utc_now(),
            "status": "failed" if selected_session is None else "completed",
            "device": options.device,
            "safety": {
                "association": "unauthenticated public only",
                "transmitted_services": ["SNRM", "AARQ", "GET", "RLRQ", "DISC"],
                "set_or_arbitrary_action_sent": False,
            },
            "probe_scope": {
                "baudrates": list(options.baudrates),
                "serial": {
                    "parity": options.serial.parity,
                    "data_bits": options.serial.data_bits,
                    "stop_bits": options.serial.stop_bits,
                },
                "primary_public_client": options.client_addresses[0],
                "fallback_clients_after_hdlc_response": list(
                    options.client_addresses[1:]
                ),
                "logical_addresses": list(options.logical_addresses),
                "physical_address_min": min(options.physical_addresses),
                "physical_address_max": max(options.physical_addresses),
                "server_candidates_per_baud": len(endpoints),
                "probe_timeout_ms": options.probe_timeout_ms,
                "security_setup_direct_instances": list(
                    options.security_setup_instances
                ),
            },
            "probe_summary": {
                "attempts": len(attempts),
                "hdlc_link_responses": sum(
                    bool(item["hdlc_link_responded"]) for item in attempts
                ),
                "outcomes": dict(sorted(failure_counts.items())),
            },
            "attempts": attempts,
            "limitations": [
                "Only logical-name referencing over direct serial HDLC is tested.",
                "IEC 62056-21 optical sign-on, WRAPPER/TCP, PLC and HDLC-over-IP are not tested.",
                "A successful client address identifies a working public SAP; discovery does not enumerate authenticated client roles.",
                "A secure client system title is provisioned client identity and usually cannot be derived from a public association.",
                "Invocation-counter objects are candidates only; their mapping to a secure client must still be verified.",
            ],
        }
        if selected_session is None:
            base_result["errors"] = [
                {
                    "phase": "connection_probe",
                    "type": "DiscoveryFailed",
                    "message": (
                        "No public DLMS association answered within the configured "
                        "baud, address, serial-format and timeout scope."
                    ),
                }
            ]
            return base_result

        assert selected_config is not None
        assert selected_association is not None
        assert selected_endpoint is not None
        selected_session.set_response_timeout(options.inspection_timeout_ms)
        inspection = _inspect_public_session(
            selected_session,
            selected_config,
            selected_association,
            progress,
            security_setup_instances=options.security_setup_instances,
        )
        base_result.update(inspection)
        base_result["connection"] = {
            "baudrate": selected_baudrate,
            "serial": {
                "parity": options.serial.parity,
                "data_bits": options.serial.data_bits,
                "stop_bits": options.serial.stop_bits,
            },
            "client_address": selected_client,
            "server_address": selected_endpoint["server_address"],
            "server_logical_address": selected_endpoint["logical_address"],
            "server_physical_address": selected_endpoint["physical_address"],
            "server_address_size": selected_endpoint["address_size"],
            "server_addressing_type": selected_endpoint["server_addressing_type"],
            "dlms_version": selected_association.get("dlms_version"),
            "max_receive_pdu_size": selected_association.get(
                "max_receive_pdu_size"
            ),
            "negotiated_conformance": selected_association.get(
                "negotiated_conformance", []
            ),
            "hdlc": selected_association.get("hdlc", {}),
        }
        if inspection["errors"]:
            base_result["status"] = "completed_with_warnings"
        return base_result
    finally:
        if selected_session is not None:
            warnings = selected_session.close()
            if warnings:
                # The result already holds a mutable error list on the success
                # path. Cleanup warnings must not erase an otherwise useful find.
                try:
                    base_result.setdefault("cleanup_warnings", []).extend(warnings)
                    if base_result.get("status") == "completed":
                        base_result["status"] = "completed_with_warnings"
                except UnboundLocalError:
                    pass


def _parse_integer_list(value: str, *, minimum: int, maximum: int) -> tuple[int, ...]:
    try:
        values = tuple(int(item.strip(), 0) for item in value.split(",") if item.strip())
    except ValueError as exc:
        raise argparse.ArgumentTypeError("expected comma-separated integers") from exc
    if not values or any(not minimum <= item <= maximum for item in values):
        raise argparse.ArgumentTypeError(
            f"values must be unique integers from {minimum} through {maximum}"
        )
    if len(set(values)) != len(values):
        raise argparse.ArgumentTypeError("values must not contain duplicates")
    return values


def _parse_physical_range(value: str) -> tuple[int, ...]:
    match = re.fullmatch(r"\s*(\d+)\s*[-:]\s*(\d+)\s*", value)
    if not match:
        raise argparse.ArgumentTypeError("expected MIN-MAX, for example 0-31")
    minimum, maximum = (int(item) for item in match.groups())
    if not 0 <= minimum <= maximum <= 127:
        raise argparse.ArgumentTypeError("physical range must stay within 0-127")
    return tuple(range(minimum, maximum + 1))


def _parse_security_setup_range(value: str) -> tuple[int, ...]:
    match = re.fullmatch(r"\s*(\d+)\s*[-:]\s*(\d+)\s*", value)
    if not match:
        raise argparse.ArgumentTypeError("expected MIN-MAX, for example 0-15")
    minimum, maximum = (int(item) for item in match.groups())
    if not 0 <= minimum <= maximum <= 255:
        raise argparse.ArgumentTypeError(
            "Security Setup instance range must stay within 0-255"
        )
    if maximum - minimum > 31:
        raise argparse.ArgumentTypeError(
            "Security Setup instance range may contain at most 32 values"
        )
    return tuple(range(minimum, maximum + 1))


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="dlms-autodiscover",
        description=(
            "Find a direct serial-HDLC DLMS public association and emit a reusable YAML config"
        ),
    )
    parser.add_argument("device", help="serial device, for example /dev/ttyUSB0")
    parser.add_argument(
        "--output-directory",
        type=Path,
        default=Path("./discovery-runs"),
        help="parent directory for discovery.json, traffic.jsonl and suggested-public-meter.yaml",
    )
    parser.add_argument(
        "--baud-rates",
        type=lambda value: _parse_integer_list(value, minimum=300, maximum=4_000_000),
        default=DEFAULT_BAUD_RATES,
        help="comma-separated probe order",
    )
    parser.add_argument(
        "--clients",
        type=lambda value: _parse_integer_list(value, minimum=1, maximum=127),
        default=DEFAULT_PUBLIC_CLIENTS,
        help="public client SAP candidates; the first is used for the broad sweep",
    )
    parser.add_argument(
        "--logical-addresses",
        type=lambda value: _parse_integer_list(value, minimum=0, maximum=127),
        default=DEFAULT_LOGICAL_ADDRESSES,
        help="comma-separated two-byte logical-device address candidates",
    )
    parser.add_argument(
        "--physical-range",
        type=_parse_physical_range,
        default=DEFAULT_PHYSICAL_ADDRESSES,
        metavar="MIN-MAX",
        help="physical server-address range; default 0-31",
    )
    parser.add_argument(
        "--deep",
        action="store_true",
        help="expand the physical address sweep to 0-127",
    )
    parser.add_argument(
        "--probe-timeout-ms",
        type=int,
        default=350,
        help="timeout for each endpoint probe; default 350",
    )
    parser.add_argument(
        "--inspection-timeout-ms",
        type=int,
        default=1500,
        help="timeout for Association View and metadata GETs; default 1500",
    )
    title_scope = parser.add_mutually_exclusive_group()
    title_scope.add_argument(
        "--security-setup-range",
        type=_parse_security_setup_range,
        default=DEFAULT_SECURITY_SETUP_INSTANCES,
        metavar="MIN-MAX",
        help="directly probe class-64 instances when no server title is exposed; default 0-15",
    )
    title_scope.add_argument(
        "--no-direct-system-title-probes",
        action="store_true",
        help="use only AARE and Association View-advertised Security Setup objects",
    )
    parser.add_argument("--parity", choices=("none", "even", "odd"), default="none")
    parser.add_argument("--data-bits", choices=(7, 8), type=int, default=8)
    parser.add_argument("--stop-bits", choices=(1.0, 1.5, 2.0), type=float, default=1.0)
    parser.add_argument(
        "--json",
        action="store_true",
        help="also print the complete discovery JSON to stdout",
    )
    return parser


def _run_directory(parent: Path) -> Path:
    stamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H%M%SZ")
    candidate = parent / stamp
    suffix = 1
    while candidate.exists():
        candidate = parent / f"{stamp}-{suffix}"
        suffix += 1
    candidate.mkdir(parents=True)
    return candidate


def _console_progress(console: Console) -> ProgressCallback:
    last_baudrate = None

    def update(event: dict[str, Any]) -> None:
        nonlocal last_baudrate
        if event.get("phase") == "connection_probe":
            baudrate = event.get("baudrate")
            if baudrate != last_baudrate:
                last_baudrate = baudrate
                console.print(f"Probing {baudrate} baud...")
        elif event.get("message"):
            console.print(str(event["message"]))

    return update


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    console = Console()
    if not 50 <= args.probe_timeout_ms <= 10_000:
        parser.error("--probe-timeout-ms must be from 50 through 10000")
    if not 100 <= args.inspection_timeout_ms <= 60_000:
        parser.error("--inspection-timeout-ms must be from 100 through 60000")

    physical_addresses = (
        DEEP_PHYSICAL_ADDRESSES if args.deep else args.physical_range
    )
    options = DiscoveryOptions(
        device=args.device,
        baudrates=args.baud_rates,
        client_addresses=args.clients,
        logical_addresses=args.logical_addresses,
        physical_addresses=physical_addresses,
        serial=SerialSettings(
            parity=args.parity,
            data_bits=args.data_bits,
            stop_bits=args.stop_bits,
        ),
        probe_timeout_ms=args.probe_timeout_ms,
        inspection_timeout_ms=args.inspection_timeout_ms,
        security_setup_instances=(
            ()
            if args.no_direct_system_title_probes
            else args.security_setup_range
        ),
    )

    try:
        # Validate before creating a run directory so a missing or inaccessible
        # device does not leave an empty evidence artifact behind.
        validate_serial_device(args.device)
        run_directory = _run_directory(args.output_directory)
        traffic_path = run_directory / "traffic.jsonl"
        with TrafficLogger(traffic_path) as traffic:
            result = discover_public_device(
                options,
                traffic,
                progress=_console_progress(console),
            )
        result["artifacts"] = {
            "directory": str(run_directory.resolve()),
            "traffic": str(traffic_path.resolve()),
            "discovery": str((run_directory / "discovery.json").resolve()),
            "suggested_config": None,
        }
        config = suggested_public_config(result)
        if config is not None:
            config_path = run_directory / "suggested-public-meter.yaml"
            config_path.write_text(
                yaml.safe_dump(config, sort_keys=False), encoding="utf-8"
            )
            result["artifacts"]["suggested_config"] = str(config_path.resolve())
        discovery_path = run_directory / "discovery.json"
        discovery_path.write_text(
            json.dumps(result, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
        )
    except KeyboardInterrupt:
        Console(stderr=True).print("[yellow]Cancelled.[/yellow]")
        return 130
    except (OSError, RuntimeError, ValueError) as exc:
        Console(stderr=True).print(f"[red]Error:[/red] {exc}")
        return 2

    if result["status"] == "failed":
        console.print("[red]No public DLMS association found.[/red]")
        console.print(f"Evidence: {result['artifacts']['discovery']}")
        console.print("Try --deep, a larger timeout, or the meter's documented serial format.")
        if args.json:
            console.print_json(json.dumps(result))
        return 2

    connection = result["connection"]
    stop_bits = connection["serial"]["stop_bits"]
    rendered_stop_bits = (
        str(int(stop_bits)) if float(stop_bits).is_integer() else str(stop_bits)
    )
    console.print("[green]Public DLMS association discovered.[/green]")
    console.print(
        "{} baud {}{}{}, client {}, server {} (logical {}, physical {}, {} byte)".format(
            connection["baudrate"],
            connection["serial"]["data_bits"],
            str(connection["serial"]["parity"])[0].upper(),
            rendered_stop_bits,
            connection["client_address"],
            connection["server_address"],
            connection["server_logical_address"],
            connection["server_physical_address"],
            connection["server_address_size"],
        )
    )
    console.print(
        f"DLMS version: {connection.get('dlms_version')}; "
        f"meter identity: {result.get('meter_identity') or 'not publicly readable'}"
    )
    titles = result.get("system_titles", [])
    if titles:
        for title in titles:
            console.print(
                f"{str(title['kind']).title()} system title: {title['hex']} "
                f"({title['source']})"
            )
    else:
        checked = result.get("system_title_retrieval", {}).get(
            "direct_probes_attempted", 0
        )
        suffix = (
            f"; attempted {checked} direct Security Setup GETs"
            if checked
            else ""
        )
        console.print(
            "System title: not exposed through public access" + suffix
        )
    console.print(f"Discovery report: {result['artifacts']['discovery']}")
    console.print(f"Reusable config: {result['artifacts']['suggested_config']}")
    if args.json:
        console.print_json(json.dumps(result))
    return 0


if __name__ == "__main__":
    sys.exit(main())
