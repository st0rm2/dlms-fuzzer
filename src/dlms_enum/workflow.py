"""Interactive read-only scan planning and public bootstrap discovery."""

from __future__ import annotations

from dataclasses import asdict, dataclass, replace
from typing import Any, Callable

from .config import (
    AppConfig,
    CounterProfile,
    LlsProfile,
    ProfileConfig,
    SecureProfile,
)
from .scanner import (
    AUTHENTICATION_MECHANISMS,
    _GetRetryPolicy,
    _TimeoutCircuitBreaker,
    _advertised_attributes,
    _association_version,
    _baud_rates,
    _discover_association_view,
    _recover_timeout_circuit,
    _server_address_candidates,
    _set_session_timeout,
    _timeout_policy_scope,
    validate_serial_device,
)
from .result_model import Outcome, classify_exception


@dataclass(frozen=True)
class CounterCandidate:
    class_id: int
    logical_name: str
    attribute_id: int
    value: int | None
    description: str | None = None
    source: str = "public_association_view"

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class PublicPreflight:
    transport: dict[str, Any]
    association: dict[str, Any]
    meter_identity: str | None
    association_view_objects: int
    counter_candidates: tuple[CounterCandidate, ...]
    errors: tuple[dict[str, Any], ...] = ()
    role_suggestions: tuple[dict[str, Any], ...] = ()

    def as_dict(self) -> dict[str, Any]:
        return {
            "transport": self.transport,
            "association": self.association,
            "meter_identity": self.meter_identity,
            "association_view_objects": self.association_view_objects,
            "counter_candidates": [item.as_dict() for item in self.counter_candidates],
            "errors": list(self.errors),
            "role_suggestions": [dict(item) for item in self.role_suggestions],
        }


def _counter_value(decoded: dict[str, Any]) -> int | None:
    value = decoded.get("value")
    if isinstance(value, bool) or not isinstance(value, int):
        return None
    return value if 0 <= value <= 0xFFFFFFFF else None


# COSEM authentication-mechanism-name OID prefix: 2.16.756.5.8.2.<id>
_MECHANISM_OID_PREFIX = bytes.fromhex("608574050802")
_ROLE_SUGGESTION_LIMIT = 8


def _association_client_sap(decoded: dict[str, Any]) -> int | None:
    for key in ("value", "raw_value"):
        value = decoded.get(key)
        if (
            isinstance(value, list)
            and value
            and isinstance(value[0], int)
            and not isinstance(value[0], bool)
        ):
            return int(value[0])
    return None


def _association_mechanism_id(decoded: dict[str, Any]) -> int | None:
    for key in ("raw_value", "value"):
        value = decoded.get(key)
        if isinstance(value, dict) and value.get("encoding") == "octet-string":
            hex_value = value.get("hex")
            if not isinstance(hex_value, str):
                continue
            try:
                raw = bytes.fromhex(hex_value)
            except ValueError:
                continue
            if len(raw) == 7 and raw[:6] == _MECHANISM_OID_PREFIX:
                return int(raw[6])
        elif isinstance(value, str):
            try:
                numbers = [int(part) for part in value.replace(".", " ").split()]
            except ValueError:
                continue
            if len(numbers) == 7 and numbers[:6] in (
                [2, 16, 756, 5, 8, 2],
                [0, 0, 0, 5, 8, 2],
            ):
                return numbers[6]
    return None


def run_public_preflight(
    config: AppConfig,
    traffic: Any,
    *,
    progress: Callable[[dict[str, Any]], None] | None = None,
    counter_profiles: tuple[CounterProfile, ...] | None = None,
    collect_role_suggestions: bool = False,
) -> PublicPreflight:
    """Discover the public endpoint and readable counter candidates."""

    progress = progress or (lambda _: None)
    validate_serial_device(config.transport.device)
    from .gurux_adapter import GuruxSession

    role = config.profile
    counter_profiles = counter_profiles or (
        (role,)
        if isinstance(role, SecureProfile)
        else ()
    )
    public_client = (
        role.invocation_counter.public_client_address
        if isinstance(role, SecureProfile)
        else role.public_client_address
        if isinstance(role, LlsProfile)
        else role.client_address
    )
    selected_session = None
    association: dict[str, Any] = {}
    selected_endpoint: dict[str, Any] | None = None
    selected_baudrate: int | None = None
    errors: list[dict[str, Any]] = []
    try:
        for baudrate in _baud_rates(config):
            for endpoint in _server_address_candidates(config):
                progress(
                    {
                        "phase": "preflight_connection",
                        "message": (
                            f"Public preflight: server {endpoint['server_address']} "
                            f"at {baudrate} baud"
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
                    client_address=public_client,
                    profile_name="public_preflight",
                )
                try:
                    association = candidate.connect()
                except Exception as exc:
                    errors.append(
                        {
                            "phase": "preflight_connection",
                            "type": type(exc).__name__,
                            "message": str(exc),
                            "baudrate": baudrate,
                            **endpoint,
                        }
                    )
                    candidate.close()
                    continue
                selected_session = candidate
                selected_endpoint = endpoint
                selected_baudrate = baudrate
                break
            if selected_session is not None:
                break
        if selected_session is None or selected_endpoint is None or selected_baudrate is None:
            raise RuntimeError("public preflight could not establish a DLMS association")

        report_stub: dict[str, Any] = {"errors": []}
        objects, attempts, discovery_error = _discover_association_view(
            selected_session,
            config,
            report_stub,
            progress,
            error_phase="public_preflight_reconnaissance",
        )
        errors.extend(report_stub["errors"])
        if discovery_error is not None:
            raise RuntimeError(f"public preflight Association View failed: {discovery_error}")

        enumeration_timeout_applied = _set_session_timeout(
            selected_session, config.scan.enumeration_timeout_ms
        )
        timeout_scope = _timeout_policy_scope(
            config,
            enumeration_timeout_applied=enumeration_timeout_applied,
        )
        timeout_circuit = _TimeoutCircuitBreaker(
            config.scan.timeout_breaker_threshold
        )
        retry_policy = _GetRetryPolicy()
        health_probe: tuple[str, Any | None, int | None] = (
            "association_view",
            None,
            None,
        )
        preflight_inconclusive = False

        def record_candidate_outcome(
            outcome: Outcome,
        ) -> None:
            retry_policy.record(outcome)
            timeout_circuit.record(outcome)

        def recover_if_needed() -> bool:
            if not timeout_circuit.tripped:
                return True
            recovered, _ = _recover_timeout_circuit(
                selected_session,
                config,
                retry_policy,
                timeout_circuit,
                health_probe,
                timeout_scope,
                {"errors": errors},
                progress,
                profile_name="public_preflight",
                phase="public_preflight_timeout_circuit",
            )
            return recovered

        meter_identity: str | None = None
        try:
            meter_identity = selected_session.read_meter_identity()
        except Exception as exc:
            record_candidate_outcome(classify_exception(exc))
            errors.append(
                {
                    "phase": "preflight_meter_identity",
                    "type": type(exc).__name__,
                    "message": str(exc),
                }
            )
            if not recover_if_needed():
                preflight_inconclusive = True
        else:
            record_candidate_outcome(Outcome.SUCCESS)

        version = _association_version(objects)
        candidates: list[CounterCandidate] = []
        for target in (() if preflight_inconclusive else objects):
            if int(target.objectType) != 1:
                continue
            rights = _advertised_attributes(target, version).get(2)
            if not rights or not rights.get("read") or rights.get("requirements"):
                continue
            try:
                decoded = selected_session.read_attribute(
                    target,
                    2,
                    1,
                    phase="public_preflight",
                    purpose="counter_candidate_read",
                )
            except Exception as exc:
                record_candidate_outcome(classify_exception(exc))
                if not recover_if_needed():
                    preflight_inconclusive = True
                    break
                continue
            record_candidate_outcome(Outcome.SUCCESS)
            health_probe = ("attribute", target, 2)
            value = _counter_value(decoded)
            if value is None:
                continue
            candidates.append(
                CounterCandidate(
                    class_id=1,
                    logical_name=str(target.logicalName),
                    attribute_id=2,
                    value=value,
                    description=str(getattr(target, "description", "") or "") or None,
                )
            )

        for counter_profile in (() if preflight_inconclusive else counter_profiles):
            configured = counter_profile.invocation_counter
            already_present = any(
                item.class_id == configured.class_id
                and item.logical_name == configured.logical_name
                and item.attribute_id == configured.attribute_id
                for item in candidates
            )
            if not already_present:
                target = selected_session.create_object(
                    configured.class_id, configured.logical_name
                )
                try:
                    decoded = selected_session.read_attribute(
                        target,
                        configured.attribute_id,
                        1,
                        phase="public_preflight",
                        purpose="configured_counter_candidate_read",
                    )
                except Exception as exc:
                    record_candidate_outcome(classify_exception(exc))
                    if not recover_if_needed():
                        preflight_inconclusive = True
                        break
                else:
                    record_candidate_outcome(Outcome.SUCCESS)
                    health_probe = (
                        "attribute",
                        target,
                        configured.attribute_id,
                    )
                    value = _counter_value(decoded)
                    if value is not None:
                        candidates.insert(
                            0,
                            CounterCandidate(
                                class_id=configured.class_id,
                                logical_name=configured.logical_name,
                                attribute_id=configured.attribute_id,
                                value=value,
                                description="Configured invocation-counter candidate",
                                source="configured_direct_read",
                            ),
                        )

        role_suggestions: list[dict[str, Any]] = []
        association_objects = [
            target for target in objects if int(target.objectType) == 15
        ][:_ROLE_SUGGESTION_LIMIT]
        for target in (() if preflight_inconclusive or not collect_role_suggestions else association_objects):
            try:
                partners = selected_session.read_attribute(
                    target,
                    3,
                    1,
                    phase="public_preflight",
                    purpose="association_partners_read",
                )
                mechanism = selected_session.read_attribute(
                    target,
                    6,
                    1,
                    phase="public_preflight",
                    purpose="association_mechanism_read",
                )
            except Exception as exc:
                record_candidate_outcome(classify_exception(exc))
                errors.append(
                    {
                        "phase": "preflight_role_suggestion",
                        "type": type(exc).__name__,
                        "message": str(exc),
                        "logical_name": str(target.logicalName),
                    }
                )
                if not recover_if_needed():
                    preflight_inconclusive = True
                    break
                continue
            record_candidate_outcome(Outcome.SUCCESS)
            mechanism_id = _association_mechanism_id(mechanism)
            role_suggestions.append(
                {
                    "logical_name": str(target.logicalName),
                    "client_sap": _association_client_sap(partners),
                    "mechanism_id": mechanism_id,
                    "mechanism": (
                        AUTHENTICATION_MECHANISMS.get(mechanism_id)
                        if mechanism_id is not None
                        else None
                    ),
                }
            )

        transport = {
            "type": "serial_hdlc",
            "device": config.transport.device,
            "selected_baudrate": selected_baudrate,
            "selected_server_address": selected_endpoint["server_address"],
            "selected_server_logical_address": selected_endpoint["logical_address"],
            "selected_server_physical_address": selected_endpoint["physical_address"],
            "server_address_size": selected_endpoint["address_size"],
            "server_addressing_type": selected_endpoint["server_addressing_type"],
        }
        association["association_view_attempts"] = attempts
        association["timeout_policy"] = timeout_scope
        return PublicPreflight(
            transport=transport,
            association=association,
            meter_identity=meter_identity,
            association_view_objects=len(objects),
            counter_candidates=tuple(candidates),
            errors=tuple(errors),
            role_suggestions=tuple(role_suggestions),
        )
    finally:
        if selected_session is not None:
            selected_session.close()


def select_counter_source(
    profile: CounterProfile,
    candidate: CounterCandidate,
    *,
    meter_identity: str | None,
) -> CounterProfile:
    """Return a secure role using the verified public counter source."""

    counter = replace(
        profile.invocation_counter,
        class_id=candidate.class_id,
        logical_name=candidate.logical_name,
        attribute_id=candidate.attribute_id,
        meter_identity=meter_identity or profile.invocation_counter.meter_identity,
    )
    return replace(profile, invocation_counter=counter)


def apply_preflight_endpoint(config: AppConfig, preflight: PublicPreflight) -> AppConfig:
    """Pin subsequent role scans to the endpoint proven by public preflight."""

    transport = replace(
        config.transport,
        baudrate=int(preflight.transport["selected_baudrate"]),
    )
    profiles = tuple(
        replace(
            profile,
            server_logical_address=int(
                preflight.transport["selected_server_logical_address"]
            ),
            server_physical_address=int(
                preflight.transport["selected_server_physical_address"]
            ),
            server_address_size=int(preflight.transport["server_address_size"]),
        )
        for profile in config.profiles
    )
    return replace(config, transport=transport, profiles=profiles)


def profiles_by_role(config: AppConfig) -> dict[str, ProfileConfig]:
    return {profile.role: profile for profile in config.profiles}
