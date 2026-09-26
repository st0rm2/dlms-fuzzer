"""Zero-config discovery, credential setup, and reusable profile storage."""

from __future__ import annotations

import re
import hashlib
import os
import tempfile
from dataclasses import replace
from pathlib import Path
from typing import Any, Callable

from rich.console import Console
from rich.prompt import Confirm, Prompt

from .autodiscover import (
    DiscoveryOptions,
    discover_public_device,
    suggested_public_config,
)
from .config import (
    AppConfig, ConfigError, LlsProfile, PublicProfile, SecureProfile,
    SecretSource, _parse_profiles, dump_config, load_config, parse_config,
    resolve_lls_password, resolve_secret,
)
from .traffic_logger import TrafficLogger
from .tui import prompt_secret

# The discovery-backed scan flow creates its run directory before the
# suggested configuration exists, so both sides share this output parent.
DEFAULT_OUTPUT_DIRECTORY = "./runs"

_SECRET_KEY = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")

_ROLE_NAME_BASES = {"low": "meter_reader", "high_gmac": "meter_client"}


def profile_path(identity: str | None) -> Path | None:
    """Use a readable, traversal-safe name without merging sanitized identities."""
    if not identity:
        return None
    name = re.sub(r"[^A-Za-z0-9_.-]+", "-", identity).strip("-.")[:100]
    if name != identity:
        name = f"{name or 'meter'}-{hashlib.sha256(identity.encode()).hexdigest()[:16]}"
    return Path.home() / ".local/state/dlms-enum/profiles" / f"{name}.yaml"


def reuse_profile(
    config: AppConfig, path: Path | None, console: Console, *, interactive: bool
) -> tuple[AppConfig, bool]:
    """Reload saved roles while retaining the newly discovered endpoint."""
    if path is None or not path.exists():
        return config, True
    choice = Prompt.ask(
        "Saved profile found — reuse roles and credential references",
        choices=["reuse", "edit", "fresh"], default="reuse", console=console,
    ) if interactive else "reuse"
    if choice == "fresh":
        return config, True
    saved = load_config(path)
    endpoint = config.profile
    profiles = tuple(replace(
        profile,
        server_logical_address=endpoint.server_logical_address,
        server_physical_address=endpoint.server_physical_address,
        server_address_size=endpoint.server_address_size,
        **({"client_address": endpoint.client_address} if isinstance(profile, PublicProfile) else {}),
    ) for profile in saved.profiles)
    # Discovery remains the authority for the public SAP, including secure
    # counter reads, even if the meter has moved to another serial port.
    profiles = tuple(
        replace(p, invocation_counter=replace(p.invocation_counter, public_client_address=endpoint.client_address))
        if isinstance(p, SecureProfile) else
        replace(p, public_client_address=endpoint.client_address)
        if isinstance(p, LlsProfile) else p
        for p in profiles
    )
    if not any(isinstance(p, PublicProfile) for p in profiles):
        profiles = (endpoint,) + profiles
    if choice == "edit":
        profiles = tuple(p for p in profiles if isinstance(p, PublicProfile) or Confirm.ask(
            f"Keep saved role {p.role}", default=True, console=console
        ))
    return replace(saved, transport=config.transport, profiles=profiles,
                   authentication_scan=config.authentication_scan), choice == "edit"


def save_profile(config: AppConfig, path: Path) -> None:
    """Atomically save only reusable references, never resolved credentials."""
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=".profile-", dir=path.parent)
    os.close(fd)
    try:
        dump_config(config, temporary)
        os.replace(temporary, path)
    finally:
        Path(temporary).unlink(missing_ok=True)


def resolve_credentials(
    config: AppConfig, console: Console, *, interactive: bool
) -> AppConfig:
    """Resolve once in memory and prevent hidden getpass calls in headless runs."""
    def reader(label: str) -> str:
        if not interactive:
            raise ConfigError("credentials require a terminal; use env references and --secrets FILE")
        return prompt_secret(label, console)

    profiles = []
    for profile in config.profiles:
        try:
            if isinstance(profile, LlsProfile):
                password = resolve_lls_password(profile, prompt=reader)
                profile = replace(profile, password=SecretSource("inline", "hex:" + password.hex()))
            elif isinstance(profile, SecureProfile):
                keys = {name: SecretSource("inline", "hex:" + resolve_secret(
                    getattr(profile.secrets, name), name.upper(), prompt=reader
                ).hex()) for name in ("gak", "guek")}
                profile = replace(profile, secrets=replace(profile.secrets, **keys))
        except ConfigError as exc:
            raise ConfigError(f"role {profile.role}: {exc}") from None
        profiles.append(profile)
    authentication = config.authentication_scan
    if authentication.enabled and authentication.password is not None:
        password = resolve_lls_password(authentication, prompt=reader)
        authentication = replace(authentication, password=SecretSource("inline", "hex:" + password.hex()))
    return replace(config, profiles=tuple(profiles), authentication_scan=authentication)


class QuickscanError(RuntimeError):
    """Zero-config discovery or secrets-file loading failed."""


def discover_device(
    device: str,
    traffic: TrafficLogger,
    *,
    progress: Callable[[dict[str, Any]], None] | None = None,
    session_factory: Callable[..., Any] | None = None,
    discover: Callable[..., dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Run public endpoint discovery and return the raw discovery result."""

    discover = discover or discover_public_device
    return discover(
        DiscoveryOptions(device=device),
        traffic,
        progress=progress,
        session_factory=session_factory,
    )


def config_from_discovery(result: dict[str, Any]) -> AppConfig:
    """Turn a successful discovery result into a pinned AppConfig."""

    device = result.get("device", "")
    if not result.get("connection"):
        raise QuickscanError(
            f"no DLMS endpoint found on {device}; check the cabling and serial "
            "format, or widen the sweep with dlms-autodiscover --deep"
        )
    suggested = suggested_public_config(result)
    if suggested is None:
        raise QuickscanError(f"no DLMS endpoint found on {device}")
    suggested.setdefault("output", {})["directory"] = DEFAULT_OUTPUT_DIRECTORY
    return parse_config(suggested)


def discover_config(
    device: str,
    traffic: TrafficLogger,
    *,
    progress: Callable[[dict[str, Any]], None] | None = None,
    session_factory: Callable[..., Any] | None = None,
    discover: Callable[..., dict[str, Any]] | None = None,
) -> AppConfig:
    """Discover the public endpoint on device and return a pinned AppConfig."""

    return config_from_discovery(
        discover_device(
            device,
            traffic,
            progress=progress,
            session_factory=session_factory,
            discover=discover,
        )
    )


def load_secrets_file(path: str | Path) -> dict[str, str]:
    """Parse a KEY=VALUE secrets file; values are used verbatim, never expanded."""

    secrets_path = Path(path)
    try:
        lines = secrets_path.read_text(encoding="utf-8").splitlines()
    except OSError as exc:
        raise QuickscanError(f"cannot read secrets file {secrets_path}: {exc}") from exc
    secrets: dict[str, str] = {}
    for lineno, raw in enumerate(lines, start=1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        key, separator, value = line.partition("=")
        key = key.strip()
        if not separator or not _SECRET_KEY.fullmatch(key):
            raise QuickscanError(
                f"{secrets_path}:{lineno}: expected KEY=VALUE; "
                "comments start with # and shell expansion is not supported"
            )
        secrets[key] = value.strip()
    return secrets


def _prompt_hex_secret(
    console: Console, prompt_text: str, byte_length: int
) -> str | None:
    while True:
        answer = prompt_secret(
            f"{prompt_text} ({byte_length * 2} hexadecimal characters, "
            "empty to skip this role)",
            console,
        )
        if not answer:
            return None
        candidate = answer.strip().lower()
        if candidate.startswith("hex:"):
            candidate = candidate[4:]
        try:
            raw = bytes.fromhex(candidate)
        except ValueError:
            console.print("[red]Hexadecimal characters only.[/red]")
            continue
        if len(raw) != byte_length:
            console.print(
                f"[red]Expected exactly {byte_length} bytes "
                f"({byte_length * 2} hexadecimal characters).[/red]"
            )
            continue
        return raw.hex().upper()


def _unique_role(base: str, client_sap: int, taken: set[str]) -> str | None:
    if base not in taken:
        return base
    candidate = f"{base}_{client_sap}"
    return candidate if candidate not in taken else None


def build_profiles(
    config: AppConfig,
    suggestions: list[dict[str, Any]] | tuple[dict[str, Any], ...],
    discovery: dict[str, Any],
    console: Console,
    *,
    interactive: bool,
) -> AppConfig:
    """Offer credential-only setup for each non-public discovered association."""

    if not interactive or not suggestions:
        return config
    client_titles = [
        str(item["hex"])
        for item in discovery.get("system_titles", [])
        if item.get("kind") == "client" and item.get("hex")
    ]
    taken = {profile.role for profile in config.profiles}
    public_sap = next((p.client_address for p in config.profiles if isinstance(p, PublicProfile)), 16)
    new_profiles: list[Any] = []
    warnings: tuple[str, ...] = ()
    console.rule("Discovered associations")
    for suggestion in suggestions:
        mechanism = suggestion.get("mechanism")
        client_sap = suggestion.get("client_sap")
        logical_name = suggestion.get("logical_name")
        if mechanism in (None, "none") or client_sap is None:
            continue
        if not isinstance(client_sap, int) or isinstance(client_sap, bool) or not 1 <= client_sap <= 0x3FFF:
            continue
        if any(p.client_address == client_sap and (
            isinstance(p, LlsProfile) and mechanism == "low" or
            isinstance(p, SecureProfile) and mechanism == "high_gmac"
        ) for p in (*config.profiles, *new_profiles)):
            continue
        console.print(
            f"Association {logical_name}: client SAP {client_sap}, "
            f"authentication {mechanism}"
        )
        if mechanism not in _ROLE_NAME_BASES:
            console.print(
                f"[yellow]{mechanism} is not supported for guided setup; "
                "configure this role via YAML.[/yellow]"
            )
            continue
        if not Confirm.ask(
            f"Configure a {mechanism} role for client SAP {client_sap}",
            default=False,
            console=console,
        ):
            continue
        role = _unique_role(_ROLE_NAME_BASES[mechanism], client_sap, taken)
        if role is None:
            console.print(
                f"[yellow]No free role name for client SAP {client_sap}; "
                "configure this role via YAML.[/yellow]"
            )
            continue
        if mechanism == "low":
            password = prompt_secret(
                f"LLS password for client SAP {client_sap} "
                "(empty to skip this role)",
                console,
            )
            if not password:
                continue
            profile_dict: dict[str, Any] = {
                "name": "lls",
                "role": role,
                "client_address": client_sap,
                "public_client_address": public_sap,
                "authentication": {"mechanism": "low", "password": {"inline": password}},
            }
        else:
            if client_titles:
                console.print(
                    "Discovered client system titles: " + ", ".join(client_titles)
                )
            title = _prompt_hex_secret(console, "Client system title", 8)
            if title is None:
                continue
            gak = _prompt_hex_secret(console, "GAK", 16)
            if gak is None:
                continue
            guek = _prompt_hex_secret(console, "GUEK", 16)
            if guek is None:
                continue
            profile_dict = {
                "name": "hls_gmac_suite0",
                "role": role,
                "client_address": client_sap,
                "client_system_title": f"hex:{title}",
                "invocation_counter": {"public_client_address": public_sap},
                "secrets": {
                    "gak": {"inline": f"hex:{gak}"},
                    "guek": {"inline": f"hex:{guek}"},
                },
            }
        parsed, profile_warnings = _parse_profiles([profile_dict], None)
        new_profiles.extend(parsed)
        warnings += profile_warnings
        taken.add(role)
    if not new_profiles:
        return config
    return replace(
        config,
        profiles=config.profiles + tuple(new_profiles),
        warnings=config.warnings + warnings,
    )
