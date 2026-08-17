"""Rich-guided setup and non-scrolling scan progress presentation."""

from __future__ import annotations

import glob
import json
import os
from dataclasses import replace
from pathlib import Path
from typing import Any

from rich.console import Console
from rich.progress import (
    BarColumn,
    MofNCompleteColumn,
    Progress,
    SpinnerColumn,
    TaskProgressColumn,
    TextColumn,
    TimeElapsedColumn,
)
from rich.prompt import Confirm, IntPrompt, Prompt
from rich.table import Table

from .config import AppConfig, ProfileConfig, SecureProfile, dump_config, parse_config
from .workflow import CounterCandidate, PublicPreflight


class ScanUI:
    """Render one live task instead of printing one line per request."""

    def __init__(self, console: Console | None = None):
        self.console = console or Console()
        self._progress = Progress(
            SpinnerColumn(style="cyan"),
            TextColumn("[bold cyan]{task.fields[stage]:<11}[/bold cyan]"),
            BarColumn(bar_width=24),
            TaskProgressColumn(),
            MofNCompleteColumn(),
            TextColumn("[white]{task.description}[/white]", table_column=None),
            TimeElapsedColumn(),
            console=self.console,
            transient=False,
            auto_refresh=True,
            refresh_per_second=1,
            expand=True,
        )
        self._task_id: int | None = None
        self._last_action = "Starting scan"

    def _ensure_started(self) -> int:
        if self._task_id is None:
            self._progress.start()
            self._task_id = self._progress.add_task(
                self._last_action,
                total=None,
                stage="Setup",
            )
        return self._task_id

    def _update(
        self,
        *,
        stage: str,
        description: str,
        total: int | None = None,
        completed: int | None = None,
        advance: int | None = None,
    ) -> None:
        task_id = self._ensure_started()
        values: dict[str, Any] = {"stage": stage, "description": description}
        if total is not None:
            values["total"] = total
        if completed is not None:
            values["completed"] = completed
        if advance is not None:
            values["advance"] = advance
        self._last_action = description
        self._progress.update(task_id, refresh=True, **values)

    def progress(self, event: dict[str, Any]) -> None:
        phase = str(event.get("phase", "scan"))
        message = str(event.get("message", ""))
        if event.get("level") == "error":
            self.close()
            self.error(message or "Scan failed")
            return
        if phase == "scan_start":
            self.close()
            self.console.rule("Scan")
            return
        if phase == "invocation_counter_reuse_start":
            self.close()
            self.console.rule("Retry Invocation Counter")
            return
        if phase == "invocation_counter_reuse_attempt":
            counter = int(event["invocation_counter"])
            self.console.print(
                f"Attempt 0x{counter:08X} as invocation counter"
            )
            return
        if phase == "invocation_counter_recovery_get":
            counter = int(event["invocation_counter"])
            self.console.print(
                f"Verify association with safe counter 0x{counter:08X}"
            )
            return
        if phase == "invocation_counter_recovery_wait":
            self.console.print(message)
            return
        if phase == "baud_detection":
            self._update(
                stage="Discovery",
                description=f"Testing {int(event['baudrate'])} baud",
            )
            return
        if phase in {
            "server_address_detection",
            "server_address_detected",
            "invocation_counter_bootstrap",
            "secure_link_setup",
            "secure_association",
            "hls_authentication",
            "association_view",
            "public_union_inventory",
            "public_union_connect",
            "short_test_selected",
            "enumeration_timeout",
            "timeout_circuit_open",
            "timeout_circuit_recovered",
            "timeout_reconnect",
            "timeout_circuit_stopped",
        }:
            labels = {
                "server_address_detection": "Discovery",
                "server_address_detected": "Discovery",
                "invocation_counter_bootstrap": "Bootstrap",
                "secure_link_setup": "Secure link",
                "secure_association": "HLS-GMAC",
                "hls_authentication": "HLS-GMAC",
                "association_view": "Inventory",
                "public_union_inventory": "Public view",
                "public_union_connect": "Public test",
                "short_test_selected": "Short test",
                "enumeration_timeout": "GET scan",
                "timeout_circuit_open": "GET health check",
                "timeout_circuit_recovered": "GET scan",
                "timeout_reconnect": "Reconnect",
                "timeout_circuit_stopped": "GET scan stopped",
            }
            self._update(stage=labels[phase], description=message)
            return
        if phase == "get_plan":
            self._update(
                stage="GET scan",
                description=message,
                total=int(event.get("total", 0)),
                completed=0,
            )
            return
        if phase == "get_scan":
            action = (
                f"GET {event.get('logical_name')}  class {event.get('class_id')}  "
                f"attribute {event.get('attribute_id')}  attempt {event.get('attempt')}"
            )
            self._update(stage="GET scan", description=action)
            return
        if phase in {"get_list_scan", "get_list_fallback"}:
            self._update(stage="GET scan", description=message)
            return
        if phase == "get_complete":
            self._update(stage="GET scan", description=self._last_action, advance=1)
            return
        if phase == "public_union_plan":
            self._update(
                stage="Public test",
                description=message,
                total=int(event.get("total", 0)),
                completed=0,
            )
            return
        if phase == "public_union_get":
            self._update(stage="Public test", description=message)
            return
        if phase == "public_union_complete":
            self._update(stage="Public test", description=self._last_action, advance=1)
            return
        if phase in {
            "get_error",
            "association_view_error",
            "timeout_health_check_failed",
            "timeout_reconnect_failed",
        }:
            # Keep the single display stable. Detailed failures are available in
            # summary.md and report.json instead of accumulating in the terminal.
            self._update(stage="Warning", description=message)
            return
        if message:
            self._update(stage="Setup", description=message)

    def close(self) -> None:
        if self._task_id is not None:
            self._progress.stop()
            self._task_id = None

    def error(self, message: str) -> None:
        self.console.print(f"[red]Error:[/red] {message}")

    def summary(
        self,
        lines: list[str],
        report_path: Path,
        traffic_path: Path,
        summary_path: Path | None = None,
    ) -> None:
        self.close()
        self.console.rule("DLMS scan summary")
        for line in lines:
            self.console.print(line)
        if summary_path is not None:
            self.console.print(f"Readable report: [green]{summary_path}[/green]")
        self.console.print(f"Full JSON: [green]{report_path}[/green]")
        self.console.print(f"Traffic: [green]{traffic_path}[/green]")


def select_roles(
    config: AppConfig, console: Console | None = None
) -> tuple[ProfileConfig, ...]:
    """Prompt for one or more configured roles, defaulting to all."""

    console = console or Console()
    table = Table(title="Configured roles")
    table.add_column("Role")
    table.add_column("Profile")
    table.add_column("Client SAP", justify="right")
    for profile in config.profiles:
        table.add_row(profile.role, profile.name, str(profile.client_address))
    console.print(table)
    available = {profile.role: profile for profile in config.profiles}
    while True:
        answer = Prompt.ask(
            "Roles to scan (comma-separated)", default="all", console=console
        ).strip()
        if answer.lower() == "all":
            return config.profiles
        names = [item.strip() for item in answer.split(",") if item.strip()]
        unknown = [item for item in names if item not in available]
        if names and not unknown and len(set(names)) == len(names):
            return tuple(available[item] for item in names)
        if unknown:
            console.print(f"[red]Unknown roles:[/red] {', '.join(unknown)}")
        else:
            console.print("[red]Select at least one role without duplicates.[/red]")


def show_public_preflight(
    preflight: PublicPreflight, console: Console | None = None
) -> None:
    console = console or Console()
    transport = preflight.transport
    association = preflight.association
    console.rule("Public preflight")
    console.print(f"Meter identity: {preflight.meter_identity or 'unavailable'}")
    console.print(f"Serial interface: {transport['device']}")
    console.print(f"Baud rate: {transport['selected_baudrate']}")
    console.print(
        f"Server: {transport['selected_server_address']} "
        f"({transport['server_addressing_type']})"
    )
    console.print(
        "Server components: logical {} / physical {}".format(
            transport["selected_server_logical_address"],
            transport["selected_server_physical_address"],
        )
    )
    console.print(f"DLMS version: {association.get('dlms_version', 'unknown')}")
    console.print(f"Maximum PDU: {association.get('max_receive_pdu_size', 'unknown')}")
    console.print(f"Public objects: {preflight.association_view_objects}")
    conformance = association.get("negotiated_conformance", [])
    console.print("Conformance: " + (", ".join(conformance) or "not reported"))


def _counter_table(candidates: tuple[CounterCandidate, ...]) -> Table:
    table = Table(title="Public-readable unsigned counter candidates")
    table.add_column("#", justify="right")
    table.add_column("Class", justify="right")
    table.add_column("Logical name")
    table.add_column("Attr", justify="right")
    table.add_column("Current value", justify="right")
    table.add_column("Description")
    for index, item in enumerate(candidates, 1):
        table.add_row(
            str(index),
            str(item.class_id),
            item.logical_name,
            str(item.attribute_id),
            f"{item.value} (0x{item.value:08X})",
            item.description or "",
        )
    return table


def verify_counter_source(
    profile: SecureProfile,
    preflight: PublicPreflight,
    console: Console | None = None,
) -> CounterCandidate:
    """Require the operator to confirm a public counter source for one role."""

    console = console or Console()
    candidates = preflight.counter_candidates
    configured = profile.invocation_counter
    selected = next(
        (
            item
            for item in candidates
            if item.class_id == configured.class_id
            and item.logical_name == configured.logical_name
            and item.attribute_id == configured.attribute_id
        ),
        None,
    )
    console.rule(f"Invocation counter — {profile.role}")
    console.print(f"Client SAP: {profile.client_address}")
    console.print(
        "Client system title: " + profile.client_system_title.hex().upper()
    )
    if not candidates:
        raise RuntimeError(
            f"no public-readable unsigned counter candidates were found for role {profile.role}"
        )
    console.print(_counter_table(candidates))
    while True:
        if selected is not None:
            console.print(
                f"Candidate: class {selected.class_id}, {selected.logical_name}, "
                f"attribute {selected.attribute_id}"
            )
            console.print(
                f"Decoded current value: {selected.value} (0x{selected.value:08X})"
            )
            choice = Prompt.ask(
                "Use this invocation-counter object?",
                choices=("yes", "list", "manual", "abort"),
                default="yes",
                console=console,
            )
            if choice == "yes":
                return selected
            if choice == "abort":
                raise KeyboardInterrupt
        else:
            choice = "select"

        if choice == "list":
            console.print(_counter_table(candidates))
        if choice == "manual":
            logical_name = Prompt.ask("Logical name", console=console).strip()
            selected = next(
                (item for item in candidates if item.logical_name == logical_name),
                None,
            )
            if selected is None:
                console.print(
                    "[red]That object was not found among the validated public-readable candidates.[/red]"
                )
                continue
        else:
            number = IntPrompt.ask(
                "Select candidate", default=1, console=console
            )
            if not 1 <= number <= len(candidates):
                console.print("[red]Candidate number is out of range.[/red]")
                continue
            selected = candidates[number - 1]


def choose_invocation_counter_reuse_test(
    profile: SecureProfile,
    console: Console | None = None,
) -> bool:
    """Ask whether to run the bounded, deliberately unsafe replay diagnostic."""

    console = console or Console()
    console.print(
        "[yellow]Optional laboratory diagnostic:[/yellow] this sends two protected "
        "GET requests with invocation counters that have already been used. A "
        "conforming meter should reject them. The meter may terminate the secure "
        "association; fresh counters remain persisted and are never rolled back."
    )
    return Confirm.ask(
        f"Test invocation-counter reuse for role {profile.role}",
        default=False,
        console=console,
    )


def choose_read_plan(
    config: AppConfig,
    preflight: PublicPreflight,
    console: Console | None = None,
    *,
    prompt_for_limit: bool = True,
) -> AppConfig:
    """Prompt for the currently implemented read-only scan limits."""

    console = console or Console()
    multiple = "multiple_references" in preflight.association.get(
        "negotiated_conformance", []
    )
    console.rule("Read-only scan plan")
    console.print("Test mode: READ only (SET and ACTION are deferred)")
    if multiple:
        use_batching = Confirm.ask(
            "Use GET-with-list batching for advertised readable attributes",
            default=True,
            console=console,
        )
        batch_size = (
            IntPrompt.ask(
                "Maximum attributes per list",
                default=config.scan.batch_size if config.scan.batch_size > 1 else 10,
                console=console,
            )
            if use_batching
            else 1
        )
        if not 1 <= batch_size <= 10:
            raise ValueError("GET-with-list batch size must be from 1 to 10")
        config = replace(config, scan=replace(config.scan, batch_size=batch_size))
    if not prompt_for_limit:
        return config
    limit = Prompt.ask(
        "Total GET limit per role (blank means full scan)",
        default=str(config.scan.get_limit or ""),
        console=console,
        show_default=False,
    ).strip()
    if not limit:
        return replace(
            config,
            scan=replace(config.scan, get_limit=None, object_limit=None),
        )
    try:
        parsed = int(limit)
    except ValueError:
        raise ValueError("GET limit must be a positive integer") from None
    if not 1 <= parsed <= 1_000_000:
        raise ValueError("GET limit must be from 1 to 1000000")
    return replace(
        config,
        scan=replace(config.scan, get_limit=parsed, object_limit=None),
    )


def _serial_candidates() -> list[str]:
    if os.name == "nt":
        return [f"COM{number}" for number in range(1, 33)]
    patterns = ("/dev/ttyUSB*", "/dev/ttyACM*", "/dev/ttyS*", "/dev/cu.*")
    return sorted({path for pattern in patterns for path in glob.glob(pattern)})


def interactive_config(console: Console | None = None) -> AppConfig:
    console = console or Console()
    console.rule("DLMS read-only scan setup")
    candidates = _serial_candidates()
    if candidates:
        console.print("Detected serial devices: " + ", ".join(candidates))
    default_device = candidates[0] if candidates else "/dev/ttyUSB0"
    device = Prompt.ask("Serial device", default=default_device, console=console)
    console.print("Transport: [bold]direct serial HDLC[/bold]")
    strategy = Prompt.ask(
        "Baud-rate strategy", choices=("auto", "fixed"), default="auto", console=console
    )
    baudrate: int | str = "auto"
    if strategy == "fixed":
        baudrate = IntPrompt.ask("Baud rate", default=9600, console=console)
    console.print("Scan mode: [bold]Mode 1 — GET only[/bold]")
    short_test = Confirm.ask(
        "Run a short test (first 10 objects after full Association View discovery)",
        default=False,
        console=console,
    )
    profile_name = Prompt.ask(
        "Profile", choices=("public", "hls_gmac_suite0"), default="public", console=console
    )
    secure = profile_name == "hls_gmac_suite0"
    union_profile_test = secure and Confirm.ask(
        "Test authenticated-only GET targets through the public client",
        default=False,
        console=console,
    )
    client_address = IntPrompt.ask(
        "Authenticated client address" if secure else "Public client address",
        default=1 if secure else 16,
        console=console,
    )
    logical_address = IntPrompt.ask("Server logical address", default=0 if secure else 1, console=console)
    physical_address = IntPrompt.ask("Server physical address", default=1, console=console)
    profile: dict[str, Any] = {
        "name": profile_name,
        "client_address": client_address,
        "server": {"logical_address": logical_address, "physical_address": physical_address},
    }
    if secure:
        profile.update(
            {
                "client_system_title": Prompt.ask(
                    "Eight-byte client system title (hex: + 16 hex characters)", console=console
                ),
                "secrets": {
                    "gak": {
                        "inline": Prompt.ask(
                            "GAK (32 hexadecimal characters)", password=True, console=console
                        )
                    },
                    "guek": {
                        "inline": Prompt.ask(
                            "GUEK (32 hexadecimal characters)", password=True, console=console
                        )
                    },
                },
            }
        )
    config = parse_config(
        {
            "transport": {"device": device, "baudrate": baudrate},
            "scan": {
                "object_limit": 10 if short_test else None,
                "union_profile_test": union_profile_test,
            },
            "profiles": [profile],
        }
    )
    console.print("\nEffective settings:")
    console.print_json(json.dumps(config.redacted_dict()))
    if Confirm.ask("Save this configuration", default=False, console=console):
        destination = Path(Prompt.ask("Configuration path", default="meter-profiles.yaml", console=console))
        dump_config(config, destination)
        console.print(f"Saved {destination}")
    if not Confirm.ask("Start the authorized read-only scan", default=True, console=console):
        raise KeyboardInterrupt
    return config
