"""Rich-guided setup and non-scrolling scan progress presentation."""

from __future__ import annotations

import glob
import json
import os
from dataclasses import replace
from pathlib import Path
from typing import Any

from rich.console import Console
from rich.panel import Panel
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


def choose_association_view_mode(
    *, role: str, snapshot: dict[str, Any] | None, console: Console | None = None
) -> tuple[str, bool]:
    """Choose whether to download, reuse, or compare an Association View."""

    console = console or Console()
    console.rule(f"Association View — {role}")
    if snapshot is None:
        console.print(
            "No reusable view exists for this device and role; the meter view will be read."
        )
        save = Confirm.ask(
            "Save the discovered view for future scans", default=True, console=console
        )
        return "live", save
    console.print(
        "Saved: [cyan]{}[/cyan]  Objects: [bold]{}[/bold]".format(
            snapshot.get("saved_at", "unknown"), snapshot.get("object_count", "—")
        )
    )
    mode = Prompt.ask(
        "Association View source",
        choices=("reuse", "live", "compare"),
        default="reuse",
        console=console,
    )
    save = mode in {"live", "compare"} and Confirm.ask(
        "Replace the reusable view with this fresh result",
        default=False,
        console=console,
    )
    return mode, save


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
            self._update(stage="Setup", description="Opening DLMS association")
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
        if phase == "authentication_scan_attempt":
            sequence = int(event.get("sequence", 1))
            self._update(
                stage="Auth scan",
                description=message,
                total=int(event.get("total", sequence)),
                completed=max(0, sequence - 1),
            )
            return
        if phase == "authentication_scan_result":
            status = str(event.get("status", "unknown"))
            style = {
                "authenticated": "bold green",
                "rejected": "yellow",
                "hls_validation_failed": "bold red",
                "inconsistent_with_known_good": "bold red reverse",
            }.get(status, "white")
            self._update(
                stage="Auth scan",
                description=f"[{style}]{message}[/{style}]",
                total=int(event.get("total", event.get("sequence", 1))),
                completed=int(event.get("sequence", 1)),
            )
            return
        if phase in {
            "authentication_counter_refresh",
            "authentication_scan_retry",
            "authentication_health_check",
        }:
            self._update(stage="Auth scan", description=message)
            return
        if phase == "authentication_health_result":
            status = str(event.get("status", "unknown"))
            style = "bold green" if status == "authenticated" else "bold red"
            self._update(
                stage="Auth health",
                description=f"[{style}]{message}[/{style}]",
            )
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
            "lls_association",
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
                "lls_association": "LLS",
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
        report: dict[str, Any],
        report_path: Path,
        traffic_path: Path,
        summary_path: Path | None = None,
    ) -> None:
        self.close()
        run = report.get("run", {})
        profile = (report.get("profiles") or [{}])[0]
        summary = profile.get("summary", {})
        association = profile.get("association", {})
        transport = report.get("transport", {})
        status = str(run.get("status", "unknown"))
        status_style = {
            "completed": "bold green",
            "completed_with_errors": "bold yellow",
            "failed": "bold red",
            "interrupted": "bold yellow",
        }.get(status, "bold white")
        title = (
            f"[bold]{profile.get('name', 'DLMS scan')}[/bold]  "
            f"[{status_style}]{status.replace('_', ' ').upper()}[/{status_style}]"
        )
        table = Table.grid(padding=(0, 2), expand=True)
        table.add_column(style="bold cyan", no_wrap=True)
        table.add_column()
        table.add_row(
            "Endpoint",
            f"client {association.get('client_address', '—')}  •  "
            f"server {transport.get('selected_server_address', '—')}  •  "
            f"{transport.get('selected_baudrate', '—')} baud  •  "
            f"{transport.get('server_addressing_type', 'unknown addressing')}",
        )
        view = report.get("association_view", {})
        view_label = str(view.get("mode", "live"))
        comparison = view.get("comparison")
        if isinstance(comparison, dict):
            view_label += (
                " • [green]matches saved view[/green]"
                if comparison.get("matches")
                else " • [yellow]{} added / {} removed / {} changed[/yellow]".format(
                    len(comparison.get("added", [])),
                    len(comparison.get("removed", [])),
                    len(comparison.get("changed", [])),
                )
            )
        table.add_row(
            "Association View",
            f"{view_label}  •  {summary.get('association_view_objects', 0)} objects",
        )
        candidates = report.get("candidate_generation", {})
        if candidates:
            table.add_row(
                "Known unlisted targets",
                "{} selected / {} available  •  providers: {}".format(
                    candidates.get("selected_targets", 0),
                    candidates.get("available_targets", 0),
                    ", ".join(candidates.get("providers", [])) or "none",
                )
                + (
                    "  •  {} skipped (already advertised)".format(
                        candidates.get("excluded_association_targets", 0)
                    )
                    if candidates.get("excluded_association_targets", 0)
                    else ""
                )
                + (
                    "  •  [green]{} verified[/green]  •  [dim]{} rejected as expected[/dim]"
                    .format(
                        candidates.get("verified_targets", 0),
                        candidates.get("negative_targets", 0),
                    )
                    if candidates.get("verified_targets", 0)
                    or candidates.get("negative_targets", 0)
                    else ""
                ),
            )
        expected_candidate_rejections = int(candidates.get("negative_targets", 0))
        unexpected_get_failures = max(
            0, int(summary.get("get_failed", 0)) - expected_candidate_rejections
        )
        table.add_row(
            "GET results",
            "[bold green]{} succeeded[/bold green]  •  "
            "[bold yellow]{} unexpected failures[/bold yellow]  •  "
            "[dim]{} expected candidate rejections[/dim]  •  "
            "{} inconclusive  •  {} not tested".format(
                summary.get("get_success", 0),
                unexpected_get_failures,
                expected_candidate_rejections,
                summary.get("get_inconclusive", 0),
                summary.get("get_not_tested", 0),
            ),
        )
        table.add_row(
            "Passive findings",
            f"{summary.get('advertised_set_attributes', 0)} SET attributes  •  "
            f"{summary.get('advertised_action_methods', 0)} ACTION methods  "
            "[dim](not executed)[/dim]",
        )
        if summary.get("security_setup_objects", 0) or summary.get(
            "image_transfer_objects", 0
        ):
            posture_findings = int(summary.get("security_posture_findings", 0))
            table.add_row(
                "Security posture",
                f"{summary.get('security_setup_objects', 0)} Security Setup  •  "
                f"{summary.get('image_transfer_objects', 0)} Image Transfer  •  "
                + (
                    f"[bold yellow]{posture_findings} public exposure finding(s)[/bold yellow]"
                    if posture_findings
                    else "[green]no broad public control advertised[/green]"
                ),
            )
        if summary.get("profile_buffers_read", 0):
            table.add_row(
                "Profile data",
                f"[bold]{summary.get('profile_rows_read', 0)} rows[/bold] from "
                f"{summary.get('profile_buffers_read', 0)} buffers",
            )
        errors = len(report.get("errors", []))
        if errors:
            table.add_row("Warnings", f"[yellow]{errors} recorded; see the readable report[/yellow]")
        self.console.print(Panel(table, title=title, border_style=status_style.split()[-1]))

        artifacts = Table.grid(padding=(0, 2))
        artifacts.add_column(style="bold")
        artifacts.add_column(style="green")
        if summary_path is not None:
            artifacts.add_row("Readable report", str(summary_path))
        artifacts.add_row("Full JSON", str(report_path))
        artifacts.add_row("Traffic", str(traffic_path))
        if view.get("export_file"):
            artifacts.add_row(
                "Association View", str(report_path.parent / view["export_file"])
            )
        self.console.print(artifacts)


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
    details = Table.grid(padding=(0, 2), expand=True)
    details.add_column(style="bold cyan", no_wrap=True)
    details.add_column()
    details.add_row("Meter", preflight.meter_identity or "[yellow]unavailable[/yellow]")
    details.add_row(
        "Serial link",
        f"{transport['device']}  •  [bold]{transport['selected_baudrate']} baud[/bold]",
    )
    details.add_row(
        "HDLC endpoint",
        f"server {transport['selected_server_address']}  •  "
        f"logical {transport['selected_server_logical_address']} / "
        f"physical {transport['selected_server_physical_address']}  •  "
        f"{transport['server_addressing_type']}",
    )
    details.add_row(
        "DLMS",
        f"version {association.get('dlms_version', 'unknown')}  •  "
        f"max PDU {association.get('max_receive_pdu_size', 'unknown')}  •  "
        f"[bold]{preflight.association_view_objects} public objects[/bold]",
    )
    conformance = association.get("negotiated_conformance", [])
    details.add_row("Conformance", ", ".join(conformance) or "not reported")
    console.print(Panel(details, title="[bold]Public preflight[/bold]", border_style="green"))


def show_authentication_matrix(
    report: dict[str, Any], console: Console | None = None
) -> None:
    """Render one role-by-mechanism result matrix after all probes finish."""

    console = console or Console()
    matrix = report.get("authentication_matrix", {})
    roles = matrix.get("roles", [])
    table = Table(
        title="Authentication result matrix",
        caption=(
            "Authenticated = complete association (including HLS validation). "
            "Inconsistent = the same role worked in the normal scan."
        ),
        show_lines=False,
    )
    table.add_column("Mechanism")
    for role in roles:
        table.add_column(
            f"{role['role']}\nclient {role['client_address']}",
            justify="center",
        )
    for row in matrix.get("rows", []):
        display_name = row.get("display_name") or str(
            row.get("mechanism", "unknown")
        ).upper()
        status_styles = {
            "authenticated": "bold green",
            "rejected": "yellow",
            "hls_validation_failed": "bold red",
            "inconsistent_with_known_good": "bold red reverse",
            "not_tested_known_good_unavailable": "bold magenta",
            "prerequisite_failed": "magenta",
            "unsupported": "dim",
        }
        statuses = [
            str(row.get("roles", {}).get(role["role"], {}).get("status", "—"))
            for role in roles
        ]
        table.add_row(
            str(display_name),
            *[
                f"[{status_styles.get(status, 'white')}]{status.replace('_', ' ')}"
                f"[/{status_styles.get(status, 'white')}]"
                for status in statuses
            ],
        )
    console.print(table)

    health_table = Table(
        title="Known-good connection checks",
        caption=(
            "Each check uses a fresh association. Secure checks refresh and "
            "advance invocation-counter state."
        ),
    )
    health_table.add_column("Role")
    health_table.add_column("After mechanism")
    health_table.add_column("Known-good method")
    health_table.add_column("Status")
    health_rows = 0
    for profile in report.get("profiles", []):
        scan = profile.get("authentication_scan", {})
        for check in scan.get("health_checks", []):
            status = str(check.get("status", "unknown"))
            style = "green" if status == "authenticated" else "bold red"
            health_table.add_row(
                str(profile.get("role", profile.get("name", "unknown"))),
                str(check.get("after_mechanism", "—")),
                str(check.get("mechanism", "—")),
                f"[{style}]{status.replace('_', ' ')}[/{style}]",
            )
            health_rows += 1
    if health_rows:
        console.print(health_table)


def show_capability_comparison(
    report: dict[str, Any], console: Console | None = None
) -> None:
    """Render compact public-versus-authenticated permission totals."""

    console = console or Console()
    table = Table(
        title="Public versus authenticated permissions",
        caption="Advertised rights only; SET and ACTION were not sent",
    )
    table.add_column("Role")
    table.add_column("Operation")
    table.add_column("Public", justify="right")
    table.add_column("Authenticated", justify="right")
    table.add_column("Public broader", justify="right", style="yellow")
    table.add_column("Authenticated broader", justify="right", style="green")
    for comparison in report.get("comparisons", []):
        role = str(comparison.get("authenticated_role", "authenticated"))
        for index, operation in enumerate(("GET", "SET", "ACTION")):
            summary = comparison.get("summary", {}).get(operation, {})
            table.add_row(
                role if index == 0 else "",
                operation,
                str(summary.get("public_advertised", 0)),
                str(summary.get("authenticated_advertised", 0)),
                str(summary.get("public_only", 0) + summary.get("public_broader", 0)),
                str(
                    summary.get("authenticated_only", 0)
                    + summary.get("authenticated_broader", 0)
                ),
            )
    console.print(table)


def _counter_table(candidates: tuple[CounterCandidate, ...]) -> Table:
    table = Table(title="Public-readable unsigned counter candidates")
    table.add_column("#", justify="right")
    table.add_column("Class", justify="right")
    table.add_column("Logical name")
    table.add_column("Attr", justify="right")
    table.add_column("Current value", justify="right")
    table.add_column("Description")
    for index, item in enumerate(candidates, 1):
        current_value = (
            f"{item.value} (0x{item.value:08X})"
            if item.value is not None
            else "not read"
        )
        table.add_row(
            str(index),
            str(item.class_id),
            item.logical_name,
            str(item.attribute_id),
            current_value,
            item.description or "",
        )
    return table


def _counter_logical_name(value: str) -> str | None:
    parts = value.split(".")
    if len(parts) != 6 or any(not part.isdigit() for part in parts):
        return None
    octets = tuple(int(part) for part in parts)
    return value if all(0 <= part <= 0xFF for part in octets) else None


def verify_counter_source(
    profile: SecureProfile,
    preflight: PublicPreflight,
    console: Console | None = None,
) -> CounterCandidate:
    """Select a listed counter by number or accept an operator-supplied source."""

    console = console or Console()
    candidates = preflight.counter_candidates
    configured = profile.invocation_counter
    console.rule(f"Invocation counter — {profile.role}")
    console.print(f"Client SAP: {profile.client_address}")
    console.print(
        "Client system title: " + profile.client_system_title.hex().upper()
    )
    if candidates:
        console.print(_counter_table(candidates))
    else:
        console.print(
            "[yellow]No public-readable counter candidates were found. Enter a "
            "counter-object logical name to attempt a direct public read.[/yellow]"
        )
    configured_index = next(
        (
            index
            for index, item in enumerate(candidates, 1)
            if item.class_id == configured.class_id
            and item.logical_name == configured.logical_name
            and item.attribute_id == configured.attribute_id
        ),
        None,
    )
    while True:
        answer = Prompt.ask(
            "Select candidate number or enter an invocation-counter logical name",
            default=(
                str(configured_index)
                if configured_index is not None
                else configured.logical_name
            ),
            console=console,
        ).strip()
        selected: CounterCandidate | None = None
        if answer.isdigit():
            number = int(answer)
            if 1 <= number <= len(candidates):
                selected = candidates[number - 1]
            else:
                console.print(
                    f"[red]Candidate number must be from 1 to {len(candidates)}.[/red]"
                )
                continue
        else:
            logical_name = _counter_logical_name(answer)
            if logical_name is None:
                console.print(
                    "[red]Enter a displayed candidate number or a valid six-part "
                    "logical name.[/red]"
                )
                continue
            selected = next(
                (item for item in candidates if item.logical_name == logical_name),
                CounterCandidate(
                    class_id=1,
                    logical_name=logical_name,
                    attribute_id=2,
                    value=None,
                    description="Operator-supplied counter object",
                    source="operator_supplied",
                ),
            )

        if selected.value is not None:
            console.print(
                f"Selected: class {selected.class_id}, {selected.logical_name}, "
                f"attribute {selected.attribute_id}"
            )
            console.print(
                f"Decoded current value: {selected.value} (0x{selected.value:08X})"
            )
        else:
            console.print(
                f"Selected operator-supplied object: class {selected.class_id}, "
                f"{selected.logical_name}, attribute {selected.attribute_id}"
            )
            console.print(
                "[yellow]This object was not read during preflight. The scan will "
                "attempt a direct public read before secure association.[/yellow]"
            )
        if Confirm.ask(
            "Use this invocation-counter object", default=True, console=console
        ):
            return selected


def prompt_secret(prompt_text: str, console: Console | None = None) -> str:
    """Ask for a credential with masked input; an empty answer skips the role."""

    console = console or Console()
    return Prompt.ask(prompt_text, password=True, console=console).strip()


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
    authentication_scan = Confirm.ask(
        "Run an authentication-method matrix after the normal scan",
        default=False,
        console=console,
    )
    profile_name = Prompt.ask(
        "Profile",
        choices=("public", "lls", "hls_gmac_suite0"),
        default="public",
        console=console,
    )
    secure = profile_name == "hls_gmac_suite0"
    lls = profile_name == "lls"
    union_profile_test = secure and Confirm.ask(
        "Test authenticated-only GET targets through the public client",
        default=False,
        console=console,
    )
    client_address = IntPrompt.ask(
        "Authenticated client address" if secure or lls else "Public client address",
        default=1 if secure else 32 if lls else 16,
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
    elif lls:
        profile["authentication"] = {
            "mechanism": "low",
            "password": {
                "env": Prompt.ask(
                    "Environment variable containing the LLS password",
                    default="DLMS_LLS_PASSWORD",
                    console=console,
                )
            },
        }
    config = parse_config(
        {
            "transport": {"device": device, "baudrate": baudrate},
            "scan": {
                "object_limit": 10 if short_test else None,
                "union_profile_test": union_profile_test,
            },
            "authentication_scan": (
                {
                    "enabled": True,
                    "password": {
                        "env": Prompt.ask(
                            "Environment variable containing the authentication password",
                            default="DLMS_PASSWORD",
                            console=console,
                        )
                    },
                }
                if authentication_scan
                else {"enabled": False}
            ),
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
