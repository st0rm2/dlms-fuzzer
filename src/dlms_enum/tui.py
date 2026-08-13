"""Rich-guided setup and non-scrolling scan progress presentation."""

from __future__ import annotations

import glob
import json
import os
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

from .config import AppConfig, dump_config, parse_config


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
            auto_refresh=False,
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
        if phase in {"get_error", "association_view_error"}:
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
