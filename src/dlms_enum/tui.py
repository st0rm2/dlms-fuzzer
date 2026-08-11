"""Rich-guided setup and progress presentation."""

from __future__ import annotations

import glob
import json
import os
from pathlib import Path
from typing import Any

from rich.console import Console
from rich.prompt import Confirm, IntPrompt, Prompt

from .config import AppConfig, dump_config, parse_config


class ScanUI:
    def __init__(self, console: Console | None = None):
        self.console = console or Console()
        self._last_baud: int | None = None

    def progress(self, event: dict[str, Any]) -> None:
        if event.get("level") == "error":
            self.error(str(event.get("message", "Scan failed")))
            return
        if event.get("phase") == "baud_detection":
            baudrate = int(event["baudrate"])
            if baudrate != self._last_baud:
                self.console.print(f"[cyan]Baud detection[/cyan]  {baudrate}")
                self._last_baud = baudrate
            return
        self.console.print(f"[dim]{event.get('phase', 'scan')}[/dim]  {event.get('message', '')}")

    def error(self, message: str) -> None:
        self.console.print(f"[red]Error:[/red] {message}")

    def summary(self, lines: list[str], report_path: Path, traffic_path: Path) -> None:
        self.console.rule("DLMS scan summary")
        for line in lines:
            self.console.print(line)
        self.console.print(f"Report: [green]{report_path}[/green]")
        self.console.print(f"Traffic: [green]{traffic_path}[/green]")


def _serial_candidates() -> list[str]:
    if os.name == "nt":
        return [f"COM{number}" for number in range(1, 33)]
    patterns = ("/dev/ttyUSB*", "/dev/ttyACM*", "/dev/ttyS*", "/dev/cu.*")
    return sorted({path for pattern in patterns for path in glob.glob(pattern)})


def interactive_config(console: Console | None = None) -> AppConfig:
    console = console or Console()
    console.rule("DLMS public-profile scan setup")
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
    client_address = IntPrompt.ask("Public client address", default=16, console=console)
    logical_address = IntPrompt.ask("Server logical address", default=1, console=console)
    physical_address = IntPrompt.ask("Server physical address", default=1, console=console)
    config = parse_config(
        {
            "version": 1,
            "transport": {"type": "serial_hdlc", "device": device, "baudrate": baudrate},
            "scan": {"mode": "get", "total_get_attempts": 2, "association_view_first": True, "common_catalogue": True},
            "profiles": [
                {
                    "name": "public",
                    "client_address": client_address,
                    "server": {"logical_address": logical_address, "physical_address": physical_address},
                    "authentication": {"mechanism": "none"},
                    "security": {"policy": "none"},
                }
            ],
            "output": {"directory": "./runs", "report_file": "report.json", "traffic_file": "traffic.jsonl", "redact_secrets": True},
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
