"""Command-line entry points."""

from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path

from rich.console import Console

from .catalogues import COMMON_OBIS, catalogue_names
from .config import ConfigError, load_config
from .reporter import load_report, summary_lines, write_report
from .scanner import scan_public
from .traffic_logger import TrafficLogger
from .tui import ScanUI, interactive_config


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="dlms-enum", description="Enumerate a smart meter through a public DLMS/COSEM serial-HDLC association")
    subparsers = parser.add_subparsers(dest="command", required=True)
    scan = subparsers.add_parser("scan", help="run a public GET-only scan")
    scan.add_argument("--config", type=Path, help="YAML configuration; omit for guided setup")
    validate = subparsers.add_parser("validate-config", help="validate a YAML configuration")
    validate.add_argument("config", type=Path)
    subparsers.add_parser("list-catalogues", help="list built-in catalogue data")
    render = subparsers.add_parser("report", help="render a concise summary from report.json")
    render.add_argument("path", type=Path, help="run directory or report.json path")
    render.add_argument("--json", action="store_true", help="print the canonical report unchanged")
    return parser


def _run_directory(base: str) -> Path:
    stamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H%M%SZ")
    candidate = Path(base) / stamp
    suffix = 1
    while candidate.exists():
        candidate = Path(base) / f"{stamp}-{suffix}"
        suffix += 1
    candidate.mkdir(parents=True)
    return candidate


def _scan(args: argparse.Namespace, console: Console) -> int:
    config = load_config(args.config) if args.config else interactive_config(console)
    run_directory = _run_directory(config.output.directory)
    traffic_path = run_directory / config.output.traffic_file
    report_path = run_directory / config.output.report_file
    ui = ScanUI(console)
    logger = TrafficLogger(traffic_path)
    try:
        report = scan_public(config, logger, progress=ui.progress)
    finally:
        logger.close()
    write_report(report, report_path, traffic_path)
    ui.summary(summary_lines(report), report_path.resolve(), traffic_path.resolve())
    status = report.get("run", {}).get("status")
    if status == "interrupted":
        return 130
    return 0 if status in ("completed", "completed_with_errors") else 2


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    console = Console()
    try:
        if args.command == "scan":
            return _scan(args, console)
        if args.command == "validate-config":
            config = load_config(args.config)
            console.print(f"[green]Valid[/green]: {args.config}")
            console.print_json(json.dumps(config.redacted_dict()))
            return 0
        if args.command == "list-catalogues":
            for name in catalogue_names():
                console.print(f"{name}: {len(COMMON_OBIS)} entries")
            return 0
        if args.command == "report":
            report = load_report(args.path)
            if args.json:
                console.print_json(json.dumps(report))
            else:
                for line in summary_lines(report):
                    console.print(line)
            return 0
    except KeyboardInterrupt:
        Console(stderr=True).print("[yellow]Cancelled.[/yellow]")
        return 130
    except (ConfigError, OSError, RuntimeError, ValueError) as exc:
        Console(stderr=True).print(f"[red]Error:[/red] {exc}")
        return 2
    parser.error("unknown command")
    return 2
