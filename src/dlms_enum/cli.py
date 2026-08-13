"""Command-line entry points."""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

from rich.console import Console
from rich.prompt import Confirm

from .catalogues import COMMON_OBIS
from .config import ConfigError, load_config, with_get_limit, with_object_limit
from .reporter import load_report, summary_lines, write_report
from .scanner import scan
from .traffic_logger import TrafficLogger
from .tui import ScanUI, interactive_config


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="dlms-enum", description="Read-only public or HLS-GMAC DLMS/COSEM serial-HDLC enumeration")
    subparsers = parser.add_subparsers(dest="command", required=True)
    scan_parser = subparsers.add_parser("scan", help="run a public or secure GET-only scan")
    scan_parser.add_argument("--config", type=Path, help="YAML configuration; omit for guided setup")
    scope = scan_parser.add_mutually_exclusive_group()
    scope.add_argument(
        "--short",
        action="store_true",
        help="read the full Association View, then scan only its first 10 objects",
    )
    scope.add_argument(
        "--full",
        action="store_true",
        help="scan all discovered objects without asking about a short test",
    )
    scope.add_argument(
        "--get-limit",
        type=int,
        metavar="N",
        help="test at most N mapped GET operations; report all remaining operations as NOT_TESTED",
    )
    validate = subparsers.add_parser("validate-config", help="validate a YAML configuration")
    validate.add_argument("config", type=Path)
    subparsers.add_parser("list-catalogues", help="list built-in catalogue data")
    render = subparsers.add_parser("report", help="render a concise summary from report.json")
    render.add_argument("path", type=Path, help="run directory or report.json path")
    render.add_argument("--json", action="store_true", help="print the canonical report unchanged")
    return parser


def _run_directory(base: str) -> Path:
    stamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H%M%SZ")
    base_path = Path(base)
    candidate = base_path / stamp
    suffix = 1
    while candidate.exists():
        candidate = base_path / f"{stamp}-{suffix}"
        suffix += 1
    candidate.mkdir(parents=True)
    return candidate


def _scan(args: argparse.Namespace, console: Console) -> int:
    config = load_config(args.config) if args.config else interactive_config(console)
    if args.short:
        config = with_object_limit(config, 10)
    elif args.full:
        config = with_object_limit(config, None)
    elif args.get_limit is not None:
        config = with_get_limit(config, args.get_limit)
    elif (
        args.config
        and config.scan.object_limit is None
        and config.scan.get_limit is None
        and console.is_terminal
        and sys.stdin.isatty()
    ):
        short_test = Confirm.ask(
            "Run a short test (scan only the first 10 objects after reading the full Association View)",
            default=False,
            console=console,
        )
        if short_test:
            config = with_object_limit(config, 10)
    for warning in config.warnings:
        console.print(f"[yellow]Warning:[/yellow] {warning}")
    run_directory = _run_directory(config.output.directory)
    traffic_path = run_directory / config.output.traffic_file
    report_path = run_directory / config.output.report_file
    summary_path = run_directory / config.output.summary_file
    ui = ScanUI(console)
    logger = TrafficLogger(traffic_path)
    try:
        report = scan(config, logger, progress=ui.progress)
    finally:
        ui.close()
        logger.close()
    write_report(report, report_path, traffic_path, summary_path)
    ui.summary(
        summary_lines(report),
        report_path.resolve(),
        traffic_path.resolve(),
        summary_path.resolve(),
    )
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
            for warning in config.warnings:
                console.print(f"[yellow]Warning:[/yellow] {warning}")
            console.print_json(json.dumps(config.redacted_dict()))
            return 0
        if args.command == "list-catalogues":
            console.print(f"common: {len(COMMON_OBIS)} entries")
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
