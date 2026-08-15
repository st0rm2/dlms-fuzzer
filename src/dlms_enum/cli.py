"""Command-line entry points."""

from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path

from rich.console import Console
from rich.prompt import Confirm

from .catalogues import COMMON_OBIS
from .config import ConfigError, SecureProfile, load_config, with_get_limit, with_object_limit
from .reporter import load_report, summary_lines, write_report
from .scanner import scan
from .traffic_logger import TrafficLogger
from .tui import (
    ScanUI,
    choose_read_plan,
    interactive_config,
    select_roles,
    show_public_preflight,
    verify_counter_source,
)
from .workflow import apply_preflight_endpoint, run_public_preflight, select_counter_source


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="dlms-enum", description="Read-only public or HLS-GMAC DLMS/COSEM serial-HDLC enumeration")
    subparsers = parser.add_subparsers(dest="command", required=True)
    scan_parser = subparsers.add_parser("scan", help="run a public or secure GET-only scan")
    scan_parser.add_argument("--config", type=Path, help="YAML configuration; omit for guided setup")
    scan_parser.add_argument(
        "--roles",
        help="comma-separated configured roles to scan; defaults to all roles",
    )
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


def _selected_roles(config, requested: str | None, console: Console):
    if requested:
        available = {profile.role: profile for profile in config.profiles}
        names = [item.strip() for item in requested.split(",") if item.strip()]
        unknown = [item for item in names if item not in available]
        if not names or unknown or len(set(names)) != len(names):
            detail = f": {', '.join(unknown)}" if unknown else ""
            raise ConfigError(
                f"--roles contains unknown, empty, or duplicate role names{detail}"
            )
        return tuple(available[name] for name in names)
    if console.is_terminal and sys.stdin.isatty():
        return select_roles(config, console)
    return config.profiles


def _safe_role_directory(role: str) -> str:
    candidate = re.sub(r"[^A-Za-z0-9_.-]+", "-", role).strip("-.")
    return candidate or "role"


def _scan(args: argparse.Namespace, console: Console) -> int:
    loaded_config = load_config(args.config) if args.config else interactive_config(console)
    selected = _selected_roles(loaded_config, args.roles, console)
    public_preflight_profile = next(
        (
            profile
            for profile in loaded_config.profiles
            if not isinstance(profile, SecureProfile)
        ),
        selected[0],
    )
    config = replace(loaded_config, profiles=selected)
    interactive = console.is_terminal and sys.stdin.isatty()
    if args.short:
        config = with_object_limit(config, 10)
    elif args.full:
        config = with_object_limit(config, None)
    elif args.get_limit is not None:
        config = with_get_limit(config, args.get_limit)
    for warning in config.warnings:
        console.print(f"[yellow]Warning:[/yellow] {warning}")
    run_directory = _run_directory(config.output.directory)
    ui = ScanUI(console)
    preflight_path = run_directory / "preflight-traffic.jsonl"
    preflight_logger = TrafficLogger(preflight_path)
    try:
        # The configured public role remains the preflight authority even when
        # the operator selected only secure roles for the full scan.
        preflight_config = replace(config, profiles=(public_preflight_profile,))
        preflight = run_public_preflight(
            preflight_config,
            preflight_logger,
            progress=ui.progress,
            counter_profiles=tuple(
                profile
                for profile in config.profiles
                if isinstance(profile, SecureProfile)
            ),
        )
    finally:
        ui.close()
        preflight_logger.close()

    show_public_preflight(preflight, console)
    config = apply_preflight_endpoint(config, preflight)
    verified_profiles = []
    verified_counter_sources = []
    for profile in config.profiles:
        if not isinstance(profile, SecureProfile):
            verified_profiles.append(profile)
            continue
        counter = profile.invocation_counter
        configured_candidate = next(
            (
                item
                for item in preflight.counter_candidates
                if item.class_id == counter.class_id
                and item.logical_name == counter.logical_name
                and item.attribute_id == counter.attribute_id
            ),
            None,
        )
        use_unsafe_override = False
        if configured_candidate is None and counter.unsafe_override is not None:
            use_unsafe_override = not interactive or Confirm.ask(
                f"The configured counter for {profile.role} could not be read. Use its "
                "explicit unsafe override instead of selecting a validated candidate",
                default=False,
                console=console,
            )
        if use_unsafe_override:
            verified_profiles.append(
                replace(
                    profile,
                    invocation_counter=replace(
                        counter,
                        meter_identity=(
                            preflight.meter_identity or counter.meter_identity
                        ),
                    ),
                )
            )
            verified_counter_sources.append(
                {
                    "role": profile.role,
                    "class_id": counter.class_id,
                    "logical_name": counter.logical_name,
                    "attribute_id": counter.attribute_id,
                    "value": None,
                    "live_read_validated": False,
                    "operator_verified": interactive,
                    "unsafe_override_used": True,
                }
            )
            continue
        if not preflight.counter_candidates:
            raise RuntimeError(
                f"role {profile.role} has no public-readable invocation-counter candidate"
            )
        if interactive:
            candidate = verify_counter_source(profile, preflight, console)
        else:
            candidate = configured_candidate
            if candidate is None:
                raise RuntimeError(
                    f"role {profile.role} invocation-counter source could not be "
                    "verified during non-interactive public preflight"
                )
        verified_profiles.append(
            select_counter_source(
                profile, candidate, meter_identity=preflight.meter_identity
            )
        )
        verified_counter_sources.append(
            {
                "role": profile.role,
                **candidate.as_dict(),
                "live_read_validated": True,
                "operator_verified": interactive,
            }
        )
    config = replace(config, profiles=tuple(verified_profiles))

    if interactive:
        config = choose_read_plan(
            config,
            preflight,
            console,
            prompt_for_limit=not (
                args.short or args.full or args.get_limit is not None
            ),
        )
    if interactive and not Confirm.ask(
        "Start the selected READ-only scans", default=True, console=console
    ):
        raise KeyboardInterrupt

    role_results = []
    statuses = []
    multiple_roles = len(config.profiles) > 1
    role_directory_names: dict[str, str] = {}
    used_directory_names: set[str] = set()
    for profile in config.profiles:
        base_name = _safe_role_directory(profile.role)
        directory_name = base_name
        suffix = 2
        while directory_name in used_directory_names:
            directory_name = f"{base_name}-{suffix}"
            suffix += 1
        used_directory_names.add(directory_name)
        role_directory_names[profile.role] = directory_name
    for profile in config.profiles:
        role_directory = (
            run_directory / role_directory_names[profile.role]
            if multiple_roles
            else run_directory
        )
        role_directory.mkdir(parents=True, exist_ok=True)
        traffic_path = role_directory / config.output.traffic_file
        report_path = role_directory / config.output.report_file
        summary_path = role_directory / config.output.summary_file
        role_ui = ScanUI(console)
        logger = TrafficLogger(traffic_path)
        try:
            report = scan(
                config.for_profile(profile), logger, progress=role_ui.progress
            )
        finally:
            role_ui.close()
            logger.close()
        report["preflight"] = preflight.as_dict()
        report["workflow"] = {
            "selected_roles": [item.role for item in config.profiles],
            "current_role": profile.role,
            "test_mode": "read_only",
            "verified_counter_sources": verified_counter_sources,
        }
        write_report(report, report_path, traffic_path, summary_path)
        role_ui.summary(
            summary_lines(report),
            report_path.resolve(),
            traffic_path.resolve(),
            summary_path.resolve(),
        )
        status = report.get("run", {}).get("status")
        statuses.append(status)
        role_results.append(
            {
                "role": profile.role,
                "profile": profile.name,
                "status": status,
                "directory": str(role_directory.relative_to(run_directory) or "."),
                "report": str(report_path.relative_to(run_directory)),
            }
        )

    workflow_report = {
        "schema_version": 1,
        "type": "multi_role_read_workflow",
        "selected_roles": [profile.role for profile in config.profiles],
        "preflight": preflight.as_dict(),
        "effective_configuration": config.redacted_dict(),
        "role_runs": role_results,
        "verified_counter_sources": verified_counter_sources,
    }
    (run_directory / "workflow.json").write_text(
        json.dumps(workflow_report, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    if "interrupted" in statuses:
        return 130
    return 0 if all(item in ("completed", "completed_with_errors") for item in statuses) else 2


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
