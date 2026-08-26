"""Command-line entry points."""

from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from rich.console import Console
from rich.prompt import Confirm

from .association_view import (
    compare_snapshots,
    default_cache_path,
    load_snapshot,
    snapshot_from_report,
    validate_snapshot,
    write_snapshot,
)
from .catalogues import CANDIDATE_PROVIDERS
from .capability_comparison import (
    build_workflow_comparison,
    write_workflow_comparison,
)
from .config import (
    ConfigError,
    PublicProfile,
    SecureProfile,
    load_config,
    with_get_limit,
    with_object_limit,
)
from .reporter import load_report, summary_lines, write_report
from .scanner import (
    AUTHENTICATION_DISPLAY_NAMES,
    AUTHENTICATION_MECHANISMS,
    run_authentication_scan,
    scan,
)
from .traffic_logger import TrafficLogger
from .tui import (
    ScanUI,
    choose_association_view_mode,
    choose_read_plan,
    choose_invocation_counter_reuse_test,
    interactive_config,
    select_roles,
    show_authentication_matrix,
    show_capability_comparison,
    show_public_preflight,
    verify_counter_source,
)
from .workflow import apply_preflight_endpoint, run_public_preflight, select_counter_source


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="dlms-enum",
        description="Read-only DLMS/COSEM enumeration and authentication scanning over serial HDLC",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)
    scan_parser = subparsers.add_parser(
        "scan", help="run normal GET-only role scans and an optional final authentication matrix"
    )
    scan_parser.add_argument("--config", type=Path, help="YAML configuration; omit for guided setup")
    scan_parser.add_argument(
        "--roles",
        help="comma-separated configured roles to scan; defaults to all roles",
    )
    scan_parser.add_argument(
        "--association-view-mode",
        choices=("live", "reuse", "compare"),
        help=(
            "read the meter view, reuse the saved per-device/role view, or compare "
            "a fresh view with the saved one"
        ),
    )
    scan_parser.add_argument(
        "--save-association-view",
        action="store_true",
        help="update the reusable per-device/role Association View after a live read",
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
            if isinstance(profile, PublicProfile)
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
    counter_reuse_tests: dict[str, bool] = {}
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
            verified_profile = replace(
                profile,
                invocation_counter=replace(
                    counter,
                    meter_identity=(
                        preflight.meter_identity or counter.meter_identity
                    ),
                ),
            )
            verified_profiles.append(verified_profile)
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
            counter_reuse_tests[profile.role] = (
                choose_invocation_counter_reuse_test(verified_profile, console)
                if interactive and isinstance(profile, SecureProfile)
                else False
            )
            continue
        if interactive:
            candidate = verify_counter_source(profile, preflight, console)
        else:
            if not preflight.counter_candidates:
                raise RuntimeError(
                    f"role {profile.role} has no public-readable invocation-counter candidate"
                )
            candidate = configured_candidate
            if candidate is None:
                raise RuntimeError(
                    f"role {profile.role} invocation-counter source could not be "
                    "verified during non-interactive public preflight"
                )
        verified_profile = select_counter_source(
            profile, candidate, meter_identity=preflight.meter_identity
        )
        verified_profiles.append(verified_profile)
        verified_counter_sources.append(
            {
                "role": profile.role,
                **candidate.as_dict(),
                "live_read_validated": candidate.value is not None,
                "operator_verified": interactive,
            }
        )
        counter_reuse_tests[profile.role] = (
            choose_invocation_counter_reuse_test(verified_profile, console)
            if interactive and isinstance(profile, SecureProfile)
            else False
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
    association_view_plans: dict[str, dict[str, Any]] = {}
    for profile in config.profiles:
        cache_path = default_cache_path(config.transport.device, profile.role)
        snapshot = None
        if cache_path.exists():
            try:
                snapshot = load_snapshot(cache_path)
                validate_snapshot(
                    snapshot,
                    device=config.transport.device,
                    role=profile.role,
                    client_address=profile.client_address,
                    meter_identity=preflight.meter_identity,
                    profile=profile.name,
                )
            except (OSError, ValueError) as exc:
                if getattr(args, "association_view_mode", None) in {"reuse", "compare"}:
                    raise RuntimeError(f"Cannot use {cache_path}: {exc}") from exc
                console.print(
                    f"[yellow]Ignoring incompatible Association View cache for "
                    f"{profile.role}:[/yellow] {exc}"
                )
                snapshot = None
        requested_view_mode = getattr(args, "association_view_mode", None)
        if requested_view_mode is not None:
            mode = requested_view_mode
            if mode in {"reuse", "compare"} and snapshot is None:
                raise RuntimeError(
                    f"Association View mode {mode!r} requires a saved view for "
                    f"device {config.transport.device} and role {profile.role}"
                )
            save = bool(
                getattr(args, "save_association_view", False)
                and mode in {"live", "compare"}
            )
        elif interactive:
            mode, save = choose_association_view_mode(
                role=profile.role, snapshot=snapshot, console=console
            )
        else:
            mode, save = "live", bool(getattr(args, "save_association_view", False))
        association_view_plans[profile.role] = {
            "mode": mode,
            "save": save,
            "snapshot": snapshot,
            "cache_path": cache_path,
        }
    if interactive and not Confirm.ask(
        "Start the selected READ-only scans", default=True, console=console
    ):
        raise KeyboardInterrupt

    role_results = []
    role_reports: dict[str, dict[str, Any]] = {}
    role_snapshots: dict[str, dict[str, Any]] = {}
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
        view_plan = association_view_plans[profile.role]
        console.rule(f"Normal scan — {profile.role}")
        view_phase = {
            "live": "fresh Association View",
            "reuse": "saved Association View",
            "compare": "fresh + saved-view comparison",
        }[view_plan["mode"]]
        console.print(
            f"[bold]{profile.name}[/bold]  •  client [bold cyan]{profile.client_address}[/bold cyan]  •  "
            f"association  •  {view_phase}  •  GET enumeration"
            + (
                ", invocation-counter replay diagnostic"
                if counter_reuse_tests.get(profile.role, False)
                else ""
            )
        )
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
                config.for_profile(profile),
                logger,
                progress=role_ui.progress,
                invocation_counter_reuse_test=counter_reuse_tests.get(
                    profile.role, False
                ),
                association_view_mode=view_plan["mode"],
                association_view_snapshot=view_plan["snapshot"],
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
            "invocation_counter_reuse_test_requested": counter_reuse_tests.get(
                profile.role, False
            ),
        }
        association_export_path = role_directory / "association-view.json"
        exported_snapshot = (
            view_plan["snapshot"] if view_plan["mode"] == "reuse" else None
        )
        if view_plan["mode"] != "reuse" and report.get("profiles"):
            try:
                exported_snapshot = snapshot_from_report(report)
            except ValueError:
                # Failed scans and lightweight test doubles may not have reached
                # Association View discovery, so there is nothing useful to export.
                exported_snapshot = None
        view_report = report.setdefault(
            "association_view",
            {"mode": view_plan["mode"], "source": "meter"},
        )
        if exported_snapshot is not None:
            write_snapshot(exported_snapshot, association_export_path)
            view_report["snapshot_saved_at"] = exported_snapshot.get("saved_at")
            if view_plan["mode"] == "compare":
                view_report["comparison"] = compare_snapshots(
                    view_plan["snapshot"], exported_snapshot
                )
            if view_plan["save"]:
                write_snapshot(exported_snapshot, view_plan["cache_path"])
        view_report.update(
            {
                "export_file": (
                    association_export_path.name
                    if exported_snapshot is not None
                    else None
                ),
                "cache_file": str(view_plan["cache_path"]),
                "cache_updated": bool(view_plan["save"] and exported_snapshot),
            }
        )
        write_report(report, report_path, traffic_path, summary_path)
        role_ui.summary(
            report,
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
                "association_view": (
                    str(association_export_path.relative_to(run_directory))
                    if exported_snapshot is not None
                    else None
                ),
                "association_view_mode": view_plan["mode"],
            }
        )
        role_reports[profile.role] = report
        if exported_snapshot is not None:
            role_snapshots[profile.role] = exported_snapshot

    capability_comparison = None
    public_profile = next(
        (profile for profile in config.profiles if isinstance(profile, PublicProfile)),
        None,
    )
    authenticated_profiles = [
        profile
        for profile in config.profiles
        if not isinstance(profile, PublicProfile) and profile.role in role_snapshots
    ]
    if (
        public_profile is not None
        and public_profile.role in role_snapshots
        and authenticated_profiles
    ):
        capability_comparison = build_workflow_comparison(
            role_snapshots[public_profile.role],
            [
                (role_snapshots[profile.role], role_reports.get(profile.role))
                for profile in authenticated_profiles
            ],
        )
        comparison_json_path = run_directory / "capability-comparison.json"
        comparison_markdown_path = run_directory / "capability-comparison.md"
        write_workflow_comparison(
            capability_comparison,
            comparison_json_path,
            comparison_markdown_path,
        )
        show_capability_comparison(capability_comparison, console)
        console.print(
            "Permission comparison: "
            f"[green]{comparison_markdown_path.resolve()}[/green]"
        )

    authentication_report = None
    if config.authentication_scan.enabled:
        console.rule("Final authentication scan")
        console.print(
            "Normal role scans are complete. Each authentication attempt now uses "
            "a fresh association. The known-good role is rechecked between methods; "
            "later tests stop if that continuity check fails."
        )
        authentication_traffic_path = run_directory / "authentication-traffic.jsonl"
        authentication_report_path = run_directory / "authentication-report.json"
        authentication_summary_path = run_directory / "authentication-summary.md"
        authentication_logger = TrafficLogger(authentication_traffic_path)
        authentication_ui = ScanUI(console)
        authentication_profiles = []
        try:
            for profile in config.profiles:
                result = run_authentication_scan(
                    config.for_profile(profile),
                    authentication_logger,
                    transport=preflight.transport,
                    meter_identity=preflight.meter_identity,
                    counter_candidates=preflight.counter_candidates,
                    progress=authentication_ui.progress,
                    known_good_association=next(
                        (
                            item.get("association")
                            for item in role_reports.get(profile.role, {}).get(
                                "profiles", []
                            )
                        ),
                        None,
                    ),
                )
                authentication_profiles.append(
                    {
                        "name": result["name"],
                        "role": result["role"],
                        "association": {
                            "client_address": result["client_address"],
                            "server_address": preflight.transport[
                                "selected_server_address"
                            ],
                        },
                        "authentication_scan": result["authentication_scan"],
                        "objects": [],
                        "summary": {
                            "mechanisms_total": len(
                                result["authentication_scan"]["results"]
                            ),
                            "mechanisms_attempted": sum(
                                item["attempted"]
                                for item in result["authentication_scan"]["results"]
                            ),
                            "mechanisms_authenticated": len(
                                result["authentication_scan"][
                                    "accepted_mechanisms"
                                ]
                            ),
                            "objects": 0,
                        },
                        "errors": result["errors"],
                    }
                )
        finally:
            authentication_ui.close()
            authentication_logger.close()

        mechanism_names = [
            AUTHENTICATION_MECHANISMS[index]
            for index in sorted(AUTHENTICATION_MECHANISMS)
        ]
        matrix_rows = []
        for mechanism in mechanism_names:
            cells = {}
            for profile_result in authentication_profiles:
                record = next(
                    item
                    for item in profile_result["authentication_scan"]["results"]
                    if item["mechanism"] == mechanism
                )
                cells[profile_result["role"]] = record
            matrix_rows.append(
                {
                    "mechanism": mechanism,
                    "display_name": AUTHENTICATION_DISPLAY_NAMES[mechanism],
                    "roles": cells,
                }
            )
        now = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
        authentication_errors = [
            error
            for item in authentication_profiles
            for error in item.get("errors", [])
        ]
        known_good_contradiction = any(
            result.get("status") == "inconsistent_with_known_good"
            for item in authentication_profiles
            for result in item["authentication_scan"].get("results", [])
        )
        known_good_health_failed = any(
            item["authentication_scan"].get("health_check_complete") is False
            for item in authentication_profiles
        )
        authentication_report = {
            "schema_version": 1,
            "type": "authentication_matrix",
            "run": {
                "id": run_directory.name + "-authentication",
                "started_at": now,
                "finished_at": now,
                "status": (
                    "completed_with_errors"
                    if authentication_errors
                    or known_good_contradiction
                    or known_good_health_failed
                    else "completed"
                ),
            },
            "effective_configuration": config.redacted_dict(),
            "transport": preflight.transport,
            "profiles": authentication_profiles,
            "authentication_matrix": {
                "roles": [
                    {
                        "role": item["role"],
                        "profile": item["name"],
                        "client_address": item["association"]["client_address"],
                    }
                    for item in authentication_profiles
                ],
                "rows": matrix_rows,
            },
            "capability_matrix": [],
            "errors": authentication_errors,
        }
        write_report(
            authentication_report,
            authentication_report_path,
            authentication_traffic_path,
            authentication_summary_path,
        )
        show_authentication_matrix(authentication_report, console)
        console.print(
            f"Authentication report: [green]{authentication_report_path.resolve()}[/green]"
        )

    workflow_report = {
        "schema_version": 1,
        "type": "multi_role_read_workflow",
        "selected_roles": [profile.role for profile in config.profiles],
        "preflight": preflight.as_dict(),
        "effective_configuration": config.redacted_dict(),
        "role_runs": role_results,
        "verified_counter_sources": verified_counter_sources,
        "invocation_counter_reuse_tests_requested": counter_reuse_tests,
        "capability_comparison": (
            {
                "status": "completed",
                "json": "capability-comparison.json",
                "summary": "capability-comparison.md",
                "public_role": capability_comparison.get("public_role"),
                "compared_roles": [
                    item.get("authenticated_role")
                    for item in capability_comparison.get("comparisons", [])
                ],
            }
            if capability_comparison is not None
            else {"status": "not_available"}
        ),
        "authentication_scan": (
            {
                "enabled": True,
                "status": authentication_report["run"]["status"],
                "report": "authentication-report.json",
                "traffic": "authentication-traffic.jsonl",
                "summary": "authentication-summary.md",
                "matrix": authentication_report["authentication_matrix"],
            }
            if authentication_report is not None
            else {"enabled": False, "status": "disabled"}
        ),
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
            for name, entries in CANDIDATE_PROVIDERS.items():
                console.print(
                    f"{name}: {len(entries)} objects / "
                    f"{sum(len(entry.attributes) for entry in entries)} GET targets"
                )
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
