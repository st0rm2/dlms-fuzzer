import argparse
import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from rich.console import Console

from dlms_enum.cli import _scan
from dlms_enum.config import parse_config
from dlms_enum.workflow import CounterCandidate, PublicPreflight


class NullLogger:
    def __init__(self, path):
        self.path = path

    def close(self):
        pass


class CliWorkflowTests(unittest.TestCase):
    def test_public_and_authenticated_scans_write_permission_comparison(self):
        config = parse_config(
            {
                "transport": {"device": "/dev/null"},
                "profiles": [
                    {"name": "public", "role": "public"},
                    {
                        "name": "lls",
                        "role": "reader",
                        "client_address": 32,
                        "authentication": {
                            "mechanism": "low",
                            "password": {"inline": "00000000"},
                        },
                    },
                ],
            }
        )
        preflight = PublicPreflight(
            transport={
                "device": "/dev/null",
                "selected_baudrate": 9600,
                "selected_server_address": 1,
                "selected_server_logical_address": 0,
                "selected_server_physical_address": 1,
                "server_address_size": 1,
                "server_addressing_type": "1-byte addressing",
            },
            association={"negotiated_conformance": ["get"]},
            meter_identity="METER-1",
            association_view_objects=1,
            counter_candidates=(),
        )
        args = argparse.Namespace(
            config=Path("meter.yaml"),
            roles=None,
            short=False,
            full=True,
            get_limit=None,
            association_view_mode="live",
            save_association_view=False,
        )

        def fake_scan(runtime_config, *_args, **_kwargs):
            profile = runtime_config.profile
            return {
                "run": {"id": profile.role, "status": "completed"},
                "effective_configuration": runtime_config.redacted_dict(),
                "transport": {
                    "device": "/dev/null",
                    "selected_server_address": 1,
                },
                "profiles": [
                    {
                        "name": profile.role,
                        "type": profile.name,
                        "association": {
                            "client_address": profile.client_address,
                            "authentication": (
                                "none" if profile.name == "public" else "low"
                            ),
                        },
                        "objects": [
                            {
                                "class_id": 1,
                                "logical_name": "0.0.96.1.0.255",
                                "object_version": 0,
                                "description": "Serial number",
                                "discovery_sources": ["association_view"],
                                "attributes": [
                                    {
                                        "attribute_id": 2,
                                        "name": "Value",
                                        "access_rights": {
                                            "read": True,
                                            "write": profile.name != "public",
                                            "mode": (
                                                "read"
                                                if profile.name == "public"
                                                else "read_write"
                                            ),
                                            "requirements": [],
                                        },
                                    }
                                ],
                                "methods": [],
                            }
                        ],
                        "summary": {},
                    }
                ],
                "errors": [],
            }

        with tempfile.TemporaryDirectory() as directory:
            run_directory = Path(directory) / "run"
            run_directory.mkdir()
            with (
                patch("dlms_enum.cli.load_config", return_value=config),
                patch("dlms_enum.cli._run_directory", return_value=run_directory),
                patch("dlms_enum.cli.TrafficLogger", NullLogger),
                patch("dlms_enum.cli.run_public_preflight", return_value=preflight),
                patch("dlms_enum.cli.scan", side_effect=fake_scan),
                patch("dlms_enum.cli.write_report"),
                patch("dlms_enum.cli.ScanUI.summary"),
            ):
                status = _scan(args, Console(file=io.StringIO(), color_system=None))

            comparison = json.loads(
                (run_directory / "capability-comparison.json").read_text()
            )
            workflow = json.loads((run_directory / "workflow.json").read_text())

        self.assertEqual(status, 0)
        self.assertEqual(comparison["comparisons"][0]["authenticated_role"], "reader")
        self.assertEqual(
            comparison["comparisons"][0]["summary"]["SET"]["authenticated_only"],
            1,
        )
        self.assertEqual(workflow["capability_comparison"]["status"], "completed")

    def test_live_association_export_updates_report_snapshot_timestamp(self):
        config = parse_config(
            {
                "transport": {"device": "/dev/null"},
                "profiles": [{"name": "public", "role": "public"}],
            }
        )
        preflight = PublicPreflight(
            transport={
                "device": "/dev/null",
                "selected_baudrate": 9600,
                "selected_server_address": 1,
                "selected_server_logical_address": 0,
                "selected_server_physical_address": 1,
                "server_address_size": 1,
                "server_addressing_type": "1-byte addressing",
            },
            association={"negotiated_conformance": ["get"]},
            meter_identity="METER-1",
            association_view_objects=1,
            counter_candidates=(),
        )
        args = argparse.Namespace(
            config=Path("meter.yaml"),
            roles=None,
            short=False,
            full=True,
            get_limit=None,
            association_view_mode="live",
            save_association_view=False,
        )
        written = []

        def fake_scan(runtime_config, *_args, **_kwargs):
            return {
                "run": {"id": "public", "status": "completed"},
                "effective_configuration": runtime_config.redacted_dict(),
                "transport": {
                    "device": "/dev/null",
                    "selected_server_address": 1,
                },
                "profiles": [
                    {
                        "name": "public",
                        "type": "public",
                        "association": {"client_address": 16},
                        "objects": [
                            {
                                "class_id": 1,
                                "logical_name": "0.0.96.1.0.255",
                                "object_version": 0,
                                "description": "Serial number",
                                "discovery_sources": ["association_view"],
                                "attributes": [],
                                "methods": [],
                            }
                        ],
                        "summary": {},
                    }
                ],
                "errors": [],
                "association_view": {
                    "mode": "live",
                    "source": "meter",
                    "snapshot_saved_at": None,
                },
            }

        with tempfile.TemporaryDirectory() as directory:
            run_directory = Path(directory) / "run"
            run_directory.mkdir()
            cache_path = Path(directory) / "cache.json"
            with (
                patch("dlms_enum.cli.load_config", return_value=config),
                patch("dlms_enum.cli._run_directory", return_value=run_directory),
                patch("dlms_enum.cli.default_cache_path", return_value=cache_path),
                patch("dlms_enum.cli.TrafficLogger", NullLogger),
                patch("dlms_enum.cli.run_public_preflight", return_value=preflight),
                patch("dlms_enum.cli.scan", side_effect=fake_scan),
                patch("dlms_enum.cli.ScanUI.summary"),
                patch(
                    "dlms_enum.cli.write_report",
                    side_effect=lambda report, path, *_args: written.append(
                        (path.name, report)
                    ),
                ),
            ):
                status = _scan(
                    args,
                    Console(file=io.StringIO(), color_system=None),
                )

            exported = json.loads(
                (run_directory / "association-view.json").read_text()
            )

        role_report = next(report for name, report in written if name == "report.json")
        self.assertEqual(status, 0)
        self.assertEqual(
            role_report["association_view"]["snapshot_saved_at"],
            exported["saved_at"],
        )

    def test_unselected_public_role_still_drives_preflight_and_pins_secure_scan(self):
        config = parse_config(
            {
                "transport": {"device": "/dev/null"},
                "profiles": [
                    {"name": "public", "role": "public"},
                    {
                        "name": "hls_gmac_suite0",
                        "role": "client1",
                        "client_address": 1,
                        "client_system_title": "hex:0011223344556677",
                        "secrets": {
                            "gak": {"inline": "00" * 16},
                            "guek": {"inline": "11" * 16},
                        },
                    },
                ],
            }
        )
        preflight = PublicPreflight(
            transport={
                "device": "/dev/null",
                "selected_baudrate": 19200,
                "selected_server_address": 131,
                "selected_server_logical_address": 1,
                "selected_server_physical_address": 3,
                "server_address_size": 2,
                "server_addressing_type": "2-byte addressing",
            },
            association={"negotiated_conformance": ["get"]},
            meter_identity="METER-1",
            association_view_objects=1,
            counter_candidates=(
                CounterCandidate(1, "0.0.43.1.0.255", 2, 100),
            ),
        )
        args = argparse.Namespace(
            config=Path("meter.yaml"),
            roles="client1",
            short=False,
            full=True,
            get_limit=None,
        )
        captured = {}

        def fake_preflight(runtime_config, *_args, **_kwargs):
            captured["preflight_role"] = runtime_config.profile.role
            return preflight

        def fake_scan(runtime_config, *_args, **_kwargs):
            captured["scan_config"] = runtime_config
            return {
                "run": {"id": "test", "status": "completed"},
                "transport": {},
                "profiles": [],
                "errors": [],
            }

        with tempfile.TemporaryDirectory() as directory:
            run_directory = Path(directory) / "run"
            run_directory.mkdir()
            with (
                patch("dlms_enum.cli.load_config", return_value=config),
                patch("dlms_enum.cli._run_directory", return_value=run_directory),
                patch("dlms_enum.cli.TrafficLogger", NullLogger),
                patch("dlms_enum.cli.run_public_preflight", side_effect=fake_preflight),
                patch("dlms_enum.cli.scan", side_effect=fake_scan),
                patch("dlms_enum.cli.write_report"),
            ):
                status = _scan(
                    args,
                    Console(file=io.StringIO(), color_system=None),
                )

        self.assertEqual(status, 0)
        self.assertEqual(captured["preflight_role"], "public")
        runtime = captured["scan_config"]
        self.assertEqual(runtime.profile.role, "client1")
        self.assertEqual(runtime.transport.baudrate, 19200)
        self.assertEqual(runtime.profile.server_logical_address, 1)
        self.assertEqual(runtime.profile.server_physical_address, 3)
        self.assertEqual(runtime.profile.server_address_size, 2)

    def test_authentication_matrix_runs_after_all_normal_role_scans(self):
        config = parse_config(
            {
                "transport": {"device": "/dev/null"},
                "authentication_scan": {
                    "enabled": True,
                    "password": {"inline": "00000000"},
                },
                "profiles": [
                    {"name": "public", "role": "public", "client_address": 16},
                    {
                        "name": "lls",
                        "role": "reader",
                        "client_address": 32,
                        "authentication": {
                            "mechanism": "low",
                            "password": {"inline": "00000000"},
                        },
                    },
                ],
            }
        )
        preflight = PublicPreflight(
            transport={
                "device": "/dev/null",
                "selected_baudrate": 9600,
                "selected_server_address": 1,
                "selected_server_logical_address": 0,
                "selected_server_physical_address": 1,
                "server_address_size": 1,
                "server_addressing_type": "1-byte addressing",
            },
            association={"negotiated_conformance": ["get"]},
            meter_identity="METER-1",
            association_view_objects=1,
            counter_candidates=(),
        )
        args = argparse.Namespace(
            config=Path("meter.yaml"),
            roles=None,
            short=False,
            full=True,
            get_limit=None,
        )
        calls = []
        written = []

        def fake_scan(runtime_config, *_args, **_kwargs):
            calls.append(("normal", runtime_config.profile.role))
            return {
                "run": {"id": runtime_config.profile.role, "status": "completed"},
                "transport": {},
                "profiles": [],
                "errors": [],
            }

        def fake_auth(runtime_config, *_args, **_kwargs):
            role = runtime_config.profile.role
            calls.append(("authentication", role))
            results = [
                {
                    "mechanism": mechanism,
                    "attempted": mechanism != "high_ecdsa",
                    "status": "authenticated" if mechanism == "none" else "rejected",
                    "fully_authenticated": mechanism == "none",
                }
                for mechanism in (
                    "none", "low", "high", "high_md5", "high_sha1",
                    "high_gmac", "high_sha256", "high_ecdsa",
                )
            ]
            return {
                "name": runtime_config.profile.name,
                "role": role,
                "client_address": runtime_config.profile.client_address,
                "authentication_scan": {
                    "results": results,
                    "accepted_mechanisms": ["none"],
                },
                "errors": [],
            }

        with tempfile.TemporaryDirectory() as directory:
            run_directory = Path(directory) / "run"
            run_directory.mkdir()
            with (
                patch("dlms_enum.cli.load_config", return_value=config),
                patch("dlms_enum.cli._run_directory", return_value=run_directory),
                patch("dlms_enum.cli.TrafficLogger", NullLogger),
                patch("dlms_enum.cli.run_public_preflight", return_value=preflight),
                patch("dlms_enum.cli.scan", side_effect=fake_scan),
                patch("dlms_enum.cli.run_authentication_scan", side_effect=fake_auth),
                patch(
                    "dlms_enum.cli.write_report",
                    side_effect=lambda report, path, *_args: written.append((path.name, report)),
                ),
            ):
                status = _scan(
                    args,
                    Console(file=io.StringIO(), color_system=None, width=160),
                )

        self.assertEqual(status, 0)
        self.assertEqual(
            calls,
            [
                ("normal", "public"),
                ("normal", "reader"),
                ("authentication", "public"),
                ("authentication", "reader"),
            ],
        )
        authentication_report = next(
            report for name, report in written if name == "authentication-report.json"
        )
        self.assertEqual(
            [item["role"] for item in authentication_report["authentication_matrix"]["roles"]],
            ["public", "reader"],
        )
        self.assertEqual(
            set(authentication_report["authentication_matrix"]["rows"][0]["roles"]),
            {"public", "reader"},
        )


if __name__ == "__main__":
    unittest.main()
