import io
import json
import os
import sys
import types
import unittest
from unittest.mock import patch

from gurux_dlms.enums import Authentication
from rich.console import Console

from dlms_enum.config import ConfigError, SecureProfile, parse_config, resolve_lls_password
from dlms_enum.gurux_adapter import GuruxAuthenticationProbeSession
from dlms_enum.reporter import render_summary_report
from dlms_enum.scanner import run_authentication_scan
from dlms_enum.tui import ScanUI, show_authentication_matrix
from dlms_enum.workflow import CounterCandidate


GAK = "00112233445566778899AABBCCDDEEFF"
GUEK = "FFEEDDCCBBAA99887766554433221100"


def authentication_scan_mapping():
    return {
        "transport": {"device": "/dev/null", "session_guard_ms": 0},
        "authentication_scan": {
            "enabled": True,
            "password": {"env": "TEST_DLMS_PASSWORD"},
        },
        "profiles": [
            {"name": "public", "role": "public", "client_address": 16},
            {
                "name": "hls_gmac_suite0",
                "role": "client4",
                "client_address": 4,
                "client_system_title": "hex:0011223344556677",
                "secrets": {
                    "gak": {"inline": GAK},
                    "guek": {"inline": GUEK},
                },
                "invocation_counter": {"logical_name": "0.0.43.1.1.255"},
            },
        ],
    }


class FakeSession:
    aarq_accepted = False

    def __init__(self, *_args, **kwargs):
        self.client_address = kwargs.get("client_address", 4)

    def connect(self):
        return {"authentication": "none", "client_address": self.client_address}

    def read_invocation_counter(self, _profile):
        return 129127

    def close(self):
        return []


class FakePasswordSession(FakeSession):
    def __init__(self, _config, _baudrate, _traffic, authentication, **kwargs):
        super().__init__(client_address=kwargs["client_address"])
        self.mechanism = authentication.name.lower()
        self.aarq_accepted = False

    def connect(self):
        if self.mechanism == "low":
            raise RuntimeError("association rejected")
        if self.mechanism == "high_md5":
            self.aarq_accepted = True
            raise RuntimeError("server challenge validation failed")
        self.aarq_accepted = True
        return {"authentication": self.mechanism, "hls_validated": True}


class FakeGmacSession(FakeSession):
    def connect(self):
        self.aarq_accepted = True
        return {"authentication": "high_gmac", "hls_validated": True}


class FakeLease:
    next_counter = 129128

    def persist_next(self, value):
        self.next_counter = value

    def close(self):
        pass


class RetryGmacSession(FakeGmacSession):
    connect_calls = 0

    def connect(self):
        type(self).connect_calls += 1
        if type(self).connect_calls == 1:
            raise RuntimeError("fresh association temporarily rejected")
        return super().connect()


TRANSPORT = {
    "selected_baudrate": 9600,
    "selected_server_address": 1,
    "selected_server_logical_address": 0,
    "selected_server_physical_address": 1,
    "server_address_size": 1,
    "server_addressing_type": "1-byte addressing",
}


class AuthenticationScanTests(unittest.TestCase):
    def test_authentication_is_a_final_phase_not_a_profile(self):
        config = parse_config(authentication_scan_mapping())

        self.assertTrue(config.authentication_scan.enabled)
        self.assertEqual([profile.role for profile in config.profiles], ["public", "client4"])
        self.assertIsInstance(config.profiles[1], SecureProfile)
        self.assertEqual(
            resolve_lls_password(
                config.authentication_scan,
                environ={"TEST_DLMS_PASSWORD": "00000000"},
            ),
            b"00000000",
        )
        effective = json.dumps(config.redacted_dict())
        self.assertNotIn(GAK, effective)
        self.assertNotIn(GUEK, effective)
        self.assertNotIn("00000000", effective)

    def test_enabled_scan_requires_only_a_shared_password(self):
        mapping = authentication_scan_mapping()
        del mapping["authentication_scan"]["password"]

        with self.assertRaisesRegex(ConfigError, "password is required"):
            parse_config(mapping)

    def test_standalone_authentication_profile_is_rejected(self):
        mapping = authentication_scan_mapping()
        mapping["profiles"] = [{"name": "authentication_scan"}]

        with self.assertRaisesRegex(ConfigError, "top-level final workflow phase"):
            parse_config(mapping)

    def test_gurux_password_probe_receives_generated_mechanism_and_password(self):
        full = parse_config(authentication_scan_mapping())
        config = full.for_profile(full.profiles[1])
        session = GuruxAuthenticationProbeSession(
            config,
            9600,
            object(),
            Authentication.HIGH_SHA1,
            client_address=4,
            profile_name="client4",
            password=b"00000000",
            client_system_title=b"12345678",
            server_logical_address=0,
            server_physical_address=1,
            server_address_size=1,
        )

        self.assertEqual(session.client.authentication, Authentication.HIGH_SHA1)
        self.assertEqual(bytes(session.client.password), b"00000000")
        self.assertEqual(session.authentication_name, "high_sha1")
        self.assertTrue(session.client.aarqRequest())

    def test_probe_continues_and_emits_attempt_and_result_events(self):
        full = parse_config(authentication_scan_mapping())
        config = full.for_profile(full.profiles[1])
        module = types.ModuleType("dlms_enum.gurux_adapter")
        module.GuruxSession = FakeSession
        module.GuruxAuthenticationProbeSession = FakePasswordSession
        module.GuruxSecureSession = FakeGmacSession
        events = []

        with (
            patch.dict(sys.modules, {"dlms_enum.gurux_adapter": module}),
            patch.dict(os.environ, {"TEST_DLMS_PASSWORD": "00000000"}),
            patch("dlms_enum.scanner.acquire_counter_lease", return_value=FakeLease()),
            patch("dlms_enum.scanner.resolve_secure_keys", return_value=(b"A" * 16, b"B" * 16)),
        ):
            result = run_authentication_scan(
                config,
                object(),
                transport=TRANSPORT,
                meter_identity="METER-1",
                counter_candidates=(CounterCandidate(1, "0.0.43.1.1.255", 2, 129127),),
                progress=events.append,
            )

        results = {
            item["mechanism"]: item
            for item in result["authentication_scan"]["results"]
        }
        self.assertEqual(results["low"]["status"], "rejected")
        self.assertEqual(results["high_md5"]["status"], "hls_validation_failed")
        self.assertEqual(results["high_sha1"]["status"], "authenticated")
        self.assertEqual(results["high_gmac"]["status"], "authenticated")
        self.assertEqual(results["high_ecdsa"]["status"], "unsupported")
        self.assertEqual(
            len([event for event in events if event["phase"] == "authentication_scan_attempt"]),
            7,
        )
        self.assertTrue(any("client 4 / HLS-GMAC" in event["message"] for event in events))

    def test_public_role_marks_gmac_as_prerequisite_failed(self):
        full = parse_config(authentication_scan_mapping())
        module = types.ModuleType("dlms_enum.gurux_adapter")
        module.GuruxSession = FakeSession
        module.GuruxAuthenticationProbeSession = FakePasswordSession
        module.GuruxSecureSession = FakeGmacSession
        with (
            patch.dict(sys.modules, {"dlms_enum.gurux_adapter": module}),
            patch.dict(os.environ, {"TEST_DLMS_PASSWORD": "00000000"}),
        ):
            result = run_authentication_scan(
                full.for_profile(full.profiles[0]),
                object(),
                transport=TRANSPORT,
                meter_identity="METER-1",
                counter_candidates=(),
                progress=lambda _event: None,
            )
        gmac = next(
            item
            for item in result["authentication_scan"]["results"]
            if item["mechanism"] == "high_gmac"
        )
        self.assertEqual(gmac["status"], "prerequisite_failed")

    def test_gmac_refreshes_counter_and_retries_an_aarq_rejection_once(self):
        full = parse_config(authentication_scan_mapping())
        config = full.for_profile(full.profiles[1])
        module = types.ModuleType("dlms_enum.gurux_adapter")
        module.GuruxSession = FakeSession
        module.GuruxAuthenticationProbeSession = FakePasswordSession
        module.GuruxSecureSession = RetryGmacSession
        RetryGmacSession.connect_calls = 0

        with (
            patch.dict(sys.modules, {"dlms_enum.gurux_adapter": module}),
            patch.dict(os.environ, {"TEST_DLMS_PASSWORD": "00000000"}),
            patch("dlms_enum.scanner.acquire_counter_lease", return_value=FakeLease()),
            patch("dlms_enum.scanner.resolve_secure_keys", return_value=(b"A" * 16, b"B" * 16)),
        ):
            result = run_authentication_scan(
                config,
                object(),
                transport=TRANSPORT,
                meter_identity="METER-1",
                counter_candidates=(CounterCandidate(1, "0.0.43.1.1.255", 2, 10),),
                progress=lambda _event: None,
            )

        gmac = next(
            item
            for item in result["authentication_scan"]["results"]
            if item["mechanism"] == "high_gmac"
        )
        self.assertEqual(gmac["status"], "authenticated")
        self.assertEqual(gmac["attempt_count"], 2)
        self.assertEqual(
            [item["status"] for item in gmac["attempts"]],
            ["rejected", "authenticated"],
        )
        self.assertEqual(len(gmac["counter_refreshes"]), 2)

    def test_role_by_mechanism_matrix_renders_in_markdown_and_terminal(self):
        records = {
            "client4": {"status": "authenticated"},
            "client5": {"status": "rejected"},
        }
        report = {
            "run": {"id": "auth", "status": "completed"},
            "transport": TRANSPORT,
            "profiles": [],
            "errors": [],
            "authentication_matrix": {
                "roles": [
                    {"role": "client4", "client_address": 4},
                    {"role": "client5", "client_address": 5},
                ],
                "rows": [{"mechanism": "high_gmac", "roles": records}],
            },
        }
        markdown = render_summary_report(report)
        self.assertIn("Authentication result matrix", markdown)
        self.assertIn("client4 (client 4)", markdown)
        output = io.StringIO()
        show_authentication_matrix(
            report, Console(file=output, color_system=None, width=160)
        )
        self.assertIn("client4", output.getvalue())
        self.assertIn("HIGH_GMAC", output.getvalue())

    def test_live_ui_reuses_one_progress_line_for_authentication(self):
        output = io.StringIO()
        ui = ScanUI(Console(file=output, color_system=None, width=120))
        ui.progress(
            {
                "phase": "authentication_scan_attempt",
                "sequence": 1,
                "total": 7,
                "message": "Testing client4 / client 4 / HIGH_GMAC",
            }
        )
        ui.progress(
            {
                "phase": "authentication_scan_result",
                "sequence": 1,
                "total": 7,
                "status": "rejected",
                "message": "client4 / client 4 / HIGH_GMAC: rejected",
            }
        )
        ui.close()
        self.assertNotIn("Testing client4 / client 4 / HIGH_GMAC\n", output.getvalue())
        self.assertIn("rejected", output.getvalue())
        self.assertIn("1/7", output.getvalue())


if __name__ == "__main__":
    unittest.main()
