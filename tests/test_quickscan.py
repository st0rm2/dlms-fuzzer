import io
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from rich.console import Console

from dlms_enum.autodiscover import DiscoveryOptions
from dlms_enum.config import LlsProfile, SecureProfile, parse_config
from dlms_enum.quickscan import (
    QuickscanError,
    build_profiles,
    discover_config,
    load_secrets_file,
)

from test_autodiscover import DiscoverySession, FailedSession


GAK = "00112233445566778899AABBCCDDEEFF"
GUEK = "FFEEDDCCBBAA99887766554433221100"
TITLE = "4D45544552303031"


def _successful_result(device):
    return {
        "device": device,
        "status": "completed",
        "connection": {
            "baudrate": 19200,
            "serial": {"parity": "none", "data_bits": 8, "stop_bits": 1.0},
            "client_address": 1,
            "server_address": 145,
            "server_logical_address": 1,
            "server_physical_address": 17,
            "server_address_size": 2,
        },
        "errors": [],
    }


class DiscoverConfigTests(unittest.TestCase):
    def test_discovery_result_is_pinned_into_config(self):
        captured = {}

        def fake_discover(options, _traffic, *, progress=None, session_factory=None):
            captured["options"] = options
            captured["session_factory"] = session_factory
            return _successful_result(options.device)

        config = discover_config("/dev/fake0", object(), discover=fake_discover)

        options = captured["options"]
        self.assertIsInstance(options, DiscoveryOptions)
        self.assertEqual(options.device, "/dev/fake0")
        self.assertIsNone(captured["session_factory"])
        self.assertEqual(config.transport.device, "/dev/fake0")
        self.assertEqual(config.transport.baudrate, 19200)
        profile = config.profile
        self.assertEqual(profile.role, "public")
        self.assertEqual(profile.client_address, 1)
        self.assertEqual(profile.server_logical_address, 1)
        self.assertEqual(profile.server_physical_address, 17)
        self.assertEqual(profile.server_address_size, 2)

    def test_real_discovery_with_fake_session_produces_valid_config(self):
        with patch("dlms_enum.autodiscover.validate_serial_device"):
            config = discover_config(
                "/dev/fake0", object(), session_factory=DiscoverySession
            )

        self.assertEqual(config.transport.baudrate, 9600)
        profile = config.profile
        self.assertEqual(profile.client_address, 1)
        self.assertEqual(profile.server_logical_address, 1)
        self.assertEqual(profile.server_physical_address, 17)
        self.assertEqual(profile.server_address_size, 2)

    def test_failed_discovery_raises_quickscan_error_with_device(self):
        def fake_discover(options, _traffic, *, progress=None, session_factory=None):
            return {
                "device": options.device,
                "status": "failed",
                "errors": [{"message": "no association answered"}],
            }

        with self.assertRaises(QuickscanError) as ctx:
            discover_config("/dev/ttyUSB9", object(), discover=fake_discover)

        self.assertIn("/dev/ttyUSB9", str(ctx.exception))
        self.assertIn("no DLMS endpoint found", str(ctx.exception))

    def test_real_failed_sweep_raises_quickscan_error(self):
        with patch("dlms_enum.autodiscover.validate_serial_device"):
            with self.assertRaises(QuickscanError) as ctx:
                discover_config(
                    "/dev/fake0", object(), session_factory=FailedSession
                )
        self.assertIn("/dev/fake0", str(ctx.exception))


class BuildProfilesTests(unittest.TestCase):
    def _base_config(self):
        return parse_config(
            {
                "transport": {"device": "/dev/null", "baudrate": 9600},
                "profiles": [{"name": "public", "role": "public"}],
            }
        )

    def _suggestion(self, mechanism, client_sap, mechanism_id=None):
        return {
            "logical_name": f"0.0.40.0.{client_sap}.255",
            "client_sap": client_sap,
            "mechanism_id": (
                mechanism_id
                if mechanism_id is not None
                else {"none": 0, "low": 1, "high_gmac": 5}.get(mechanism)
            ),
            "mechanism": mechanism,
        }

    def _console(self):
        return Console(file=io.StringIO(), color_system=None)

    def test_non_interactive_ignores_suggestions_without_prompting(self):
        config = self._base_config()
        with (
            patch(
                "dlms_enum.quickscan.Confirm.ask",
                side_effect=AssertionError("prompted"),
            ),
            patch(
                "dlms_enum.quickscan.prompt_secret",
                side_effect=AssertionError("prompted"),
            ),
        ):
            result = build_profiles(
                config,
                [self._suggestion("low", 32)],
                {},
                self._console(),
                interactive=False,
            )
        self.assertIs(result, config)

    def test_public_associations_are_skipped_without_prompting(self):
        config = self._base_config()
        with patch(
            "dlms_enum.quickscan.Confirm.ask",
            side_effect=AssertionError("prompted"),
        ):
            result = build_profiles(
                config,
                [self._suggestion("none", 16)],
                {},
                self._console(),
                interactive=True,
            )
        self.assertIs(result, config)

    def test_accepted_lls_role_gets_inline_password(self):
        config = self._base_config()
        console = self._console()
        with (
            patch("dlms_enum.quickscan.Confirm.ask", return_value=True),
            patch("dlms_enum.quickscan.prompt_secret", return_value="s3cret"),
        ):
            result = build_profiles(
                config,
                [self._suggestion("low", 32)],
                {},
                console,
                interactive=True,
            )

        self.assertEqual(len(result.profiles), 2)
        profile = result.profiles[1]
        self.assertIsInstance(profile, LlsProfile)
        self.assertEqual(profile.role, "meter_reader")
        self.assertEqual(profile.client_address, 32)
        self.assertEqual(profile.password.kind, "inline")
        self.assertEqual(profile.password.locator, "s3cret")
        self.assertTrue(any("laboratory" in item for item in result.warnings))

    def test_declined_role_leaves_config_unchanged(self):
        config = self._base_config()
        with patch("dlms_enum.quickscan.Confirm.ask", return_value=False):
            result = build_profiles(
                config,
                [self._suggestion("low", 32)],
                {},
                self._console(),
                interactive=True,
            )
        self.assertIs(result, config)

    def test_empty_password_aborts_role(self):
        config = self._base_config()
        with (
            patch("dlms_enum.quickscan.Confirm.ask", return_value=True),
            patch("dlms_enum.quickscan.prompt_secret", return_value=""),
        ):
            result = build_profiles(
                config,
                [self._suggestion("low", 32)],
                {},
                self._console(),
                interactive=True,
            )
        self.assertIs(result, config)

    def test_hls_gmac_role_prompts_title_and_keys(self):
        config = self._base_config()
        console = self._console()
        with (
            patch("dlms_enum.quickscan.Confirm.ask", return_value=True),
            patch(
                "dlms_enum.quickscan.prompt_secret",
                side_effect=[TITLE, GAK, GUEK],
            ) as secrets,
        ):
            result = build_profiles(
                config,
                [self._suggestion("high_gmac", 1)],
                {"system_titles": [{"kind": "client", "hex": TITLE}]},
                console,
                interactive=True,
            )

        self.assertEqual(secrets.call_count, 3)
        profile = result.profiles[1]
        self.assertIsInstance(profile, SecureProfile)
        self.assertEqual(profile.role, "meter_client")
        self.assertEqual(profile.client_address, 1)
        self.assertEqual(profile.client_system_title.hex().upper(), TITLE)
        self.assertEqual(profile.secrets.gak.kind, "inline")
        self.assertEqual(profile.secrets.gak.locator, f"hex:{GAK}")
        self.assertEqual(profile.secrets.guek.locator, f"hex:{GUEK}")
        self.assertIn(TITLE, console.file.getvalue())

    def test_hls_gmac_title_validation_retries_on_bad_hex(self):
        config = self._base_config()
        console = self._console()
        with (
            patch("dlms_enum.quickscan.Confirm.ask", return_value=True),
            patch(
                "dlms_enum.quickscan.prompt_secret",
                side_effect=["ZZZZ", "00112233", TITLE, GAK, GUEK],
            ) as secrets,
        ):
            result = build_profiles(
                config,
                [self._suggestion("high_gmac", 1)],
                {},
                console,
                interactive=True,
            )

        self.assertEqual(secrets.call_count, 5)
        self.assertIsInstance(result.profiles[1], SecureProfile)
        rendered = console.file.getvalue()
        self.assertIn("Hexadecimal characters only", rendered)
        self.assertIn("Expected exactly 8 bytes", rendered)

    def test_hls_gmac_empty_title_aborts_role(self):
        config = self._base_config()
        with (
            patch("dlms_enum.quickscan.Confirm.ask", return_value=True),
            patch("dlms_enum.quickscan.prompt_secret", return_value=""),
        ):
            result = build_profiles(
                config,
                [self._suggestion("high_gmac", 1)],
                {},
                self._console(),
                interactive=True,
            )
        self.assertIs(result, config)

    def test_unsupported_mechanism_is_reported_and_skipped(self):
        config = self._base_config()
        console = self._console()
        with patch(
            "dlms_enum.quickscan.Confirm.ask",
            side_effect=AssertionError("prompted"),
        ):
            result = build_profiles(
                config,
                [self._suggestion("high_sha256", 48, mechanism_id=6)],
                {},
                console,
                interactive=True,
            )
        self.assertIs(result, config)
        self.assertIn("not supported for guided setup", console.file.getvalue())

    def test_duplicate_role_names_get_sap_suffix(self):
        config = self._base_config()
        with (
            patch("dlms_enum.quickscan.Confirm.ask", return_value=True),
            patch("dlms_enum.quickscan.prompt_secret", return_value="s3cret"),
        ):
            result = build_profiles(
                config,
                [self._suggestion("low", 32), self._suggestion("low", 48)],
                {},
                self._console(),
                interactive=True,
            )
        self.assertEqual(
            [profile.role for profile in result.profiles],
            ["public", "meter_reader", "meter_reader_48"],
        )


class SecretsFileTests(unittest.TestCase):
    def test_parses_comments_and_blank_lines(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "secrets.env"
            path.write_text(
                "# meter laboratory keys\n"
                "\n"
                "DLMS_GAK=00112233445566778899AABBCCDDEEFF\n"
                "  DLMS_GUEK = hex:FFEEDDCCBBAA99887766554433221100  \n",
                encoding="utf-8",
            )
            secrets = load_secrets_file(path)

        self.assertEqual(
            secrets,
            {
                "DLMS_GAK": "00112233445566778899AABBCCDDEEFF",
                "DLMS_GUEK": "hex:FFEEDDCCBBAA99887766554433221100",
            },
        )

    def test_values_are_not_shell_expanded(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "secrets.env"
            path.write_text("DLMS_KEY=$HOME/'quoted'\n", encoding="utf-8")
            secrets = load_secrets_file(path)

        self.assertEqual(secrets, {"DLMS_KEY": "$HOME/'quoted'"})

    def test_malformed_line_is_rejected_with_line_number(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "secrets.env"
            path.write_text("DLMS_GAK=00\nnot an assignment\n", encoding="utf-8")
            with self.assertRaises(QuickscanError) as ctx:
                load_secrets_file(path)

        self.assertIn(":2", str(ctx.exception))
        self.assertIn("KEY=VALUE", str(ctx.exception))

    def test_invalid_key_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "secrets.env"
            path.write_text("1KEY=00\n", encoding="utf-8")
            with self.assertRaises(QuickscanError):
                load_secrets_file(path)

    def test_missing_file_is_rejected(self):
        with self.assertRaises(QuickscanError) as ctx:
            load_secrets_file("/nonexistent/secrets.env")
        self.assertIn("/nonexistent/secrets.env", str(ctx.exception))

    def test_parsed_secrets_apply_to_environ(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "secrets.env"
            path.write_text("DLMS_TEST_QUICKSCAN_KEY=00\n", encoding="utf-8")
            with patch.dict(os.environ):
                os.environ.pop("DLMS_TEST_QUICKSCAN_KEY", None)
                os.environ.update(load_secrets_file(path))
                self.assertEqual(os.environ["DLMS_TEST_QUICKSCAN_KEY"], "00")
        self.assertNotIn("DLMS_TEST_QUICKSCAN_KEY", os.environ)


if __name__ == "__main__":
    unittest.main()
