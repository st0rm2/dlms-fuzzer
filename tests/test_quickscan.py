import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from dlms_enum.autodiscover import DiscoveryOptions
from dlms_enum.quickscan import (
    QuickscanError,
    discover_config,
    load_secrets_file,
)

from test_autodiscover import DiscoverySession, FailedSession


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
