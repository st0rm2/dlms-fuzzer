from pathlib import Path
import unittest

from dlms_enum.config import ConfigError, load_config, parse_config


ROOT = Path(__file__).resolve().parents[1]


class ConfigTests(unittest.TestCase):
    def test_example_is_valid_and_redacted_snapshot_has_public_profile(self):
        config = load_config(ROOT / "examples" / "public-meter.yaml")
        self.assertEqual(config.profile.client_address, 16)
        self.assertEqual(config.transport.baudrate, 9600)
        self.assertEqual(config.profile.server_logical_address, 0)
        self.assertEqual(config.profile.server_physical_address, 1)
        self.assertEqual(config.output.summary_file, "summary.md")
        snapshot = config.redacted_dict()
        self.assertEqual(snapshot["profiles"][0]["authentication"], {"mechanism": "none"})
        self.assertNotIn("profile", snapshot)

    def test_non_get_mode_is_rejected(self):
        with self.assertRaisesRegex(ConfigError, "only scan.mode: get"):
            parse_config(
                {
                    "transport": {"device": "/dev/null"},
                    "scan": {"mode": "set"},
                }
            )

    def test_get_retry_budget_is_exactly_two_total_attempts(self):
        with self.assertRaisesRegex(ConfigError, "scan.total_get_attempts"):
            parse_config(
                {
                    "transport": {"device": "/dev/null"},
                    "scan": {"total_get_attempts": 1},
                }
            )

    def test_additional_profile_is_rejected_in_this_milestone(self):
        profile = {
            "name": "public",
            "client_address": 16,
            "authentication": {"mechanism": "none"},
            "security": {"policy": "none"},
        }
        with self.assertRaisesRegex(ConfigError, "exactly one public profile"):
            parse_config(
                {
                    "transport": {"device": "/dev/null"},
                    "profiles": [profile, profile],
                }
            )

    def test_server_address_parts_are_bounded(self):
        with self.assertRaisesRegex(ConfigError, "server.physical_address"):
            parse_config(
                {
                    "transport": {"device": "/dev/null"},
                    "profiles": [{"server": {"physical_address": 20000}}],
                }
            )

    def test_short_scan_object_limit_is_validated(self):
        config = parse_config(
            {
                "transport": {"device": "/dev/null"},
                "scan": {"object_limit": 10},
            }
        )
        self.assertEqual(config.scan.object_limit, 10)

        for invalid in (0, True):
            with self.subTest(invalid=invalid), self.assertRaisesRegex(
                ConfigError, "scan.object_limit"
            ):
                parse_config(
                    {
                        "transport": {"device": "/dev/null"},
                        "scan": {"object_limit": invalid},
                    }
                )

    def test_exact_get_limit_is_validated_and_excludes_object_limit(self):
        config = parse_config(
            {
                "transport": {"device": "/dev/null"},
                "scan": {"get_limit": 100},
            }
        )
        self.assertEqual(config.scan.get_limit, 100)

        for invalid in (0, True):
            with self.subTest(invalid=invalid), self.assertRaisesRegex(
                ConfigError, "scan.get_limit"
            ):
                parse_config(
                    {
                        "transport": {"device": "/dev/null"},
                        "scan": {"get_limit": invalid},
                    }
                )

        with self.assertRaisesRegex(ConfigError, "mutually exclusive"):
            parse_config(
                {
                    "transport": {"device": "/dev/null"},
                    "scan": {"object_limit": 10, "get_limit": 100},
                }
            )


if __name__ == "__main__":
    unittest.main()
