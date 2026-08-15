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

    def test_multi_role_example_is_valid(self):
        config = load_config(ROOT / "examples" / "multi-role-meter.yaml")

        self.assertEqual(
            [profile.role for profile in config.profiles],
            ["public", "client1", "client2"],
        )

    def test_non_get_mode_is_rejected(self):
        with self.assertRaisesRegex(ConfigError, "only scan.mode: get"):
            parse_config(
                {
                    "transport": {"device": "/dev/null"},
                    "scan": {"mode": "set"},
                }
            )

    def test_default_response_timeout_is_one_second(self):
        config = parse_config({"transport": {"device": "/dev/null"}})

        self.assertEqual(config.transport.response_timeout_ms, 1000)
        self.assertEqual(config.scan.enumeration_timeout_ms, 1000)
        self.assertEqual(config.scan.timeout_breaker_threshold, 4)

    def test_enumeration_timeout_and_breaker_threshold_are_bounded(self):
        config = parse_config(
            {
                "transport": {
                    "device": "/dev/null",
                    "response_timeout_ms": 3000,
                },
                "scan": {
                    "enumeration_timeout_ms": 750,
                    "timeout_breaker_threshold": 5,
                },
            }
        )

        self.assertEqual(config.transport.response_timeout_ms, 3000)
        self.assertEqual(config.scan.enumeration_timeout_ms, 750)
        self.assertEqual(config.scan.timeout_breaker_threshold, 5)

        for key, invalid in (
            ("enumeration_timeout_ms", 0),
            ("timeout_breaker_threshold", 2),
            ("timeout_breaker_threshold", 11),
        ):
            with self.subTest(key=key, invalid=invalid), self.assertRaisesRegex(
                ConfigError, f"scan.{key}"
            ):
                parse_config(
                    {
                        "transport": {"device": "/dev/null"},
                        "scan": {key: invalid},
                    }
                )

    def test_unimplemented_manufacturer_catalogue_is_rejected(self):
        with self.assertRaisesRegex(ConfigError, "unsupported keys"):
            parse_config(
                {
                    "transport": {"device": "/dev/null"},
                    "scan": {"manufacturer_catalogue": "auto"},
                }
            )

    def test_union_profile_test_requires_a_secure_profile(self):
        with self.assertRaisesRegex(ConfigError, "requires an hls_gmac_suite0 profile"):
            parse_config(
                {
                    "transport": {"device": "/dev/null"},
                    "scan": {"union_profile_test": True},
                }
            )

        with self.assertRaisesRegex(ConfigError, "scan.union_profile_test must be boolean"):
            parse_config(
                {
                    "transport": {"device": "/dev/null"},
                    "scan": {"union_profile_test": 1},
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

    def test_multiple_uniquely_named_roles_are_supported(self):
        public = {
            "name": "public",
            "role": "public",
            "client_address": 16,
            "authentication": {"mechanism": "none"},
            "security": {"policy": "none"},
        }
        second_public = {**public, "role": "public2", "client_address": 17}
        config = parse_config(
            {
                "transport": {"device": "/dev/null"},
                "profiles": [public, second_public],
            }
        )

        self.assertEqual([item.role for item in config.profiles], ["public", "public2"])
        with self.assertRaisesRegex(ConfigError, "role names must be unique"):
            parse_config(
                {
                    "transport": {"device": "/dev/null"},
                    "profiles": [public, public],
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

    def test_get_with_list_batch_size_is_bounded(self):
        config = parse_config(
            {
                "transport": {"device": "/dev/null"},
                "scan": {"batch_size": 10},
            }
        )
        self.assertEqual(config.scan.batch_size, 10)

        for invalid in (0, 11, True):
            with self.subTest(invalid=invalid), self.assertRaisesRegex(
                ConfigError, "scan.batch_size"
            ):
                parse_config(
                    {
                        "transport": {"device": "/dev/null"},
                        "scan": {"batch_size": invalid},
                    }
                )


if __name__ == "__main__":
    unittest.main()
