import json
import os
import tempfile
import unittest
from pathlib import Path

from dlms_enum.config import (
    ConfigError,
    SecureProfile,
    dump_config,
    parse_config,
    resolve_secret,
    resolve_secure_keys,
)


GAK = "00112233445566778899AABBCCDDEEFF"
GUEK = "FFEEDDCCBBAA99887766554433221100"


def secure_mapping(**profile_overrides):
    profile = {
        "name": "hls_gmac_suite0",
        "client_address": 1,
        "client_system_title": "hex:4D45544552303031",
        "secrets": {
            "gak": {"inline": GAK},
            "guek": {"inline": GUEK},
        },
    }
    profile.update(profile_overrides)
    return {"transport": {"device": "/dev/null"}, "profiles": [profile]}


class SecureConfigTests(unittest.TestCase):
    def test_multiple_secure_roles_have_independent_labels_and_counter_sources(self):
        first = secure_mapping()["profiles"][0]
        first["role"] = "client1"
        second = {
            **secure_mapping(client_address=4)["profiles"][0],
            "role": "client2",
            "client_system_title": "hex:4D45544552303032",
            "invocation_counter": {"logical_name": "0.0.43.1.1.255"},
        }

        config = parse_config(
            {
                "transport": {"device": "/dev/null"},
                "profiles": [first, second],
            }
        )

        self.assertEqual([item.role for item in config.profiles], ["client1", "client2"])
        self.assertEqual(config.profiles[1].invocation_counter.logical_name, "0.0.43.1.1.255")
        self.assertEqual(
            [item["role"] for item in config.redacted_dict()["profiles"]],
            ["client1", "client2"],
        )

    def test_secure_profile_parsing_and_implied_defaults(self):
        config = parse_config(secure_mapping())

        self.assertIsInstance(config.profile, SecureProfile)
        self.assertTrue(config.is_secure)
        self.assertEqual(config.profile.client_address, 1)
        self.assertEqual(config.profile.client_system_title, b"METER001")
        self.assertEqual(config.profile.invocation_counter.public_client_address, 16)
        self.assertEqual(config.profile.invocation_counter.logical_name, "0.0.43.1.0.255")
        snapshot = config.redacted_dict()
        self.assertEqual(snapshot["profiles"][0]["authentication"]["mechanism"], "high_gmac")
        self.assertEqual(snapshot["profiles"][0]["security"]["suite"], 0)
        self.assertEqual(snapshot["profiles"][0]["security"]["policy"], "authentication_encryption")

    def test_secure_profile_can_enable_public_union_testing(self):
        mapping = secure_mapping()
        mapping["scan"] = {"union_profile_test": True}

        config = parse_config(mapping)

        self.assertTrue(config.scan.union_profile_test)

    def test_exact_system_title_and_key_lengths_are_required(self):
        for title in ("hex:0011", "hex:001122334455667788"):
            with self.subTest(title=title), self.assertRaisesRegex(ConfigError, "exactly 8 bytes"):
                parse_config(secure_mapping(client_system_title=title))

        for key_name in ("gak", "guek"):
            mapping = secure_mapping()
            mapping["profiles"][0]["secrets"][key_name] = {"inline": "AA" * 15}
            with self.subTest(key=key_name), self.assertRaisesRegex(ConfigError, "exactly 16 bytes"):
                parse_config(mapping)

    def test_secret_values_are_absent_from_repr_effective_config_and_saved_config(self):
        config = parse_config(secure_mapping())
        rendered = repr(config)
        effective = json.dumps(config.redacted_dict())

        for secret in (GAK, GUEK):
            self.assertNotIn(secret, rendered)
            self.assertNotIn(secret, effective)
        self.assertIn("laboratory use only", effective)

        with tempfile.TemporaryDirectory() as directory:
            destination = Path(directory) / "saved.yaml"
            dump_config(config, destination)
            saved = destination.read_text(encoding="utf-8")
        self.assertNotIn(GAK, saved)
        self.assertNotIn(GUEK, saved)
        self.assertIn("prompt: true", saved)

    def test_environment_and_protected_file_secret_resolution(self):
        with tempfile.TemporaryDirectory() as directory:
            key_file = Path(directory) / "guek.txt"
            key_file.write_text(f"hex:{GUEK}\n", encoding="utf-8")
            os.chmod(key_file, 0o600)
            mapping = secure_mapping(
                secrets={
                    "gak": {"env": "TEST_DLMS_GAK"},
                    "guek": {"file": str(key_file)},
                }
            )
            config = parse_config(mapping)
            gak = resolve_secret(
                config.profile.secrets.gak,
                "GAK",
                environ={"TEST_DLMS_GAK": f"hex:{GAK}"},
            )
            guek = resolve_secret(config.profile.secrets.guek, "GUEK")

        self.assertEqual(gak, bytes.fromhex(GAK))
        self.assertEqual(guek, bytes.fromhex(GUEK))

    def test_resolution_errors_and_validation_errors_do_not_echo_key_material(self):
        bad = "DEADBEEF"
        mapping = secure_mapping()
        mapping["profiles"][0]["secrets"]["gak"] = {"inline": bad}
        try:
            parse_config(mapping)
        except ConfigError as exc:
            self.assertNotIn(bad, str(exc))
        else:
            self.fail("invalid GAK was accepted")

        config = parse_config(
            secure_mapping(
                secrets={
                    "gak": {"env": "MISSING_GAK"},
                    "guek": {"env": "MISSING_GUEK"},
                }
            )
        )
        with self.assertRaises(ConfigError) as raised:
            resolve_secure_keys(config.profile)
        self.assertNotIn(GAK, str(raised.exception))
        self.assertNotIn(GUEK, str(raised.exception))


if __name__ == "__main__":
    unittest.main()
