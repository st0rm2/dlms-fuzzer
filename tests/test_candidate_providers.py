import tempfile
import unittest
from pathlib import Path

from dlms_enum.catalogues import CatalogueEntry, bounded_candidates
from dlms_enum.config import ConfigError, dump_config, load_config, parse_config


class CandidateProviderTests(unittest.TestCase):
    def test_provider_targets_are_deterministic_deduplicated_and_bounded(self):
        duplicate = CatalogueEntry(
            64,
            "0.0.43.0.0.255",
            (2,),
            "Configured duplicate",
            provider="user",
            rule="configured_candidate",
            confidence="operator_supplied",
        )
        selected, summary = bounded_candidates(
            ("security",), (duplicate,), request_limit=3
        )
        self.assertEqual(len(selected), 3)
        self.assertEqual(
            [(item.logical_name, item.attributes[0]) for item in selected],
            [
                ("0.0.43.0.0.255", 2),
                ("0.0.43.0.0.255", 3),
                ("0.0.43.0.0.255", 4),
            ],
        )
        self.assertEqual(selected[0].provider, "user")
        self.assertEqual(summary["selected_targets"], 3)
        self.assertGreater(summary["truncated_targets"], 0)

        selected, summary = bounded_candidates(
            ("firmware",),
            (),
            request_limit=3,
            excluded_objects={(18, "0.0.44.0.0.255")},
        )
        self.assertEqual(selected, ())
        self.assertEqual(summary["available_targets"], 0)
        self.assertEqual(summary["excluded_association_targets"], 3)

    def test_configuration_accepts_builtin_and_exact_user_candidates(self):
        config = parse_config(
            {
                "transport": {"device": "/dev/null"},
                "scan": {
                    "candidate_providers": ["security", "firmware"],
                    "candidate_limit": 12,
                    "candidate_objects": [
                        {
                            "class_id": 99,
                            "logical_name": "0.0.128.0.0.255",
                            "attributes": [2, 3],
                            "description": "Vendor status",
                        }
                    ],
                },
            }
        )
        self.assertEqual(config.scan.candidate_providers, ("security", "firmware"))
        self.assertEqual(config.scan.candidate_limit, 12)
        self.assertEqual(config.scan.candidate_objects[0].provider, "user")

        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "meter.yaml"
            dump_config(config, path)
            reloaded = load_config(path)
        self.assertEqual(reloaded.scan.candidate_providers, ("security", "firmware"))
        self.assertEqual(reloaded.scan.candidate_objects, config.scan.candidate_objects)

        with self.assertRaisesRegex(ConfigError, "unknown providers"):
            parse_config(
                {
                    "transport": {"device": "/dev/null"},
                    "scan": {"candidate_providers": ["everything"]},
                }
            )
        with self.assertRaisesRegex(ConfigError, "six-part"):
            parse_config(
                {
                    "transport": {"device": "/dev/null"},
                    "scan": {
                        "candidate_objects": [
                            {
                                "class_id": 1,
                                "logical_name": "not-an-obis",
                                "attributes": [2],
                            }
                        ]
                    },
                }
            )


if __name__ == "__main__":
    unittest.main()
