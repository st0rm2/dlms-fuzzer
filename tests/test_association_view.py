import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from dlms_enum.association_view import (
    compare_snapshots,
    default_cache_path,
    load_snapshot,
    snapshot_from_report,
    validate_snapshot,
    write_snapshot,
)


def sample_report():
    return {
        "effective_configuration": {
            "profiles": [{"name": "public", "client_address": 16}]
        },
        "transport": {
            "device": "/dev/ttyUSB0",
            "selected_server_address": 1,
        },
        "preflight": {"meter_identity": "meter-1"},
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
                        "attributes": [
                            {
                                "attribute_id": 2,
                                "name": "Value",
                                "access_rights": {"read": True, "raw": 1},
                            }
                        ],
                        "methods": [],
                    },
                    {
                        "class_id": 3,
                        "logical_name": "1.0.1.8.0.255",
                        "discovery_sources": ["common_catalogue"],
                        "attributes": [],
                        "methods": [],
                    },
                ],
            }
        ],
    }


class AssociationViewSnapshotTests(unittest.TestCase):
    def test_snapshot_is_portable_and_filters_catalogue_only_objects(self):
        snapshot = snapshot_from_report(sample_report())
        self.assertEqual(snapshot["object_count"], 1)
        self.assertEqual(snapshot["identity"]["role"], "public")
        validate_snapshot(
            snapshot,
            device="/dev/ttyUSB0",
            role="public",
            client_address=16,
        )
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "association-view.json"
            write_snapshot(snapshot, path)
            self.assertEqual(load_snapshot(path)["objects"], snapshot["objects"])

    def test_comparison_reports_added_removed_and_changed_objects(self):
        saved = snapshot_from_report(sample_report())
        current = snapshot_from_report(sample_report())
        current["objects"][0]["attributes"][0]["access_rights"]["raw"] = 3
        current["objects"].append(
            {
                "class_id": 8,
                "logical_name": "0.0.1.0.0.255",
                "object_version": 0,
                "attributes": [],
                "methods": [],
            }
        )
        result = compare_snapshots(saved, current)
        self.assertFalse(result["matches"])
        self.assertEqual(len(result["added"]), 1)
        self.assertEqual(len(result["changed"]), 1)

    def test_default_path_is_separate_per_device_and_role(self):
        with tempfile.TemporaryDirectory() as directory, patch.dict(
            os.environ, {"XDG_STATE_HOME": directory}
        ):
            public = default_cache_path("/dev/ttyUSB0", "public")
            secure = default_cache_path("/dev/ttyUSB0", "client4")
            other_device = default_cache_path("/dev/ttyUSB1", "public")
        self.assertNotEqual(public, secure)
        self.assertNotEqual(public, other_device)


if __name__ == "__main__":
    unittest.main()
