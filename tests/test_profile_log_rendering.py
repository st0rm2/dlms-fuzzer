import unittest

from dlms_enum.reporter import render_summary_report


class ProfileLogRenderingTests(unittest.TestCase):
    def test_profile_buffer_is_rendered_as_timestamped_rows(self):
        report = {
            "run": {"id": "run", "status": "completed"},
            "transport": {},
            "profiles": [
                {
                    "name": "public",
                    "association": {},
                    "summary": {},
                    "scan_scope": {},
                    "objects": [
                        {
                            "class_id": 7,
                            "logical_name": "1.0.99.98.0.255",
                            "description": "Event log",
                            "attributes": [
                                {
                                    "attribute_id": 2,
                                    "name": "Buffer",
                                    "outcome": "SUCCESS",
                                    "access_rights": {"read": True},
                                    "decoded": {
                                        "value": [
                                            ["2026-08-24T11:12:50Z", "Power restored"],
                                            ["2026-08-24T11:10:01Z", "Power failed"],
                                        ]
                                    },
                                }
                            ],
                            "methods": [],
                        }
                    ],
                }
            ],
            "errors": [],
        }

        rendered = render_summary_report(report)

        self.assertIn("Profile Generic logs and rows", rendered)
        self.assertIn("| Timestamp | Event / description |", rendered)
        self.assertIn("Power restored", rendered)
        self.assertIn("2 rows — see Profile Generic table above", rendered)
        self.assertNotIn(
            '[["2026-08-24T11:12:50Z","Power restored"]', rendered
        )

    def test_cosem_datetime_and_numeric_event_code_are_rendered_as_log_columns(self):
        report = {
            "run": {"id": "run", "status": "completed"},
            "transport": {},
            "profiles": [
                {
                    "name": "public",
                    "association": {},
                    "summary": {},
                    "scan_scope": {},
                    "objects": [
                        {
                            "class_id": 7,
                            "logical_name": "1.0.99.98.0.255",
                            "description": "Event log",
                            "attributes": [
                                {
                                    "attribute_id": 2,
                                    "outcome": "SUCCESS",
                                    "access_rights": {"read": True},
                                    "decoded": {
                                        "value": [[
                                            {
                                                "encoding": "octet-string",
                                                "hex": "07EA030D050F0F1C00FFC400",
                                                "length": 12,
                                            },
                                            255,
                                        ]]
                                    },
                                }
                            ],
                            "methods": [],
                        }
                    ],
                }
            ],
            "errors": [],
        }

        rendered = render_summary_report(report)

        self.assertIn("| Timestamp | Event code | Description |", rendered)
        self.assertIn("2026-03-13T15:15:28+01:00", rendered)
        self.assertIn("Meter-specific event code 255", rendered)

    def test_profile_schema_names_columns_and_displays_profile_metadata(self):
        report = {
            "run": {"id": "run", "status": "completed"},
            "transport": {},
            "profiles": [
                {
                    "name": "public",
                    "association": {},
                    "summary": {},
                    "scan_scope": {},
                    "objects": [
                        {
                            "class_id": 7,
                            "logical_name": "1.0.99.1.0.255",
                            "description": "Load profile",
                            "profile_generic": {
                                "row_encoding": "array_of_structures",
                                "capture_period_seconds": 900,
                                "sort_method": "fifo",
                                "entries_in_use": 1,
                                "profile_entries": 1000,
                                "columns": [
                                    {
                                        "position": 1,
                                        "class_id": 8,
                                        "logical_name": "0.0.1.0.0.255",
                                        "attribute_id": 2,
                                        "data_index": 0,
                                        "attribute_name": "Time",
                                        "ui_data_type": "datetime",
                                    },
                                    {
                                        "position": 2,
                                        "class_id": 3,
                                        "logical_name": "1.0.1.8.0.255",
                                        "attribute_id": 2,
                                        "data_index": 0,
                                        "attribute_name": "Value",
                                        "interface_data_type": "uint32",
                                        "engineering_metadata": {
                                            "scaler": 0.001,
                                            "unit": "active_energy",
                                        },
                                    },
                                ],
                            },
                            "attributes": [
                                {
                                    "attribute_id": 2,
                                    "outcome": "SUCCESS",
                                    "access_rights": {"read": True},
                                    "decoded": {
                                        "value": [["2026-08-27T10:00:00Z", 123456]]
                                    },
                                }
                            ],
                            "methods": [],
                        }
                    ],
                }
            ],
            "errors": [],
        }

        rendered = render_summary_report(report)

        self.assertIn("| Capture period | 900 seconds |", rendered)
        self.assertIn("| 2 | 1.0.1.8.0.255 | 3 | 2 | 0 | Value |", rendered)
        self.assertIn(
            "| Time (0.0.1.0.0.255 attr 2) | Value (1.0.1.8.0.255 attr 2) |",
            rendered,
        )


if __name__ == "__main__":
    unittest.main()
