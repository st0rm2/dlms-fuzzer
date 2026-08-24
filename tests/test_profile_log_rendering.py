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


if __name__ == "__main__":
    unittest.main()
