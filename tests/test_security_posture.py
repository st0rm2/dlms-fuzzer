import unittest

from dlms_enum.security_posture import build_security_posture
from dlms_enum.reporter import render_summary_report


class SecurityPostureTests(unittest.TestCase):
    def test_public_security_and_firmware_controls_are_flagged_passively(self):
        profile = {
            "name": "public",
            "association": {"authentication": "none"},
            "objects": [
                {
                    "class_id": 64,
                    "logical_name": "0.0.43.0.0.255",
                    "attributes": [
                        {
                            "attribute_id": 2,
                            "outcome": "SUCCESS",
                            "decoded": {"value": 1},
                            "access_rights": {"read": True, "write": True},
                        }
                    ],
                    "methods": [
                        {
                            "method_id": 2,
                            "access_rights": {"action": True, "requirements": []},
                        }
                    ],
                },
                {
                    "class_id": 18,
                    "logical_name": "0.0.44.0.0.255",
                    "attributes": [
                        {
                            "attribute_id": 5,
                            "outcome": "SUCCESS",
                            "decoded": {"value": True},
                            "access_rights": {"read": True, "write": False},
                        }
                    ],
                    "methods": [
                        {
                            "method_id": 4,
                            "access_rights": {"action": True, "requirements": []},
                        }
                    ],
                },
            ],
        }
        posture = build_security_posture(profile)
        self.assertEqual(posture["summary"]["security_setup_objects"], 1)
        self.assertEqual(posture["summary"]["image_transfer_objects"], 1)
        self.assertEqual(posture["summary"]["high_findings"], 3)
        self.assertEqual(
            posture["security_setup_objects"][0]["attributes"][0]["value"], 1
        )
        self.assertTrue(
            all(item["passive_evidence"] for item in posture["findings"])
        )

        rendered = render_summary_report(
            {
                "run": {"id": "test", "status": "completed"},
                "transport": {},
                "profiles": [
                    {
                        **profile,
                        "security_posture": posture,
                        "summary": {},
                        "scan_scope": {},
                    }
                ],
                "errors": [],
            }
        )
        self.assertIn("Security and firmware-update posture", rendered)
        self.assertIn("Public role advertises firmware-update control", rendered)

    def test_authenticated_controls_are_reported_without_public_findings(self):
        profile = {
            "name": "client4",
            "association": {"authentication": "high_gmac"},
            "objects": [
                {
                    "class_id": 64,
                    "logical_name": "0.0.43.0.0.255",
                    "attributes": [],
                    "methods": [
                        {"method_id": 2, "access_rights": {"action": True}}
                    ],
                }
            ],
        }
        posture = build_security_posture(profile)
        self.assertEqual(posture["findings"], [])


if __name__ == "__main__":
    unittest.main()
