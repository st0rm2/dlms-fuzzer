import json
import tempfile
import unittest
from pathlib import Path

from dlms_enum.result_model import Outcome, classify_exception, normalize_value
from dlms_enum.reporter import load_report, render_summary_report, write_report
from dlms_enum.traffic_logger import TrafficLogger, redact


class ResultAndTrafficTests(unittest.TestCase):
    def test_octets_keep_machine_and_human_representations(self):
        value = normalize_value(b"ABC123")
        self.assertEqual(value["hex"], "414243313233")
        self.assertEqual(value["base64"], "QUJDMTIz")
        self.assertEqual(value["text"], "ABC123")

    def test_timeout_is_normalized(self):
        self.assertEqual(classify_exception(TimeoutError("late")), Outcome.TIMEOUT)

    def test_sensitive_keys_and_xml_values_are_redacted(self):
        clean, indicators = redact(
            {
                "authentication_key": "not-safe",
                "gak": "00112233445566778899AABBCCDDEEFF",
                "guek": "FFEEDDCCBBAA99887766554433221100",
                "xml": '<CallingAuthentication Value="AABB" />',
            }
        )
        self.assertEqual(clean["authentication_key"], "<redacted>")
        self.assertEqual(clean["gak"], "<redacted>")
        self.assertEqual(clean["guek"], "<redacted>")
        self.assertIn("<redacted>", clean["xml"])
        self.assertTrue(indicators)

    def test_jsonl_has_side_by_side_schema_and_flushes(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "traffic.jsonl"
            logger = TrafficLogger(path)
            logger.log(
                profile="public",
                phase="get_scan",
                purpose="object_attribute_read",
                object_context={"logical_name": "1.0.1.8.0.255"},
                operation="GET",
                attempt=1,
                tx_frames=[b"\x7e\x01\x7e"],
                tx_decoded={"service": "get-request"},
                rx_frames=[b"\x7e\x02\x7e"],
                rx_decoded={"value": 12},
                elapsed_ms=1.25,
                result="SUCCESS",
            )
            record = json.loads(path.read_text(encoding="utf-8"))
            logger.close()
        self.assertEqual(record["sequence_number"], 1)
        self.assertEqual(record["tx"]["encoded_frames"], ["7E017E"])
        self.assertEqual(record["rx"]["decoded"]["value"], 12)

    def test_report_is_canonical_json_with_traffic_hash(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            traffic = root / "traffic.jsonl"
            traffic.write_text("{}\n", encoding="utf-8")
            report_path = root / "report.json"
            report = {
                "schema_version": 1,
                "run": {"id": "test", "status": "completed"},
                "transport": {},
                "profiles": [],
                "errors": [],
            }
            write_report(report, report_path, traffic)
            loaded = load_report(root)
        self.assertEqual(len(loaded["related_logs"]["traffic_sha256"]), 64)
        self.assertEqual(loaded["related_logs"]["traffic_file"], "traffic.jsonl")

    def test_compact_report_has_profile_obis_decoded_and_hex_table(self):
        report = {
            "schema_version": 1,
            "run": {"id": "test", "status": "completed"},
            "transport": {"selected_baudrate": 9600, "selected_server_address": 1},
            "profiles": [
                {
                    "name": "hls_gmac_suite0",
                    "association": {
                        "client_address": 4,
                        "authentication": "high_gmac",
                        "security": "authentication_encryption",
                        "security_suite": 0,
                        "hls_validated": True,
                    },
                    "summary": {"objects": 1, "get_success": 2, "get_failed": 0},
                    "scan_scope": {
                        "short_test": True,
                        "selected_objects": 1,
                        "association_view_objects": 20,
                    },
                    "identification": {"serial_number": "12345"},
                    "objects": [
                        {
                            "logical_name": "0.0.96.1.0.255",
                            "class_id": 1,
                            "attributes": [
                                {"attribute_id": 1, "outcome": "SUCCESS"},
                                {
                                    "attribute_id": 2,
                                    "name": "Value",
                                    "outcome": "SUCCESS",
                                    "decoded": {
                                        "value": "12345",
                                        "raw_value": {
                                            "encoding": "octet-string",
                                            "hex": "3132333435",
                                            "text": "12345",
                                        },
                                    },
                                },
                            ],
                        }
                    ],
                }
            ],
            "errors": [],
        }

        rendered = render_summary_report(report)

        self.assertIn("## Profile: hls_gmac_suite0", rendered)
        self.assertIn("First 1 objects (short test)", rendered)
        self.assertIn("| 0.0.96.1.0.255 | 1 | 2 | Value | 12345 | 3132333435 | — | SUCCESS |", rendered)

    def test_write_report_links_compact_summary(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            traffic = root / "traffic.jsonl"
            traffic.write_text("{}\n", encoding="utf-8")
            report_path = root / "report.json"
            summary_path = root / "summary.md"
            report = {
                "schema_version": 1,
                "run": {"id": "test", "status": "completed"},
                "transport": {},
                "profiles": [],
                "errors": [],
            }
            write_report(report, report_path, traffic, summary_path)
            loaded = load_report(report_path)

        self.assertEqual(loaded["related_logs"]["summary_file"], "summary.md")
        self.assertEqual(len(loaded["related_logs"]["summary_sha256"]), 64)

    def test_summary_lists_passive_set_and_action_capabilities(self):
        report = {
            "schema_version": 1,
            "run": {"id": "test", "status": "completed"},
            "transport": {},
            "profiles": [
                {
                    "name": "role_4",
                    "association": {"client_address": 4},
                    "summary": {
                        "objects": 1,
                        "advertised_set_attributes": 1,
                        "advertised_action_methods": 1,
                    },
                    "objects": [
                        {
                            "logical_name": "1.0.0.1.0.255",
                            "class_id": 1,
                            "attributes": [
                                {
                                    "attribute_id": 2,
                                    "name": "Value",
                                    "advertised_access": "read_write",
                                    "access_rights": {"read": True, "write": True},
                                    "outcome": "SUCCESS",
                                    "decoded": {"value": 7},
                                }
                            ],
                            "methods": [
                                {
                                    "method_id": 1,
                                    "name": "Reset",
                                    "advertised_access": "access",
                                    "access_rights": {"action": True},
                                }
                            ],
                        }
                    ],
                }
            ],
            "errors": [],
        }

        rendered = render_summary_report(report)

        self.assertIn("### Operation capability matrix", rendered)
        self.assertIn("| SET | 1.0.0.1.0.255 | 1 | 2 | Value | read_write | NOT_TESTED |", rendered)
        self.assertIn("| ACTION | 1.0.0.1.0.255 | 1 | 1 | Reset | access | NOT_TESTED |", rendered)
        self.assertIn("SET and ACTION are mapped passively", rendered)

    def test_summary_highlights_unexpected_public_cross_profile_access(self):
        report = {
            "schema_version": 1,
            "run": {"id": "test", "status": "completed"},
            "transport": {},
            "profiles": [],
            "public_union_test": {
                "enabled": True,
                "status": "completed",
                "public_association_view_objects": 3,
                "candidate_gets": 1,
                "selected_gets": 1,
                "unexpected_public_access": 1,
                "public_access_rejected": 0,
                "inconclusive": 0,
                "results": [
                    {
                        "class_id": 1,
                        "logical_name": "1.0.99.1.0.255",
                        "attribute_id": 2,
                        "name": "Value",
                        "public_object_advertised": False,
                        "outcome": "SUCCESS",
                        "access_assessment": "UNEXPECTED_PUBLIC_ACCESS",
                        "decoded": {"value": "exposed"},
                    }
                ],
            },
            "errors": [],
        }

        rendered = render_summary_report(report)

        self.assertIn("## Public cross-profile access test", rendered)
        self.assertIn("| Selected GETs | 1 |", rendered)
        self.assertIn("| Unexpected public access | 1 |", rendered)
        self.assertIn("UNEXPECTED_PUBLIC_ACCESS", rendered)
        self.assertIn("exposed", rendered)

    def test_written_summary_includes_ciphertext_without_full_hdlc_frame(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            traffic = root / "traffic.jsonl"
            traffic.write_text(
                json.dumps(
                    {
                        "sequence_number": 7,
                        "operation": "GET",
                        "result": "SUCCESS",
                        "object_context": {
                            "class_id": 1,
                            "logical_name": "1.0.1.8.0.255",
                            "attribute_id": 2,
                        },
                        "tx": {
                            "encoded_frames": ["7EA02C0309540911DEADBEEF7E"],
                            "decoded": {
                                "protected": True,
                                "protected_command": "glo-get-request",
                                "security_control": "0x30",
                                "invocation_counter": 42,
                                "ciphertext_hex": "A1B2C3D4",
                                "ciphertext_captured_length": 4,
                                "ciphertext_declared_length": 4,
                                "ciphertext_complete": True,
                                "authentication_tag_hex": "00112233445566778899AABB",
                                "authentication_tag_complete": True,
                            },
                        },
                        "rx": {
                            "decoded": {
                                "protected": True,
                                "protected_command": "glo-get-response",
                                "security_control": "0x30",
                                "invocation_counter": 99,
                                "ciphertext_hex": "E5F6A7B8",
                                "ciphertext_captured_length": 4,
                                "ciphertext_declared_length": 4,
                                "ciphertext_complete": True,
                                "authentication_tag_hex": "AABBCCDDEEFF001122334455",
                                "authentication_tag_complete": True,
                            }
                        },
                    }
                )
                + "\n",
                encoding="utf-8",
            )
            report_path = root / "report.json"
            summary_path = root / "summary.md"
            report = {
                "schema_version": 1,
                "run": {"id": "test", "status": "completed"},
                "transport": {},
                "profiles": [
                    {
                        "name": "hls_gmac_suite0",
                        "association": {},
                        "summary": {"objects": 1, "get_success": 1},
                        "objects": [
                            {
                                "class_id": 1,
                                "logical_name": "1.0.1.8.0.255",
                                "attributes": [
                                    {
                                        "attribute_id": 2,
                                        "name": "Value",
                                        "access_rights": {"read": True},
                                        "advertised_access": "read",
                                        "outcome": "SUCCESS",
                                        "decoded": {
                                            "value": 10,
                                            "raw_value": {
                                                "encoding": "octet-string",
                                                "hex": "0A",
                                            },
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

            write_report(report, report_path, traffic, summary_path)
            rendered = summary_path.read_text(encoding="utf-8")

        self.assertIn("## Protected APDU evidence", rendered)
        self.assertIn(
            "| 7 | TX | GET | glo-get-request | 0x30 | 42 | A1B2C3D4 |",
            rendered,
        )
        self.assertIn("00112233445566778899AABB", rendered)
        self.assertIn("| SUCCESS |", rendered)
        self.assertIn(
            "| 1.0.1.8.0.255 | 1 | 2 | Value | 10 | 0A | E5F6A7B8 | SUCCESS |",
            rendered,
        )
        self.assertNotIn("7EA02C0309540911DEADBEEF7E", rendered)


if __name__ == "__main__":
    unittest.main()
