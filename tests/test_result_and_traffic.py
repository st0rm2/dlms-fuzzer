import json
import tempfile
import unittest
from pathlib import Path

from dlms_enum.result_model import Outcome, classify_exception, normalize_value
from dlms_enum.reporter import load_report, write_report
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
                "xml": '<CallingAuthenticationValue Value="AABB" />',
            }
        )
        self.assertEqual(clean["authentication_key"], "<redacted>")
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


if __name__ == "__main__":
    unittest.main()
