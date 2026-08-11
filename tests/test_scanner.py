import sys
import types
import unittest
from unittest.mock import patch

from dlms_enum.config import parse_config
from dlms_enum.scanner import _serial_permission_message, scan_public


class Attribute:
    def __init__(self, index):
        self.index = index


class FakeObject:
    objectType = 1
    logicalName = "0.0.96.1.0.255"
    version = 0
    description = "Serial number"
    attributes = [Attribute(2)]
    methodAttributes = []

    def getAccess(self, index):
        return 1

    def getAccess3(self, index):
        return 1

    def getAttributeCount(self):
        return 2

    def getNames(self):
        return ("Logical name", "Value")


class FakeSession:
    read_attempts = []

    def __init__(
        self,
        config,
        baudrate,
        traffic,
        *,
        server_logical_address=None,
        server_physical_address=None,
        server_address_size=0,
    ):
        self.baudrate = baudrate
        self.server_logical_address = server_logical_address
        self.server_physical_address = server_physical_address
        self.server_address_size = server_address_size

    def connect(self):
        return {"authentication": "none", "negotiated_conformance": ["get"]}

    def discover_objects(self, attempt):
        return [FakeObject()]

    def read_attribute(self, target, attribute_id, attempt):
        self.read_attempts.append((attribute_id, attempt))
        if attribute_id == 2 and attempt == 1:
            raise TimeoutError("first attempt timed out")
        return {"value": "decoded", "dlms_data_type": "visible_string"}

    def create_object(self, class_id, logical_name):
        raise AssertionError("common catalogue is disabled in this test")

    def close(self):
        return []


class TwoByteOnlySession(FakeSession):
    endpoint_attempts = []

    def connect(self):
        self.endpoint_attempts.append(
            (
                self.server_logical_address,
                self.server_physical_address,
                self.server_address_size,
            )
        )
        if self.server_address_size == 1:
            raise TimeoutError("one-byte server address did not reply")
        return super().connect()


class ScannerTests(unittest.TestCase):
    def test_serial_permission_message_recommends_device_group(self):
        device_stat = types.SimpleNamespace(st_mode=0o20660, st_uid=0, st_gid=986)
        group = types.SimpleNamespace(gr_name="uucp")
        owner = types.SimpleNamespace(pw_name="root")

        with (
            patch("dlms_enum.scanner.getpass.getuser", return_value="storm"),
            patch("dlms_enum.scanner.os.getgroups", return_value=[1000]),
            patch("dlms_enum.scanner.os.getegid", return_value=1000),
            patch("grp.getgrgid", return_value=group),
            patch("pwd.getpwuid", return_value=owner),
        ):
            message = _serial_permission_message(device_stat, "/dev/ttyUSB0")

        self.assertIn("owner root:uucp", message)
        self.assertIn("sudo usermod -aG uucp storm", message)
        self.assertIn("log out and back in", message)

    def test_serial_permission_failure_is_actionable_and_emitted_to_ui(self):
        config = parse_config({"transport": {"device": "/dev/null", "baudrate": 9600}})
        events = []

        with patch("dlms_enum.scanner.os.access", return_value=False):
            report = scan_public(config, object(), progress=events.append)

        self.assertEqual(report["run"]["status"], "failed")
        message = report["errors"][-1]["message"]
        self.assertIn("Permission denied for serial device /dev/null", message)
        self.assertIn("udev rule", message)
        self.assertEqual(events[-1]["level"], "error")
        self.assertEqual(events[-1]["message"], message)

    def test_get_has_one_retry_and_only_success_counts(self):
        config = parse_config(
            {
                "transport": {"device": "/dev/null", "baudrate": 9600, "inter_request_delay_ms": 0},
                "scan": {"mode": "get", "total_get_attempts": 2, "common_catalogue": False},
            }
        )
        module = types.ModuleType("dlms_enum.gurux_adapter")
        module.GuruxSession = FakeSession
        FakeSession.read_attempts = []
        previous = sys.modules.get("dlms_enum.gurux_adapter")
        sys.modules["dlms_enum.gurux_adapter"] = module
        try:
            report = scan_public(config, object())
        finally:
            if previous is None:
                sys.modules.pop("dlms_enum.gurux_adapter", None)
            else:
                sys.modules["dlms_enum.gurux_adapter"] = previous

        summary = report["profiles"][0]["summary"]
        self.assertEqual(summary["get_success"], 2)  # LN attribute plus value attribute
        self.assertEqual(summary["get_failed"], 0)
        self.assertEqual(summary["get_transmissions"], 3)
        self.assertEqual(FakeSession.read_attempts, [(1, 1), (2, 1), (2, 2)])
        self.assertEqual(report["transport"]["selected_server_address"], 1)
        self.assertEqual(report["transport"]["server_address_size"], 1)
        self.assertEqual(
            report["transport"]["server_addressing_type"], "1-byte addressing"
        )
        value_attribute = report["profiles"][0]["objects"][0]["attributes"][1]
        self.assertEqual(value_attribute["attempt_count"], 2)
        self.assertEqual(value_attribute["outcome"], "SUCCESS")

    def test_two_byte_server_address_is_discovered_after_one_byte_timeout(self):
        config = parse_config(
            {
                "transport": {
                    "device": "/dev/null",
                    "baudrate": 9600,
                    "inter_request_delay_ms": 0,
                },
                "scan": {"mode": "get", "total_get_attempts": 2, "common_catalogue": False},
            }
        )
        module = types.ModuleType("dlms_enum.gurux_adapter")
        module.GuruxSession = TwoByteOnlySession
        TwoByteOnlySession.endpoint_attempts = []

        with patch.dict(sys.modules, {"dlms_enum.gurux_adapter": module}):
            report = scan_public(config, object())

        self.assertEqual(
            TwoByteOnlySession.endpoint_attempts,
            [(0, 1, 1), (1, 1, 2)],
        )
        self.assertEqual(report["transport"]["selected_server_address"], 129)
        self.assertEqual(report["transport"]["server_address_size"], 2)
        self.assertEqual(
            report["transport"]["server_addressing_type"], "2-Byte addressing"
        )
        self.assertEqual(
            [item["valid"] for item in report["transport"]["endpoint_findings"]],
            [False, True],
        )


if __name__ == "__main__":
    unittest.main()
