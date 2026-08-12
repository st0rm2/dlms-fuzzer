import sys
import types
import unittest
from unittest.mock import patch

from dlms_enum.config import parse_config
from dlms_enum.scanner import _serial_permission_message, scan_public


class Attribute:
    def __init__(self, index):
        self.index = index


class Method:
    def __init__(self, index, access):
        self.index = index
        self.methodAccess = access
        self.methodAccess3 = access


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


class ManyObject(FakeObject):
    def __init__(self, index):
        self.logicalName = f"1.0.{index}.8.0.255"


class LimitedSession(FakeSession):
    read_objects = []

    def discover_objects(self, attempt):
        return [ManyObject(index) for index in range(1, 13)]

    def read_attribute(self, target, attribute_id, attempt):
        self.read_objects.append((target.logicalName, attribute_id))
        return {"value": target.logicalName, "dlms_data_type": "visible_string"}


class WritableObject(FakeObject):
    attributes = [Attribute(2), Attribute(3)]
    methodAttributes = [Method(1, 1)]

    def getAccess(self, index):
        return {1: 1, 2: 3, 3: 2}[index]

    def getAttributeCount(self):
        return 3

    def getNames(self):
        return ("Logical name", "Value", "Configuration")

    def getMethodNames(self):
        return ("Reset",)


class WritableSession(FakeSession):
    def discover_objects(self, attempt):
        return [WritableObject()]

    def read_attribute(self, target, attribute_id, attempt):
        self.read_attempts.append((attribute_id, attempt))
        return {"value": "decoded", "dlms_data_type": "visible_string"}


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

    def test_association_write_and_action_rights_are_reported_but_not_executed(self):
        config = parse_config(
            {
                "transport": {"device": "/dev/null", "baudrate": 9600, "inter_request_delay_ms": 0},
                "scan": {"common_catalogue": False},
            }
        )
        module = types.ModuleType("dlms_enum.gurux_adapter")
        module.GuruxSession = WritableSession
        WritableSession.read_attempts = []

        with patch.dict(sys.modules, {"dlms_enum.gurux_adapter": module}):
            report = scan_public(config, object())

        profile = report["profiles"][0]
        attributes = profile["objects"][0]["attributes"]
        self.assertEqual(WritableSession.read_attempts, [(1, 1), (2, 1)])
        self.assertEqual(attributes[1]["advertised_operations"], ["GET", "SET"])
        self.assertEqual(attributes[2]["advertised_operations"], ["SET"])
        self.assertEqual(attributes[2]["lifecycle"], "not_readable")
        self.assertFalse(attributes[2]["write_tested"])
        self.assertEqual(profile["summary"]["advertised_set_attributes"], 2)
        self.assertEqual(profile["summary"]["advertised_action_methods"], 1)
        operations = [item["operation"] for item in report["capability_matrix"]]
        self.assertEqual(operations.count("GET"), 2)
        self.assertEqual(operations.count("SET"), 2)
        self.assertEqual(operations.count("ACTION"), 1)

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

    def test_short_scan_reads_full_association_then_only_first_ten_objects(self):
        config = parse_config(
            {
                "transport": {
                    "device": "/dev/null",
                    "baudrate": 9600,
                    "inter_request_delay_ms": 0,
                },
                "scan": {"common_catalogue": False, "object_limit": 10},
            }
        )
        module = types.ModuleType("dlms_enum.gurux_adapter")
        module.GuruxSession = LimitedSession
        LimitedSession.read_objects = []
        events = []

        with patch.dict(sys.modules, {"dlms_enum.gurux_adapter": module}):
            report = scan_public(config, object(), progress=events.append)

        profile = report["profiles"][0]
        self.assertEqual(profile["association_view_object_count"], 12)
        self.assertEqual(profile["scan_scope"]["selected_objects"], 10)
        self.assertTrue(profile["scan_scope"]["short_test"])
        self.assertEqual(len(profile["objects"]), 12)
        self.assertEqual(
            sorted(item["logical_name"] for item in profile["objects"]),
            sorted(f"1.0.{index}.8.0.255" for index in range(1, 13)),
        )
        self.assertFalse(
            any(name in {"1.0.11.8.0.255", "1.0.12.8.0.255"} for name, _ in LimitedSession.read_objects)
        )
        short_event = next(item for item in events if item["phase"] == "short_test_selected")
        self.assertEqual(short_event["association_view_objects"], 12)
        untested = [
            attribute
            for obj in profile["objects"]
            if obj["logical_name"] in {"1.0.11.8.0.255", "1.0.12.8.0.255"}
            for attribute in obj["attributes"]
        ]
        self.assertEqual({item["outcome"] for item in untested}, {"NOT_TESTED"})
        get_rows = [
            item for item in report["capability_matrix"] if item["operation"] == "GET"
        ]
        self.assertEqual(len(get_rows), 24)
        self.assertEqual(
            sum(
                row["profiles"]["public"]["status"] == "NOT_TESTED"
                for row in get_rows
            ),
            4,
        )

    def test_get_limit_tests_exact_budget_and_maps_remaining_gets(self):
        config = parse_config(
            {
                "transport": {
                    "device": "/dev/null",
                    "baudrate": 9600,
                    "inter_request_delay_ms": 0,
                },
                "scan": {"common_catalogue": False, "get_limit": 5},
            }
        )
        module = types.ModuleType("dlms_enum.gurux_adapter")
        module.GuruxSession = LimitedSession
        LimitedSession.read_objects = []

        with patch.dict(sys.modules, {"dlms_enum.gurux_adapter": module}):
            report = scan_public(config, object())

        profile = report["profiles"][0]
        self.assertEqual(len(LimitedSession.read_objects), 5)
        self.assertEqual(profile["summary"]["get_attempted"], 5)
        self.assertEqual(profile["summary"]["get_not_tested"], 19)
        self.assertEqual(profile["scan_scope"]["mapped_gets"], 24)
        self.assertEqual(profile["scan_scope"]["selected_gets"], 5)
        get_rows = [
            item for item in report["capability_matrix"] if item["operation"] == "GET"
        ]
        self.assertEqual(len(get_rows), 24)
        self.assertEqual(
            sum(row["profiles"]["public"]["tested"] for row in get_rows),
            5,
        )


if __name__ == "__main__":
    unittest.main()
