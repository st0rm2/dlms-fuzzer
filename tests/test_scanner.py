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


class EventLogObject(FakeObject):
    objectType = 7
    logicalName = "0.0.99.98.0.255"
    description = "Event log"


class LimitedSession(FakeSession):
    read_objects = []

    def discover_objects(self, attempt):
        return [ManyObject(index) for index in range(1, 13)]

    def read_attribute(self, target, attribute_id, attempt):
        self.read_objects.append((target.logicalName, attribute_id))
        return {"value": target.logicalName, "dlms_data_type": "visible_string"}


class ProfilePrioritySession(LimitedSession):
    def discover_objects(self, attempt):
        return [ManyObject(index) for index in range(1, 13)] + [EventLogObject()]

    def read_attribute(self, target, attribute_id, attempt):
        self.read_objects.append((target.logicalName, attribute_id))
        if target.objectType == 7 and attribute_id == 2:
            return {
                "value": [["2026-08-24T11:45:00Z", 42]],
                "dlms_data_type": "array",
            }
        return {"value": target.logicalName, "dlms_data_type": "visible_string"}


class BatchSession(LimitedSession):
    batches = []

    def connect(self):
        return {
            "authentication": "none",
            "negotiated_conformance": ["get", "multiple_references"],
            "max_receive_pdu_size": 62,
        }

    def read_attributes(self, requests, attempt):
        self.batches.append(
            [(target.logicalName, attribute_id) for target, attribute_id in requests]
        )
        return [
            {"value": target.logicalName, "dlms_data_type": "visible_string"}
            for target, _ in requests
        ]


class FailingBatchSession(BatchSession):
    def discover_objects(self, attempt):
        return [ManyObject(1), ManyObject(2)]

    def read_attributes(self, requests, attempt):
        self.batches.append(
            [(target.logicalName, attribute_id) for target, attribute_id in requests]
        )
        raise RuntimeError("list service rejected")


class TimeoutSession(FakeSession):
    read_attempts = []

    def discover_objects(self, attempt):
        return [ManyObject(1), ManyObject(2)]

    def read_attribute(self, target, attribute_id, attempt):
        self.read_attempts.append((target.logicalName, attribute_id, attempt))
        raise TimeoutError("meter did not reply")


class CircuitBreakerSession(FakeSession):
    read_attempts = []
    timeout_changes = []
    reconnects = 0

    def discover_objects(self, attempt):
        return [ManyObject(index) for index in range(1, 9)]

    def set_response_timeout(self, timeout_ms):
        self.timeout_changes.append(timeout_ms)

    def read_attribute(
        self,
        target,
        attribute_id,
        attempt,
        *,
        phase="get_scan",
        purpose="object_attribute_read",
    ):
        self.read_attempts.append(
            (target.logicalName, attribute_id, attempt, phase, purpose)
        )
        if target.logicalName == "1.0.1.8.0.255" and phase == "get_scan":
            return {"value": "known-good", "dlms_data_type": "visible_string"}
        raise TimeoutError("meter did not reply")

    def reconnect(self):
        self.__class__.reconnects += 1
        return self.connect()


class RecoveringCircuitSession(CircuitBreakerSession):
    def discover_objects(self, attempt):
        return [ManyObject(index) for index in range(1, 7)]

    def read_attribute(
        self,
        target,
        attribute_id,
        attempt,
        *,
        phase="get_scan",
        purpose="object_attribute_read",
    ):
        self.read_attempts.append(
            (target.logicalName, attribute_id, attempt, phase, purpose)
        )
        index = int(target.logicalName.split(".")[2])
        if phase == "get_health_check" or index in {1, 5, 6}:
            return {"value": "known-good", "dlms_data_type": "visible_string"}
        raise TimeoutError("meter did not reply")


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


class SnapshotObject(FakeObject):
    def __init__(self, class_id, logical_name):
        self.objectType = class_id
        self.logicalName = logical_name
        self.version = 2 if class_id == 15 else 0
        self.description = ""
        self.attributes = []
        self.methodAttributes = []

    def setAccess(self, index, access):
        self.attributes.append(Attribute(index))

    def setMethodAccess(self, index, access):
        self.methodAttributes.append(Method(index, access))


class ReusedViewSession(FakeSession):
    read_objects = []

    def discover_objects(self, attempt):
        raise AssertionError("saved Association View must skip meter discovery")

    def create_object(self, class_id, logical_name):
        return SnapshotObject(class_id, logical_name)

    def read_attribute(self, target, attribute_id, attempt):
        self.read_objects.append((target.objectType, target.logicalName, attribute_id))
        return {"value": "decoded", "dlms_data_type": "visible_string"}


class CandidateSession(LimitedSession):
    def discover_objects(self, attempt):
        return [ManyObject(1)]

    def create_object(self, class_id, logical_name):
        return SnapshotObject(class_id, logical_name)


class GXDLMSException(Exception):
    pass


class RejectedCandidateSession(CandidateSession):
    def read_attribute(self, target, attribute_id, attempt):
        if target.logicalName == "0.0.128.0.0.255":
            raise GXDLMSException("object unavailable")
        return super().read_attribute(target, attribute_id, attempt)


class SecuritySetupObject(FakeObject):
    objectType = 64
    logicalName = "0.0.43.0.0.255"
    description = "Security Setup"
    attributes = [Attribute(2), Attribute(3), Attribute(4), Attribute(5)]

    def getAttributeCount(self):
        return 5

    def getNames(self):
        return (
            "Logical name",
            "Security policy",
            "Security suite",
            "Client system title",
            "Server system title",
        )


class PosturePrioritySession(LimitedSession):
    def discover_objects(self, attempt):
        return [ManyObject(index) for index in range(1, 10)] + [SecuritySetupObject()]


class ScannerTests(unittest.TestCase):
    def test_user_candidate_is_probed_with_provenance_and_independent_budget(self):
        config = parse_config(
            {
                "transport": {
                    "device": "/dev/null",
                    "baudrate": 9600,
                    "inter_request_delay_ms": 0,
                },
                "scan": {
                    "common_catalogue": False,
                    "candidate_providers": [],
                    "candidate_limit": 1,
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
        module = types.ModuleType("dlms_enum.gurux_adapter")
        module.GuruxSession = CandidateSession
        CandidateSession.read_objects = []
        with patch.dict(sys.modules, {"dlms_enum.gurux_adapter": module}):
            report = scan_public(config, object())

        self.assertEqual(report["candidate_generation"]["available_targets"], 2)
        self.assertEqual(report["candidate_generation"]["selected_targets"], 1)
        self.assertEqual(report["candidate_generation"]["truncated_targets"], 1)
        candidate = next(
            obj
            for obj in report["profiles"][0]["objects"]
            if obj["logical_name"] == "0.0.128.0.0.255"
        )
        self.assertIn("candidate_user", candidate["discovery_sources"])
        rights = candidate["attributes"][0]["access_rights"]
        self.assertEqual(rights["candidate_provider"], "user")
        self.assertEqual(rights["candidate_rule"], "configured_candidate")

    def test_get_limit_prioritizes_security_posture_values(self):
        config = parse_config(
            {
                "transport": {
                    "device": "/dev/null",
                    "baudrate": 9600,
                    "inter_request_delay_ms": 0,
                },
                "scan": {
                    "common_catalogue": False,
                    "candidate_providers": [],
                    "get_limit": 2,
                },
            }
        )
        module = types.ModuleType("dlms_enum.gurux_adapter")
        module.GuruxSession = PosturePrioritySession
        PosturePrioritySession.read_objects = []
        with patch.dict(sys.modules, {"dlms_enum.gurux_adapter": module}):
            report = scan_public(config, object())

        profile = report["profiles"][0]
        self.assertEqual(
            PosturePrioritySession.read_objects,
            [("0.0.43.0.0.255", 2), ("0.0.43.0.0.255", 3)],
        )
        self.assertEqual(profile["summary"]["security_setup_objects"], 1)
        self.assertEqual(len(profile["scan_scope"]["prioritized_posture_gets"]), 2)

    def test_expected_candidate_rejection_is_evidence_not_a_run_error(self):
        config = parse_config(
            {
                "transport": {
                    "device": "/dev/null",
                    "baudrate": 9600,
                    "inter_request_delay_ms": 0,
                },
                "scan": {
                    "common_catalogue": False,
                    "candidate_providers": [],
                    "candidate_limit": 1,
                    "candidate_objects": [
                        {
                            "class_id": 99,
                            "logical_name": "0.0.128.0.0.255",
                            "attributes": [2],
                        }
                    ],
                },
            }
        )
        module = types.ModuleType("dlms_enum.gurux_adapter")
        module.GuruxSession = RejectedCandidateSession
        with patch.dict(sys.modules, {"dlms_enum.gurux_adapter": module}):
            report = scan_public(config, object())

        candidate = next(
            obj
            for obj in report["profiles"][0]["objects"]
            if obj["logical_name"] == "0.0.128.0.0.255"
        )
        self.assertEqual(report["run"]["status"], "completed")
        self.assertEqual(report["errors"], [])
        self.assertEqual(report["candidate_generation"]["negative_targets"], 1)
        self.assertEqual(
            candidate["attributes"][0]["candidate_assessment"],
            "object_unavailable",
        )

    def test_saved_association_view_skips_object_list_download(self):
        config = parse_config(
            {
                "transport": {"device": "/dev/null", "baudrate": 9600},
                "scan": {"common_catalogue": False},
            }
        )
        snapshot = {
            "saved_at": "2026-08-24T10:00:00Z",
            "objects": [
                {
                    "class_id": 15,
                    "logical_name": "0.0.40.0.0.255",
                    "object_version": 2,
                    "attributes": [
                        {"attribute_id": 2, "access_rights": {"read": True, "raw": 1}}
                    ],
                    "methods": [],
                },
                {
                    "class_id": 1,
                    "logical_name": "0.0.96.1.0.255",
                    "object_version": 0,
                    "attributes": [
                        {"attribute_id": 2, "access_rights": {"read": True, "raw": 1}}
                    ],
                    "methods": [],
                },
            ],
        }
        module = types.ModuleType("dlms_enum.gurux_adapter")
        module.GuruxSession = ReusedViewSession
        ReusedViewSession.read_objects = []
        previous = sys.modules.get("dlms_enum.gurux_adapter")
        sys.modules["dlms_enum.gurux_adapter"] = module
        try:
            report = scan_public(
                config,
                object(),
                association_view_mode="reuse",
                association_view_snapshot=snapshot,
            )
        finally:
            if previous is None:
                sys.modules.pop("dlms_enum.gurux_adapter", None)
            else:
                sys.modules["dlms_enum.gurux_adapter"] = previous

        profile = report["profiles"][0]
        self.assertEqual(profile["association_view_attempt_count"], 0)
        self.assertEqual(profile["association_view_source"], "saved_snapshot")
        self.assertNotIn(
            (15, "0.0.40.0.0.255", 2), ReusedViewSession.read_objects
        )
        association_object = next(
            item for item in profile["objects"] if item["class_id"] == 15
        )
        association_attribute = association_object["attributes"][0]
        self.assertEqual(association_attribute["outcome"], "NOT_TESTED")

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
        self.assertEqual(summary["get_success"], 1)
        self.assertEqual(summary["get_failed"], 0)
        self.assertEqual(summary["get_transmissions"], 2)
        self.assertEqual(FakeSession.read_attempts, [(2, 1), (2, 2)])
        self.assertEqual(report["transport"]["selected_server_address"], 1)
        self.assertEqual(report["transport"]["server_address_size"], 1)
        self.assertEqual(
            report["transport"]["server_addressing_type"], "1-byte addressing"
        )
        attributes = report["profiles"][0]["objects"][0]["attributes"]
        self.assertEqual([item["attribute_id"] for item in attributes], [2])
        value_attribute = attributes[0]
        self.assertEqual(value_attribute["attempt_count"], 2)
        self.assertEqual(value_attribute["outcome"], "SUCCESS")
        self.assertEqual(
            report["profiles"][0]["objects"][0]["logical_name"],
            FakeObject.logicalName,
        )
        self.assertFalse(
            any(
                row.get("attribute_id") == 1
                for row in report["capability_matrix"]
                if row["operation"] in {"GET", "SET"}
            )
        )

    def test_retries_are_suppressed_after_consecutive_timeouts(self):
        config = parse_config(
            {
                "transport": {
                    "device": "/dev/null",
                    "baudrate": 9600,
                    "inter_request_delay_ms": 0,
                },
                "scan": {"common_catalogue": False},
            }
        )
        module = types.ModuleType("dlms_enum.gurux_adapter")
        module.GuruxSession = TimeoutSession
        TimeoutSession.read_attempts = []

        with patch.dict(sys.modules, {"dlms_enum.gurux_adapter": module}):
            report = scan_public(config, object())

        profile = report["profiles"][0]
        self.assertEqual(profile["summary"]["get_attempted"], 2)
        self.assertEqual(profile["summary"]["get_transmissions"], 3)
        self.assertEqual([item[2] for item in TimeoutSession.read_attempts], [1, 2, 1])
        attributes = [
            attribute
            for obj in profile["objects"]
            for attribute in obj["attributes"]
        ]
        self.assertFalse(attributes[0]["retry_suppressed"])
        self.assertTrue(all(item["retry_suppressed"] for item in attributes[1:]))

    def test_timeout_circuit_reconnects_once_then_marks_remainder_inconclusive(self):
        config = parse_config(
            {
                "transport": {
                    "device": "/dev/null",
                    "baudrate": 9600,
                    "response_timeout_ms": 3000,
                    "inter_request_delay_ms": 0,
                },
                "scan": {
                    "common_catalogue": False,
                    "enumeration_timeout_ms": 800,
                    "timeout_breaker_threshold": 4,
                },
            }
        )
        module = types.ModuleType("dlms_enum.gurux_adapter")
        module.GuruxSession = CircuitBreakerSession
        CircuitBreakerSession.read_attempts = []
        CircuitBreakerSession.timeout_changes = []
        CircuitBreakerSession.reconnects = 0
        events = []

        with patch.dict(sys.modules, {"dlms_enum.gurux_adapter": module}):
            report = scan_public(config, object(), progress=events.append)

        profile = report["profiles"][0]
        policy = profile["scan_scope"]["timeout_policy"]
        self.assertEqual(profile["summary"]["get_success"], 1)
        self.assertEqual(profile["summary"]["get_failed"], 3)
        self.assertEqual(profile["summary"]["get_inconclusive"], 4)
        self.assertEqual(profile["summary"]["get_transmissions"], 7)
        self.assertEqual(CircuitBreakerSession.reconnects, 1)
        self.assertEqual(CircuitBreakerSession.timeout_changes, [800, 3000, 800])
        self.assertEqual(policy["trips"], 1)
        self.assertEqual(policy["health_check_transmissions"], 2)
        self.assertEqual(policy["reconnect_attempts"], 1)
        self.assertEqual(policy["successful_reconnects"], 1)
        self.assertTrue(policy["stopped"])
        self.assertEqual(
            policy["last_health_probe"]["logical_name"], "1.0.1.8.0.255"
        )
        outcomes = [
            attribute["outcome"]
            for obj in profile["objects"]
            for attribute in obj["attributes"]
            if attribute["attribute_id"] == 2
        ]
        self.assertEqual(
            outcomes,
            ["SUCCESS", "TIMEOUT", "TIMEOUT", "TIMEOUT"]
            + ["INCONCLUSIVE"] * 4,
        )
        inconclusive_rows = [
            row
            for row in report["capability_matrix"]
            if row["operation"] == "GET"
            and row["profiles"]["public"]["status"] == "INCONCLUSIVE"
        ]
        self.assertEqual(len(inconclusive_rows), 4)
        self.assertTrue(
            all(not row["profiles"]["public"]["tested"] for row in inconclusive_rows)
        )
        self.assertEqual(
            sum(event["phase"] == "timeout_reconnect" for event in events), 1
        )
        self.assertEqual(
            sum(event["phase"] == "timeout_circuit_stopped" for event in events),
            1,
        )

    def test_successful_health_check_resets_breaker_and_resumes(self):
        config = parse_config(
            {
                "transport": {
                    "device": "/dev/null",
                    "baudrate": 9600,
                    "inter_request_delay_ms": 0,
                },
                "scan": {
                    "common_catalogue": False,
                    "timeout_breaker_threshold": 4,
                },
            }
        )
        module = types.ModuleType("dlms_enum.gurux_adapter")
        module.GuruxSession = RecoveringCircuitSession
        RecoveringCircuitSession.read_attempts = []
        RecoveringCircuitSession.timeout_changes = []
        RecoveringCircuitSession.reconnects = 0

        with patch.dict(sys.modules, {"dlms_enum.gurux_adapter": module}):
            report = scan_public(config, object())

        profile = report["profiles"][0]
        policy = profile["scan_scope"]["timeout_policy"]
        self.assertEqual(profile["summary"]["get_success"], 3)
        self.assertEqual(profile["summary"]["get_failed"], 3)
        self.assertEqual(profile["summary"]["get_inconclusive"], 0)
        self.assertEqual(policy["trips"], 1)
        self.assertEqual(policy["recoveries_without_reconnect"], 1)
        self.assertEqual(policy["reconnect_attempts"], 0)
        self.assertFalse(policy["stopped"])

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
        self.assertEqual(WritableSession.read_attempts, [(2, 1)])
        self.assertEqual(attributes[0]["advertised_operations"], ["GET", "SET"])
        self.assertEqual(attributes[1]["advertised_operations"], ["SET"])
        self.assertEqual(attributes[1]["lifecycle"], "not_readable")
        self.assertFalse(attributes[1]["write_tested"])
        self.assertEqual(profile["summary"]["advertised_set_attributes"], 2)
        self.assertEqual(profile["summary"]["advertised_action_methods"], 1)
        operations = [item["operation"] for item in report["capability_matrix"]]
        self.assertEqual(operations.count("GET"), 1)
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
            report["transport"]["server_addressing_type"], "2-byte addressing"
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
        self.assertEqual(len(get_rows), 12)
        self.assertEqual(
            sum(
                row["profiles"]["public"]["status"] == "NOT_TESTED"
                for row in get_rows
            ),
            2,
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
        self.assertEqual(profile["summary"]["get_not_tested"], 7)
        self.assertEqual(profile["scan_scope"]["mapped_gets"], 12)
        self.assertNotIn("derived_gets", profile["scan_scope"])
        self.assertEqual(profile["scan_scope"]["testable_gets"], 12)
        self.assertEqual(profile["scan_scope"]["selected_gets"], 5)
        get_rows = [
            item for item in report["capability_matrix"] if item["operation"] == "GET"
        ]
        self.assertEqual(len(get_rows), 12)
        self.assertEqual(
            sum(row["profiles"]["public"]["tested"] for row in get_rows),
            5,
        )

    def test_get_limit_reserves_one_slot_for_an_event_log_buffer(self):
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
        module.GuruxSession = ProfilePrioritySession
        ProfilePrioritySession.read_objects = []

        with patch.dict(sys.modules, {"dlms_enum.gurux_adapter": module}):
            report = scan_public(config, object())

        profile = report["profiles"][0]
        self.assertEqual(len(ProfilePrioritySession.read_objects), 5)
        self.assertIn(
            ("0.0.99.98.0.255", 2), ProfilePrioritySession.read_objects
        )
        self.assertEqual(profile["summary"]["profile_buffers_read"], 1)
        self.assertEqual(profile["summary"]["profile_rows_read"], 1)
        self.assertEqual(
            profile["scan_scope"]["prioritized_profile_buffer"],
            {
                "class_id": 7,
                "logical_name": "0.0.99.98.0.255",
                "attribute_id": 2,
            },
        )

    def test_get_with_list_batches_in_attribute_order(self):
        config = parse_config(
            {
                "transport": {
                    "device": "/dev/null",
                    "baudrate": 9600,
                    "inter_request_delay_ms": 0,
                },
                "scan": {"common_catalogue": False, "batch_size": 10},
            }
        )
        module = types.ModuleType("dlms_enum.gurux_adapter")
        module.GuruxSession = BatchSession
        BatchSession.batches = []
        BatchSession.read_objects = []

        with patch.dict(sys.modules, {"dlms_enum.gurux_adapter": module}):
            report = scan_public(config, object())

        profile = report["profiles"][0]
        self.assertEqual([len(batch) for batch in BatchSession.batches], [5, 5, 2])
        self.assertEqual(
            [name for batch in BatchSession.batches for name, _ in batch],
            sorted(f"1.0.{index}.8.0.255" for index in range(1, 13)),
        )
        self.assertTrue(
            all(attribute_id == 2 for batch in BatchSession.batches for _, attribute_id in batch)
        )
        self.assertEqual(BatchSession.read_objects, [])
        self.assertEqual(profile["summary"]["get_attempted"], 12)
        self.assertEqual(profile["summary"]["get_transmissions"], 3)
        self.assertEqual(profile["summary"]["get_success"], 12)
        self.assertEqual(
            profile["scan_scope"]["get_with_list"]["successful_batches"], 3
        )
        self.assertEqual(
            profile["scan_scope"]["get_with_list"]["effective_batch_size"], 5
        )

    def test_failed_get_with_list_falls_back_to_individual_outcomes(self):
        config = parse_config(
            {
                "transport": {
                    "device": "/dev/null",
                    "baudrate": 9600,
                    "inter_request_delay_ms": 0,
                },
                "scan": {"common_catalogue": False, "batch_size": 5},
            }
        )
        module = types.ModuleType("dlms_enum.gurux_adapter")
        module.GuruxSession = FailingBatchSession
        FailingBatchSession.batches = []
        FailingBatchSession.read_objects = []

        with patch.dict(sys.modules, {"dlms_enum.gurux_adapter": module}):
            report = scan_public(config, object())

        profile = report["profiles"][0]
        self.assertEqual(len(FailingBatchSession.batches), 1)
        self.assertEqual(len(FailingBatchSession.read_objects), 2)
        self.assertEqual(profile["summary"]["get_success"], 2)
        self.assertEqual(profile["summary"]["get_failed"], 0)
        self.assertEqual(profile["summary"]["get_transmissions"], 3)
        self.assertEqual(
            profile["scan_scope"]["get_with_list"]["fallback_batches"], 1
        )


if __name__ == "__main__":
    unittest.main()
