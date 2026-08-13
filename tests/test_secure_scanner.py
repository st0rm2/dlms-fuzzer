import sys
import tempfile
import types
import unittest
from pathlib import Path
from unittest.mock import patch

from dlms_enum.config import parse_config
from dlms_enum.scanner import scan


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

    def getAccess(self, _index):
        return 1

    def getAccess3(self, _index):
        return 1

    def getAttributeCount(self):
        return 2

    def getNames(self):
        return ("Logical name", "Value")


class SecureOnlyObject(FakeObject):
    logicalName = "1.0.99.1.0.255"
    description = "Secure-only value"


class PublicAuthenticatedObject(FakeObject):
    def getAccess(self, _index):
        return 4


class GXDLMSException(Exception):
    pass


class BootstrapSession:
    events = []
    public_read_error = None
    objects = [FakeObject()]

    def __init__(self, _config, _baudrate, _traffic, **kwargs):
        self.kwargs = kwargs

    def connect(self):
        self.events.append("public_connect")
        return {"authentication": "none"}

    def read_meter_identity(self):
        self.events.append("meter_identity")
        return "METER-BOOTSTRAP-ID"

    def read_invocation_counter(self, _profile):
        self.events.append("counter_read")
        return 100

    def discover_objects(self, _attempt):
        self.events.append("public_inventory")
        return self.objects

    def create_object(self, class_id, logical_name):
        target = FakeObject()
        target.objectType = class_id
        target.logicalName = logical_name
        return target

    def read_attribute(self, target, attribute_id, _attempt, **_kwargs):
        self.events.append(f"public_get:{target.logicalName}:{attribute_id}")
        if self.public_read_error is not None:
            raise self.public_read_error
        return {"value": "public", "dlms_data_type": "visible_string"}

    def close(self):
        self.events.append("public_close")
        return []


class SecureSession:
    events = BootstrapSession.events
    first_counter = None
    discover_called = False
    fail_hls = False
    objects = [FakeObject()]

    def __init__(
        self,
        _config,
        _baudrate,
        _traffic,
        lease,
        _gak,
        _guek,
        **_kwargs,
    ):
        self.__class__.first_counter = lease.next_counter
        self.client = types.SimpleNamespace(
            ciphering=types.SimpleNamespace(invocationCounter=lease.next_counter)
        )
        self.events.append("secure_created")

    def connect(self):
        self.events.append("secure_connect")
        if self.fail_hls:
            raise RuntimeError("HLS validation failed")
        return {"hls_validated": True, "security": "authentication_encryption"}

    def discover_objects(self, _attempt):
        self.__class__.discover_called = True
        self.events.append("secure_get_scan")
        return self.objects

    def read_attribute(self, _target, _attribute_id, _attempt):
        return {"value": "secure", "dlms_data_type": "visible_string"}

    def create_object(self, _class_id, _logical_name):
        raise AssertionError("common catalogue disabled")

    def close(self):
        self.events.append("secure_close")
        return []


def secure_config(state_file, *, union_profile_test=False):
    return parse_config(
        {
            "transport": {
                "device": "/dev/null",
                "baudrate": 9600,
                "inter_request_delay_ms": 0,
                "session_guard_ms": 0,
            },
            "scan": {
                "common_catalogue": False,
                "union_profile_test": union_profile_test,
            },
            "profiles": [
                {
                    "name": "hls_gmac_suite0",
                    "client_address": 1,
                    "client_system_title": "hex:434C49454E543031",
                    "secrets": {
                        "gak": {"inline": "00" * 16},
                        "guek": {"inline": "11" * 16},
                    },
                    "invocation_counter": {"state_file": str(state_file)},
                }
            ],
        }
    )


class SecureScannerTests(unittest.TestCase):
    def setUp(self):
        BootstrapSession.events = []
        SecureSession.events = BootstrapSession.events
        SecureSession.first_counter = None
        SecureSession.discover_called = False
        SecureSession.fail_hls = False
        SecureSession.objects = [FakeObject()]
        BootstrapSession.public_read_error = None
        BootstrapSession.objects = [FakeObject()]

    def _run(self, config):
        module = types.ModuleType("dlms_enum.gurux_adapter")
        module.GuruxSession = BootstrapSession
        module.GuruxSecureSession = SecureSession
        with patch.dict(sys.modules, {"dlms_enum.gurux_adapter": module}):
            return scan(config, object())

    def test_public_bootstrap_closes_before_first_secure_counter_and_hls_scan(self):
        with tempfile.TemporaryDirectory() as directory:
            report = self._run(secure_config(Path(directory) / "counters.json"))

        self.assertEqual(report["run"]["status"], "completed")
        self.assertEqual(report["profiles"][0]["name"], "hls_gmac_suite0")
        bootstrap = report["profiles"][0]["association"]["invocation_counter_bootstrap"]
        self.assertEqual(bootstrap["meter_reported_counter"], 100)
        self.assertEqual(bootstrap["first_secure_counter"], 101)
        self.assertTrue(bootstrap["strictly_greater_than_meter"])
        self.assertEqual(SecureSession.first_counter, 101)
        self.assertLess(
            BootstrapSession.events.index("public_close"),
            BootstrapSession.events.index("secure_created"),
        )
        self.assertTrue(SecureSession.discover_called)

    def test_hls_failure_prevents_all_get_scanning(self):
        SecureSession.fail_hls = True
        with tempfile.TemporaryDirectory() as directory:
            report = self._run(secure_config(Path(directory) / "counters.json"))

        self.assertEqual(report["run"]["status"], "failed")
        self.assertFalse(SecureSession.discover_called)
        self.assertNotIn("secure_get_scan", BootstrapSession.events)

    def test_secure_only_targets_are_retested_through_a_fresh_public_association(self):
        SecureSession.objects = [FakeObject(), SecureOnlyObject()]
        with tempfile.TemporaryDirectory() as directory:
            report = self._run(
                secure_config(
                    Path(directory) / "counters.json",
                    union_profile_test=True,
                )
            )

        union_test = report["public_union_test"]
        self.assertEqual(union_test["status"], "completed")
        self.assertEqual(union_test["candidate_gets"], 2)
        self.assertEqual(union_test["unexpected_public_access"], 2)
        self.assertEqual(union_test["public_access_rejected"], 0)
        self.assertEqual(
            {
                (item["logical_name"], item["attribute_id"])
                for item in union_test["results"]
            },
            {
                (SecureOnlyObject.logicalName, 1),
                (SecureOnlyObject.logicalName, 2),
            },
        )
        self.assertFalse(
            any(
                event.startswith(f"public_get:{FakeObject.logicalName}:")
                for event in BootstrapSession.events
            )
        )
        second_public_connect = len(BootstrapSession.events) - 1 - BootstrapSession.events[::-1].index(
            "public_connect"
        )
        self.assertLess(BootstrapSession.events.index("secure_close"), second_public_connect)

        rows = [
            row
            for row in report["capability_matrix"]
            if row["operation"] == "GET"
            and row["logical_name"] == SecureOnlyObject.logicalName
        ]
        self.assertEqual(len(rows), 2)
        self.assertTrue(all(row["profiles"]["public"]["cross_profile_probe"] for row in rows))
        self.assertTrue(
            all(
                row["profiles"]["public"]["access_assessment"]
                == "UNEXPECTED_PUBLIC_ACCESS"
                for row in rows
            )
        )

    def test_explicit_public_dlms_rejections_are_expected_results_not_scan_errors(self):
        SecureSession.objects = [FakeObject(), SecureOnlyObject()]
        BootstrapSession.public_read_error = GXDLMSException("read-write denied")
        with tempfile.TemporaryDirectory() as directory:
            report = self._run(
                secure_config(
                    Path(directory) / "counters.json",
                    union_profile_test=True,
                )
            )

        union_test = report["public_union_test"]
        self.assertEqual(report["run"]["status"], "completed")
        self.assertEqual(union_test["unexpected_public_access"], 0)
        self.assertEqual(union_test["public_access_rejected"], 2)
        self.assertEqual(union_test["inconclusive"], 0)
        self.assertEqual(report["errors"], [])
        self.assertTrue(
            all(
                item["access_assessment"] == "PUBLIC_ACCESS_REJECTED"
                for item in union_test["results"]
            )
        )

    def test_public_rights_requiring_authentication_are_still_probe_candidates(self):
        BootstrapSession.objects = [PublicAuthenticatedObject()]
        with tempfile.TemporaryDirectory() as directory:
            report = self._run(
                secure_config(
                    Path(directory) / "counters.json",
                    union_profile_test=True,
                )
            )

        union_test = report["public_union_test"]
        self.assertEqual(union_test["candidate_gets"], 2)
        self.assertTrue(
            all(
                item["public_advertised_access"] == "authenticated_read"
                for item in union_test["results"]
            )
        )
        self.assertTrue(
            all(item["public_object_advertised"] for item in union_test["results"])
        )


if __name__ == "__main__":
    unittest.main()
