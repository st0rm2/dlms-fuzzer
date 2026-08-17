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


class SecondSecureOnlyObject(FakeObject):
    logicalName = "1.0.99.2.0.255"
    description = "Second secure-only value"


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
    reuse_test_called = False
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

    def test_invocation_counter_reuse(self, progress=None):
        self.__class__.reuse_test_called = True
        self.events.append("counter_reuse_test")
        return {
            "enabled": True,
            "status": "reuse_not_observed",
            "requested_probes": 2,
            "attempted_probes": 2,
            "accepted_probes": 0,
            "association_restored": True,
            "probes": [],
        }

    def reconnect(self):
        self.events.append("secure_reconnect")
        return self.connect()

    def set_response_timeout(self, timeout_ms):
        self.events.append(f"secure_timeout:{timeout_ms}")

    def read_attribute(self, _target, _attribute_id, _attempt):
        return {"value": "secure", "dlms_data_type": "visible_string"}

    def create_object(self, _class_id, _logical_name):
        raise AssertionError("common catalogue disabled")

    def close(self):
        self.events.append("secure_close")
        return []


def secure_config(state_file, *, union_profile_test=False, get_limit=None):
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
                **({"get_limit": get_limit} if get_limit is not None else {}),
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
        SecureSession.reuse_test_called = False
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

    def test_opt_in_counter_reuse_test_runs_after_get_scan(self):
        with tempfile.TemporaryDirectory() as directory:
            config = secure_config(Path(directory) / "counters.json")
            module = types.ModuleType("dlms_enum.gurux_adapter")
            module.GuruxSession = BootstrapSession
            module.GuruxSecureSession = SecureSession
            with patch.dict(sys.modules, {"dlms_enum.gurux_adapter": module}):
                report = scan(
                    config,
                    object(),
                    invocation_counter_reuse_test=True,
                )

        reuse = report["profiles"][0]["association"][
            "invocation_counter_reuse_test"
        ]
        self.assertEqual(reuse["status"], "reuse_not_observed")
        self.assertTrue(SecureSession.reuse_test_called)
        self.assertGreater(
            BootstrapSession.events.index("counter_reuse_test"),
            BootstrapSession.events.index("secure_get_scan"),
        )

    def test_counter_reuse_test_runs_after_public_cross_profile_test(self):
        SecureSession.objects = [FakeObject(), SecureOnlyObject()]
        with tempfile.TemporaryDirectory() as directory:
            config = secure_config(
                Path(directory) / "counters.json",
                union_profile_test=True,
            )
            module = types.ModuleType("dlms_enum.gurux_adapter")
            module.GuruxSession = BootstrapSession
            module.GuruxSecureSession = SecureSession
            with patch.dict(sys.modules, {"dlms_enum.gurux_adapter": module}):
                report = scan(
                    config,
                    object(),
                    invocation_counter_reuse_test=True,
                )

        self.assertEqual(report["run"]["status"], "completed")
        public_get = next(
            index
            for index, event in enumerate(BootstrapSession.events)
            if event.startswith("public_get:")
        )
        reuse = BootstrapSession.events.index("counter_reuse_test")
        self.assertLess(public_get, reuse)
        self.assertIn("secure_reconnect", BootstrapSession.events[public_get:reuse])

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
        self.assertEqual(union_test["candidate_gets"], 1)
        self.assertEqual(union_test["unexpected_public_access"], 1)
        self.assertEqual(union_test["public_access_rejected"], 0)
        self.assertEqual(
            {
                (item["logical_name"], item["attribute_id"])
                for item in union_test["results"]
            },
            {
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
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["attribute_id"], 2)
        probed_rows = [
            row
            for row in rows
            if row["profiles"].get("public", {}).get("cross_profile_probe")
        ]
        self.assertEqual(len(probed_rows), 1)
        self.assertTrue(
            all(
                row["profiles"]["public"]["access_assessment"]
                == "UNEXPECTED_PUBLIC_ACCESS"
                for row in probed_rows
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
        self.assertEqual(union_test["public_access_rejected"], 1)
        self.assertEqual(union_test["inconclusive"], 0)
        self.assertEqual(report["errors"], [])
        self.assertTrue(
            all(
                item["access_assessment"] == "PUBLIC_ACCESS_REJECTED"
                for item in union_test["results"]
            )
        )

    def test_get_limit_also_caps_public_cross_profile_test(self):
        SecureSession.objects = [FakeObject(), SecureOnlyObject()]
        with tempfile.TemporaryDirectory() as directory:
            report = self._run(
                secure_config(
                    Path(directory) / "counters.json",
                    union_profile_test=True,
                    get_limit=1,
                )
            )

        union_test = report["public_union_test"]
        self.assertEqual(union_test["candidate_gets"], 1)
        self.assertEqual(union_test["selected_gets"], 1)
        self.assertEqual(union_test["attempted_gets"], 1)
        public_rows = [
            row["profiles"]["public"]
            for row in report["capability_matrix"]
            if row["operation"] == "GET"
            and row["logical_name"] == SecureOnlyObject.logicalName
            and "public" in row["profiles"]
        ]
        self.assertEqual(sum(item["tested"] for item in public_rows), 1)
        self.assertEqual(
            sum(item["status"] == "NOT_TESTED" for item in public_rows),
            0,
        )

    def test_public_cross_profile_retries_are_suppressed_after_timeouts(self):
        SecureSession.objects = [
            FakeObject(),
            SecureOnlyObject(),
            SecondSecureOnlyObject(),
        ]
        BootstrapSession.public_read_error = TimeoutError("meter did not reply")
        with tempfile.TemporaryDirectory() as directory:
            report = self._run(
                secure_config(
                    Path(directory) / "counters.json",
                    union_profile_test=True,
                )
            )

        union_test = report["public_union_test"]
        self.assertEqual(union_test["get_transmissions"], 3)
        self.assertEqual(
            [item["attempt_count"] for item in union_test["results"]],
            [2, 1],
        )
        self.assertEqual(
            [item["retry_suppressed"] for item in union_test["results"]],
            [False, True],
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
        self.assertEqual(union_test["candidate_gets"], 1)
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
