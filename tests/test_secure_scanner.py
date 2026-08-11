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


class BootstrapSession:
    events = []

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

    def close(self):
        self.events.append("public_close")
        return []


class SecureSession:
    events = BootstrapSession.events
    first_counter = None
    discover_called = False
    fail_hls = False

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
        return [FakeObject()]

    def read_attribute(self, _target, _attribute_id, _attempt):
        return {"value": "secure", "dlms_data_type": "visible_string"}

    def create_object(self, _class_id, _logical_name):
        raise AssertionError("common catalogue disabled")

    def close(self):
        self.events.append("secure_close")
        return []


def secure_config(state_file):
    return parse_config(
        {
            "transport": {
                "device": "/dev/null",
                "baudrate": 9600,
                "inter_request_delay_ms": 0,
                "session_guard_ms": 0,
            },
            "scan": {"common_catalogue": False},
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


if __name__ == "__main__":
    unittest.main()
