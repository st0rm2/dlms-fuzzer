import unittest
from unittest.mock import patch

from dlms_enum.autodiscover import (
    DiscoveryOptions,
    discover_public_device,
    server_address_candidates,
    suggested_public_config,
)
from dlms_enum.config import parse_config


class Attribute:
    def __init__(self, index):
        self.index = index


class PublicObject:
    methodAttributes = []

    def __init__(
        self,
        class_id,
        logical_name,
        attribute_ids,
        *,
        version=0,
        description="",
    ):
        self.objectType = class_id
        self.logicalName = logical_name
        self.attributes = [Attribute(index) for index in attribute_ids]
        self.version = version
        self.description = description

    def getAccess(self, _index):
        return 1

    def getAttributeCount(self):
        return max(item.index for item in self.attributes)


class DiscoverySession:
    instances = []

    def __init__(self, _config, baudrate, _traffic, **kwargs):
        self.baudrate = baudrate
        self.kwargs = kwargs
        self._linked = False
        self.closed = False
        self.timeout = None
        self.__class__.instances.append(self)

    def connect(self):
        endpoint = (
            self.kwargs["server_logical_address"],
            self.kwargs["server_physical_address"],
            self.kwargs["server_address_size"],
        )
        if endpoint != (1, 17, 2):
            raise TimeoutError("no HDLC response")
        self._linked = True
        if self.kwargs["client_address"] == 16:
            raise RuntimeError("public association rejected for client 16")
        if self.kwargs["client_address"] != 1:
            raise RuntimeError("unexpected client")
        return {
            "dlms_version": 6,
            "max_receive_pdu_size": 1024,
            "negotiated_conformance": ["get", "selective_access"],
            "server_system_title": "49534B67754E41CB",
            "hdlc": {
                "max_info_tx": 128,
                "max_info_rx": 128,
                "window_size_tx": 1,
                "window_size_rx": 1,
            },
        }

    def set_response_timeout(self, timeout_ms):
        self.timeout = timeout_ms

    def discover_objects(self, _attempt):
        return [
            PublicObject(15, "0.0.40.0.0.255", (1, 2), version=2),
            PublicObject(
                1,
                "0.0.43.1.12.255",
                (1, 2),
                description="Invocation counter",
            ),
            PublicObject(1, "0.1.43.1.0.255", (1, 2)),
            PublicObject(1, "0.2.43.1.0.255", (1, 2)),
            PublicObject(1, "0.4.43.1.0.255", (1, 2)),
            PublicObject(1, "1.0.43.1.0.255", (1, 2)),
            PublicObject(64, "0.0.43.0.0.255", (1, 4, 5)),
        ]

    def read_meter_identity(self):
        return "ISK1030789014731"

    def create_object(self, class_id, logical_name):
        return PublicObject(class_id, logical_name, (1, 4, 5))

    def read_attribute(self, target, attribute_id, _attempt, **_kwargs):
        if int(target.objectType) == 1:
            return {"value": 129062, "dlms_data_type": "uint32"}
        if int(target.objectType) == 64 and attribute_id == 4:
            return {
                "value": {
                    "encoding": "octet-string",
                    "hex": "434C49454E543031",
                    "base64": "Q0xJRU5UMDE=",
                    "text": "CLIENT01",
                    "length": 8,
                }
            }
        if int(target.objectType) == 64 and attribute_id == 5:
            return {
                "value": {
                    "encoding": "octet-string",
                    "hex": "49534B67754E41CB",
                    "base64": "SVNLaHVOUcs=",
                    "text": None,
                    "length": 8,
                }
            }
        raise AssertionError("unexpected read")

    def close(self):
        self.closed = True
        return []


class FailedSession(DiscoverySession):
    def connect(self):
        raise TimeoutError("no response")


class GXDLMSException(Exception):
    pass


class DirectSystemTitleSession(DiscoverySession):
    def connect(self):
        association = super().connect()
        association["server_system_title"] = None
        return association

    def discover_objects(self, _attempt):
        return [PublicObject(15, "0.0.40.0.0.255", (1, 2), version=2)]

    def read_attribute(self, target, attribute_id, _attempt, **_kwargs):
        logical_name = str(target.logicalName)
        if int(target.objectType) != 64:
            raise AssertionError("unexpected read")
        if logical_name != "0.0.43.0.3.255":
            raise GXDLMSException("read-write denied")
        title = (
            "49534B67754E41CB" if attribute_id == 5 else "434C49454E543031"
        )
        return {
            "value": {
                "encoding": "octet-string",
                "hex": title,
                "base64": "",
                "text": None,
                "length": 8,
            }
        }


class AutoDiscoveryTests(unittest.TestCase):
    def setUp(self):
        DiscoverySession.instances = []
        FailedSession.instances = []
        DirectSystemTitleSession.instances = []

    def test_candidates_prioritize_observed_two_byte_server_145(self):
        candidates = server_address_candidates((1, 0), range(0, 32))
        identities = [
            (
                item["logical_address"],
                item["physical_address"],
                item["address_size"],
                item["server_address"],
            )
            for item in candidates
        ]
        self.assertIn((1, 17, 2, 145), identities)
        self.assertLess(identities.index((1, 17, 2, 145)), 3)
        self.assertEqual(len(identities), len(set(identities)))

    def test_link_response_triggers_fallback_client_and_metadata_inspection(self):
        options = DiscoveryOptions(
            device="/dev/fake",
            baudrates=(9600,),
            client_addresses=(16, 1, 4),
            logical_addresses=(1,),
            physical_addresses=(17,),
            inspection_timeout_ms=1700,
        )
        with patch("dlms_enum.autodiscover.validate_serial_device"):
            result = discover_public_device(
                options,
                object(),
                session_factory=DiscoverySession,
            )

        self.assertEqual(result["status"], "completed")
        self.assertEqual(result["probe_summary"]["attempts"], 2)
        self.assertEqual(result["connection"]["client_address"], 1)
        self.assertEqual(result["connection"]["server_address"], 145)
        self.assertEqual(result["connection"]["server_logical_address"], 1)
        self.assertEqual(result["connection"]["server_physical_address"], 17)
        self.assertEqual(result["connection"]["dlms_version"], 6)
        self.assertEqual(result["meter_identity"], "ISK1030789014731")
        self.assertEqual(
            result["invocation_counter_candidates"][0]["value"], 129062
        )
        self.assertFalse(
            result["invocation_counter_candidates"][0]["mapping_verified"]
        )
        self.assertEqual(
            [
                item["logical_name"]
                for item in result["invocation_counter_candidates"]
            ],
            [
                "0.0.43.1.12.255",
                "0.1.43.1.0.255",
                "0.2.43.1.0.255",
                "0.4.43.1.0.255",
            ],
        )
        titles = {(item["kind"], item["hex"]) for item in result["system_titles"]}
        self.assertIn(("server", "49534B67754E41CB"), titles)
        self.assertIn(("client", "434C49454E543031"), titles)
        self.assertTrue(all(item.closed for item in DiscoverySession.instances))
        self.assertEqual(DiscoverySession.instances[-1].timeout, 1700)

        config = suggested_public_config(result)
        self.assertEqual(config["transport"]["baudrate"], 9600)
        self.assertEqual(config["profiles"][0]["client_address"], 1)
        self.assertEqual(
            config["profiles"][0]["server"],
            {"logical_address": 1, "physical_address": 17},
        )
        self.assertEqual(config["profiles"][0]["hdlc"]["address_size"], 2)
        self.assertEqual(parse_config(config).profile.client_address, 1)

    def test_failed_bounded_sweep_returns_evidence_instead_of_guessing(self):
        options = DiscoveryOptions(
            device="/dev/fake",
            baudrates=(9600,),
            client_addresses=(16, 1),
            logical_addresses=(1,),
            physical_addresses=(1,),
        )
        with patch("dlms_enum.autodiscover.validate_serial_device"):
            result = discover_public_device(
                options,
                object(),
                session_factory=FailedSession,
            )

        self.assertEqual(result["status"], "failed")
        self.assertIsNone(suggested_public_config(result))
        self.assertGreater(result["probe_summary"]["attempts"], 0)
        self.assertEqual(result["probe_summary"]["hdlc_link_responses"], 0)
        # Secondary client SAPs are not sprayed across silent server addresses.
        self.assertTrue(
            all(
                item["client_address"] == 16 for item in result["attempts"]
            )
        )

    def test_direct_security_setup_probe_retrieves_unadvertised_server_title(self):
        options = DiscoveryOptions(
            device="/dev/fake",
            baudrates=(9600,),
            client_addresses=(1,),
            logical_addresses=(1,),
            physical_addresses=(17,),
            security_setup_instances=(0, 1, 2, 3),
        )
        with patch("dlms_enum.autodiscover.validate_serial_device"):
            result = discover_public_device(
                options,
                object(),
                session_factory=DirectSystemTitleSession,
            )

        self.assertEqual(result["status"], "completed")
        titles = {
            (item["kind"], item["hex"], item["source"])
            for item in result["system_titles"]
        }
        self.assertIn(
            ("server", "49534B67754E41CB", "direct_security_setup_probe"),
            titles,
        )
        self.assertIn(
            ("client", "434C49454E543031", "direct_security_setup_probe"),
            titles,
        )
        retrieval = result["system_title_retrieval"]
        self.assertEqual(retrieval["direct_probes_attempted"], 5)
        self.assertEqual(retrieval["direct_probe_stopped_reason"], None)
        self.assertEqual(result["errors"], [])
        rejected = [
            item
            for item in retrieval["probes"]
            if item["outcome"] == "DLMS_ERROR"
        ]
        self.assertEqual(len(rejected), 3)


if __name__ == "__main__":
    unittest.main()
