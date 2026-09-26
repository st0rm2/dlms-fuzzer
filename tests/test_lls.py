import contextlib
import json
import sys
import tempfile
import types
import unittest
from pathlib import Path
from unittest.mock import patch

from gurux_dlms import GXReplyData
from gurux_dlms.enums import Authentication, Command

from dlms_enum.config import (
    ConfigError,
    LlsProfile,
    dump_config,
    parse_config,
    resolve_lls_password,
)
from dlms_enum.gurux_adapter import GuruxLlsSession
from dlms_enum.scanner import _authentication_enumeration, scan


class NullTraffic:
    def log(self, **_record):
        pass


class CapturingTraffic:
    def __init__(self):
        self.records = []

    def log(self, **record):
        self.records.append(record)


class Attribute:
    def __init__(self, index):
        self.index = index


class AssociationObject:
    objectType = 15
    logicalName = "0.0.40.0.1.255"
    version = 1
    description = "LLS association"
    attributes = [Attribute(2), Attribute(3), Attribute(6)]
    methodAttributes = []

    def getAccess(self, index):
        return 1 if index in (1, 2, 3, 6) else 0

    def getAccess3(self, index):
        return self.getAccess(index)

    def getAttributeCount(self):
        return 9

    def getNames(self):
        return (
            "Logical name",
            "Object list",
            "Associated partners id",
            "Application context name",
            "xDLMS context info",
            "Authentication mechanism name",
            "Secret",
            "Association status",
            "Security setup reference",
        )


class FakeLlsSession:
    created = 0

    def __init__(self, *_args, **_kwargs):
        self.__class__.created += 1

    def connect(self):
        return {
            "authentication": "low",
            "security": "none",
            "client_address": 32,
            "negotiated_conformance": ["get"],
            "max_receive_pdu_size": 1024,
        }

    def discover_objects(self, _attempt):
        return [AssociationObject()]

    def read_attribute(self, _target, attribute_id, _attempt):
        if attribute_id == 2:
            return {"value": {"association_object_count": 1}}
        if attribute_id == 3:
            return {"value": [32, 1]}
        if attribute_id == 6:
            return {
                "value": {"display": "0 0 0 5 8 2 1"},
                "raw_value": {"hex": "60857405080201"},
            }
        raise AssertionError(f"unexpected attribute {attribute_id}")

    def close(self):
        return []


def lls_mapping(password):
    return {
        "transport": {
            "device": "/dev/null",
            "baudrate": 9600,
            "inter_request_delay_ms": 0,
        },
        "scan": {"common_catalogue": False},
        "profiles": [
            {
                "name": "lls",
                "role": "meter_reader",
                "client_address": 32,
                "public_client_address": 16,
                "authentication": {
                    "mechanism": "low",
                    "password": password,
                },
                "security": {"policy": "none"},
                "server": {"logical_address": 1, "physical_address": 17},
                "hdlc": {"address_size": 2},
            }
        ],
    }


class LlsTests(unittest.TestCase):
    def test_inline_password_is_parsed_resolved_and_redacted(self):
        password = "reader-password"
        config = parse_config(lls_mapping({"inline": password}))

        self.assertIsInstance(config.profile, LlsProfile)
        self.assertEqual(resolve_lls_password(config.profile), password.encode())
        self.assertNotIn(password, repr(config))
        effective = json.dumps(config.redacted_dict())
        self.assertNotIn(password, effective)
        self.assertEqual(
            config.redacted_dict()["profiles"][0]["authentication"]["mechanism"],
            "low",
        )

    def test_environment_password_and_optional_hex_encoding(self):
        config = parse_config(lls_mapping({"env": "TEST_DLMS_LLS_PASSWORD"}))

        self.assertEqual(
            resolve_lls_password(
                config.profile,
                environ={"TEST_DLMS_LLS_PASSWORD": "hex:3030303030303030"},
            ),
            b"00000000",
        )
        with self.assertRaisesRegex(ConfigError, "environment variable is not set"):
            resolve_lls_password(config.profile, environ={})

    def test_lls_requires_one_yaml_or_environment_password_source(self):
        for password in ({}, {"file": "secret.txt"}, {"env": "A", "inline": "B"}):
            with self.subTest(password=password), self.assertRaises(ConfigError):
                parse_config(lls_mapping(password))

    def test_saved_inline_password_is_replaced_by_prompt_reference(self):
        password = "do-not-write-this"
        config = parse_config(lls_mapping(password))

        with tempfile.TemporaryDirectory() as directory:
            destination = Path(directory) / "lls.yaml"
            dump_config(config, destination)
            saved = destination.read_text(encoding="utf-8")

        self.assertNotIn(password, saved)
        self.assertIn("prompt: true", saved)

    def test_prompt_password_resolution_and_validation(self):
        config = parse_config(lls_mapping({"prompt": True}))
        self.assertEqual(resolve_lls_password(config.profile, prompt=lambda _: " secret "), b" secret ")
        for source in ({"prompt": False}, {"prompt": "true"}, {"prompt": True, "env": "KEY"}):
            with self.assertRaises(ConfigError):
                parse_config(lls_mapping(source))

    def test_gurux_lls_session_uses_low_authentication_and_resolved_password(self):
        config = parse_config(lls_mapping({"inline": "00000000"}))

        session = GuruxLlsSession(
            config,
            9600,
            NullTraffic(),
            server_logical_address=1,
            server_physical_address=17,
            server_address_size=2,
        )

        self.assertEqual(session.client.authentication, Authentication.LOW)
        self.assertEqual(bytes(session.client.password), b"00000000")
        self.assertEqual(session.authentication_name, "low")
        self.assertEqual(session.security_name, "none")
        aarq = b"".join(bytes(packet) for packet in session.client.aarqRequest())
        self.assertIn(b"00000000", aarq)

    def test_lls_aarq_raw_frame_is_not_written_to_traffic_log(self):
        config = parse_config(lls_mapping({"inline": "00000000"}))
        traffic = CapturingTraffic()
        session = object.__new__(GuruxLlsSession)
        session.authentication_name = "low"
        session.profile_name = "meter_reader"
        session.config = config
        session._response_timeout_ms = 1000
        session._endpoint_context = lambda: {}
        session._before_transmit = lambda *_args, **_kwargs: {"protected": False}
        session._after_transmit = lambda *_args, **_kwargs: None
        session._after_receive = lambda *_args, **_kwargs: {"protected": False}
        session._frame_xml = lambda _frame: {
            "xml": '<CallingAuthentication Value="00000000" />'
        }
        session.traffic = traffic

        def get_data(frame_data, reply, _notification):
            if frame_data.size == 0:
                return False
            reply.command = Command.AARE
            return True

        session.client = type("Client", (), {"getData": staticmethod(get_data)})()

        class Media:
            eop = 0x7E

            def getSynchronous(self):
                return contextlib.nullcontext()

            def send(self, _packet):
                pass

            def receive(self, parameters):
                parameters.reply = b"\x7E\x01\x7E"
                return True

        session.media = Media()
        session._exchange_packet(
            b"\x7Epassword-bearing-aarq\x7E",
            GXReplyData(),
            phase="lls_association",
            purpose="password_association",
            operation="AARQ",
            attempt=1,
        )

        self.assertEqual(traffic.records[0]["tx_frames"], [])
        self.assertTrue(
            traffic.records[0]["tx_decoded"][
                "credential_bearing_raw_frame_omitted"
            ]
        )

    def test_authentication_enumeration_maps_association_oid_and_partners(self):
        objects = [
            {
                "class_id": 15,
                "logical_name": "0.0.40.0.1.255",
                "attributes": [
                    {
                        "attribute_id": 3,
                        "outcome": "SUCCESS",
                        "decoded": {"value": [32, 1]},
                    },
                    {
                        "attribute_id": 6,
                        "outcome": "SUCCESS",
                        "decoded": {
                            "raw_value": {"hex": "60857405080201"},
                            "value": {"display": "0 0 0 5 8 2 1"},
                        },
                    },
                ],
            }
        ]

        result = _authentication_enumeration(
            objects, {"authentication": "low", "client_address": 32}
        )

        self.assertEqual(result["observed_methods"], ["low"])
        self.assertEqual(
            result["advertised_associations"],
            [
                {
                    "logical_name": "0.0.40.0.1.255",
                    "client_sap": 32,
                    "server_sap": 1,
                    "mechanism_id": 1,
                    "mechanism": "low",
                    "evidence": "association_ln_attribute_6",
                }
            ],
        )

    def test_scanner_selects_lls_session_and_reports_verified_method(self):
        config = parse_config(lls_mapping({"inline": "00000000"}))
        module = types.ModuleType("dlms_enum.gurux_adapter")
        module.GuruxSession = object
        module.GuruxLlsSession = FakeLlsSession
        FakeLlsSession.created = 0

        with (
            patch.dict(sys.modules, {"dlms_enum.gurux_adapter": module}),
            patch("dlms_enum.scanner.validate_serial_device"),
        ):
            report = scan(config, NullTraffic())

        self.assertEqual(report["run"]["status"], "completed")
        self.assertEqual(FakeLlsSession.created, 1)
        profile = report["profiles"][0]
        self.assertEqual(profile["association"]["authentication"], "low")
        self.assertEqual(
            profile["authentication_enumeration"]["observed_methods"], ["low"]
        )
        self.assertEqual(
            profile["authentication_enumeration"]["advertised_associations"][0][
                "client_sap"
            ],
            32,
        )


if __name__ == "__main__":
    unittest.main()
