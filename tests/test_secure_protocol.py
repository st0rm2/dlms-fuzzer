import contextlib
import json
import tempfile
import types
import unittest
from pathlib import Path

from gurux_dlms import GXReplyData
from gurux_dlms.enums import Command

from dlms_enum.config import parse_config
from dlms_enum.gurux_adapter import GuruxSecureSession, protected_apdu_metadata


ROOT = Path(__file__).resolve().parents[1]
GAK = bytes.fromhex("00112233445566778899AABBCCDDEEFF")
GUEK = bytes.fromhex("FFEEDDCCBBAA99887766554433221100")


def secure_config(**transport):
    values = {"device": "/dev/null", "baudrate": 9600, "inter_request_delay_ms": 0}
    values.update(transport)
    return parse_config(
        {
            "transport": values,
            "profiles": [
                {
                    "name": "hls_gmac_suite0",
                    "client_address": 1,
                    "client_system_title": "hex:434C49454E543031",
                    "secrets": {
                        "gak": {"inline": GAK.hex()},
                        "guek": {"inline": GUEK.hex()},
                    },
                }
            ],
        }
    )


class StubLease:
    def __init__(self, next_counter=101, events=None):
        self.next_counter = next_counter
        self.persisted = []
        self.events = events

    def persist_next(self, value):
        if self.events is not None:
            self.events.append(("persist", value))
        self.persisted.append(value)
        self.next_counter = value


class NullTraffic:
    def __init__(self):
        self.records = []

    def log(self, **record):
        self.records.append(record)


class SecureProtocolTests(unittest.TestCase):
    def test_real_gurux_get_generation_uses_c8_not_c0(self):
        lease = StubLease()
        session = GuruxSecureSession(
            secure_config(),
            9600,
            NullTraffic(),
            lease,
            GAK,
            GUEK,
            server_logical_address=0,
            server_physical_address=1,
            server_address_size=1,
        )
        target = session.create_object(1, "0.0.1.0.0.255")

        packet = bytes(session.client.read(target, 2)[0])
        metadata = protected_apdu_metadata(packet, outgoing=True)

        self.assertEqual(metadata["protected_command"], "glo-get-request")
        self.assertEqual(metadata["protected_command_code"], 0xC8)
        self.assertNotIn(b"\xE6\xE6\x00\xC0", packet)

        plaintext = b"\x7E\xE6\xE6\x00\xC0\x01\x7E"
        with self.assertRaisesRegex(RuntimeError, "refusing plaintext"):
            session._before_transmit(
                plaintext, operation="GET", purpose="object_attribute_read"
            )

    def test_retry_generation_consumes_and_persists_a_new_counter(self):
        lease = StubLease()
        session = GuruxSecureSession(
            secure_config(),
            9600,
            NullTraffic(),
            lease,
            GAK,
            GUEK,
            server_logical_address=0,
            server_physical_address=1,
            server_address_size=1,
        )
        target = session.create_object(1, "0.0.1.0.0.255")
        used = []
        for _attempt in (1, 2):
            packet = bytes(session.client.read(target, 2)[0])
            used.append(protected_apdu_metadata(packet, outgoing=True)["invocation_counter"])
            session._before_transmit(packet, operation="GET", purpose="object_attribute_read")

        self.assertEqual(used, [101, 102])
        self.assertEqual(lease.persisted, [102, 103])

    def test_counter_is_persisted_before_media_send_and_cc_is_decoded(self):
        events = []
        lease = StubLease(next_counter=12, events=events)
        traffic = NullTraffic()
        session = object.__new__(GuruxSecureSession)
        session.config = secure_config(response_timeout_ms=25)
        session.profile_name = "hls_gmac_suite0"
        session.counter_lease = lease
        session.traffic = traffic
        session.client = types.SimpleNamespace(
            ciphering=types.SimpleNamespace(
                invocationCounter=12,
                systemTitle=bytearray(b"CLIENT01"),
            )
        )
        session._endpoint_context = lambda: {}

        response = b"\x7E\xE6\xE7\x00\xCC\x1E\x30\x00\x00\x00\x33\x7E"

        def get_data(frame_data, reply, notification):
            if frame_data.size == 0:
                return False
            reply.command = Command.GET_RESPONSE
            reply.value = 42
            return True

        session.client.getData = get_data

        class Media:
            eop = 0x7E

            def getSynchronous(self):
                return contextlib.nullcontext()

            def send(self, _packet):
                events.append(("send", None))

            def receive(self, parameters):
                parameters.reply = response
                return True

        session.media = Media()
        request = b"\x7E\xE6\xE6\x00\xC8\x1E\x30\x00\x00\x00\x0B\x7E"
        reply = GXReplyData()

        session._exchange_packet(
            request,
            reply,
            phase="get_scan",
            purpose="object_attribute_read",
            operation="GET",
            attempt=1,
        )

        self.assertEqual(events[:2], [("persist", 12), ("send", None)])
        self.assertEqual(traffic.records[0]["profile"], "hls_gmac_suite0")
        self.assertEqual(
            traffic.records[0]["rx_decoded"]["protected_command"], "glo-get-response"
        )
        self.assertEqual(traffic.records[0]["rx_decoded"]["value"], 42)

    def _hls_harness(self, *, fail_validation=False):
        events = []
        session = object.__new__(GuruxSecureSession)
        session._open = False
        session._linked = False
        session._associated = False

        class Media:
            def open(self):
                events.append("OPEN")

        class Client:
            isAuthenticationRequired = False
            settings = types.SimpleNamespace(sourceSystemTitle=b"SERVER01")

            def snrmRequest(self):
                return None

            def aarqRequest(self):
                return [b"AARQ"]

            def parseAareResponse(self, _data):
                events.append("AARE_PARSED")
                self.isAuthenticationRequired = True

            def getApplicationAssociationRequest(self):
                events.append("HLS_GENERATED")
                return [b"HLS"]

            def parseApplicationAssociationResponse(self, _data):
                events.append("HLS_VALIDATED")
                if fail_validation:
                    raise ValueError("challenge bytes that must not escape")

        session.media = Media()
        session.client = Client()

        def read_blocks(_packets, reply, *, operation, **_kwargs):
            events.append(operation)
            if operation == "HLS_ACTION":
                self.assertFalse(session._associated, "AARE alone marked HLS associated")
            reply.data.clear()

        session._read_blocks = read_blocks
        session.association_details = lambda: {"hls_validated": session._associated}
        return session, events

    def test_aare_alone_does_not_associate_and_hls_action_is_validated(self):
        session, events = self._hls_harness()

        details = GuruxSecureSession.connect(session)

        self.assertTrue(session._associated)
        self.assertTrue(details["hls_validated"])
        self.assertEqual(events[-3:], ["HLS_GENERATED", "HLS_ACTION", "HLS_VALIDATED"])

    def test_hls_failure_prevents_get_scanning_and_sanitizes_failure(self):
        session, events = self._hls_harness(fail_validation=True)

        with self.assertRaisesRegex(RuntimeError, "HLS-GMAC server response validation failed") as raised:
            GuruxSecureSession.connect(session)

        self.assertFalse(session._associated)
        self.assertNotIn("challenge bytes", str(raised.exception))
        self.assertFalse(any(item == "GET" for item in events))

    def test_cleanup_orders_release_response_before_disconnect_and_close(self):
        events = []
        session = object.__new__(GuruxSecureSession)
        session.config = secure_config(session_guard_ms=0)
        session._open = True
        session._linked = True
        session._associated = True
        session.client = types.SimpleNamespace(
            releaseRequest=lambda: [b"release"],
            disconnectRequest=lambda: b"disconnect",
        )

        def read_blocks(_packets, _reply, *, operation, **_kwargs):
            events.extend([operation, "RLRE"])

        def exchange(_packet, _reply, *, operation, **_kwargs):
            events.extend([operation, "UA"])

        session._read_blocks = read_blocks
        session._exchange_packet = exchange
        session.media = types.SimpleNamespace(
            resetSynchronousBuffer=lambda: events.append("RESET"),
            close=lambda: events.append("CLOSE"),
        )

        warnings = session.close()

        self.assertEqual(warnings, [])
        self.assertEqual(events, ["RLRQ", "RLRE", "DISC", "UA", "RESET", "CLOSE"])

    def test_supplied_capture_structure_has_counter_and_ciphered_get_invariants(self):
        fixture = json.loads(
            (ROOT / "tests" / "fixtures" / "capture_structure.json").read_text(encoding="utf-8")
        )
        positive = fixture["positive_secure_reference"]
        secure = positive["secure"]
        self.assertGreater(secure["ciphered_aarq_counter"], positive["public_bootstrap"]["meter_counter"])
        self.assertEqual(secure["first_get_counter"], secure["hls_outer_counter"] + 1)
        self.assertEqual(secure["get_request_command"], "C8")
        self.assertEqual(secure["get_response_command"], "CC")
        negative = fixture["negative_plaintext_reference"]
        self.assertEqual(negative["plaintext_get_command"], "C0")
        self.assertEqual(negative["exception_response_command"], "D8")

        capture = ROOT / "runs" / "2026-08-10T124737Z" / "log_encrypted_worked.txt"
        if capture.exists():
            lines = capture.read_text(encoding="utf-8").splitlines()
            aarq = bytes.fromhex(lines[secure["ciphered_aarq_line"] - 1].split(":", 1)[1].strip())
            first_get = bytes.fromhex(lines[secure["first_get_line"] - 1].split(":", 1)[1].strip())
            first_response = bytes.fromhex(lines[secure["first_get_line"]].split(":", 1)[1].strip())
            self.assertEqual(protected_apdu_metadata(aarq, outgoing=True)["invocation_counter"], secure["ciphered_aarq_counter"])
            self.assertEqual(protected_apdu_metadata(first_get, outgoing=True)["protected_command"], "glo-get-request")
            self.assertEqual(protected_apdu_metadata(first_response, outgoing=False)["protected_command"], "glo-get-response")


if __name__ == "__main__":
    unittest.main()
