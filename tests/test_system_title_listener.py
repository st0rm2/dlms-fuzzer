import unittest
from unittest.mock import patch

from dlms_enum.cli import build_parser
from dlms_enum.config import parse_config
from dlms_enum.reporter import render_summary_report
from gurux_dlms import _GXFCS16
from dlms_enum.system_title_listener import (
    extract_hdlc_frames,
    listen_for_system_titles,
    system_title_observations,
)


def hdlc_frame(payload, *, target=16, source=1):
    body = bytearray(b"\xA0\x00")
    body.extend(((target << 1) | 1, (source << 1) | 1, 0x10))
    body.extend(b"\x00\x00")  # Header checksum is not needed by the parser.
    body.extend(b"\xE6\xE7\x00")
    body.extend(payload)
    body.extend(b"\x00\x00")
    frame_length = len(body)
    body[0] = 0xA0 | ((frame_length >> 8) & 0x07)
    body[1] = frame_length & 0xFF
    fcs = _GXFCS16.countFCS16(body, 0, len(body) - 2)
    body[-2:] = fcs.to_bytes(2, "big")
    return bytes((0x7E,)) + bytes(body) + bytes((0x7E,))


class FakeTraffic:
    def __init__(self):
        self.records = []

    def log(self, **record):
        self.records.append(record)


class FakeMedia:
    def __init__(self, chunk):
        self.chunk = chunk
        self.opened = False
        self.closed = False

    def open(self):
        self.opened = True

    def close(self):
        self.closed = True

    def receive(self, parameters):
        parameters.reply = self.chunk
        self.chunk = b""
        return bool(parameters.reply)


class SystemTitleListenerTests(unittest.TestCase):
    def test_main_scan_accepts_passive_listen_duration(self):
        args = build_parser().parse_args(
            ["scan", "--config", "meter.yaml", "--system-title-listen-seconds", "30"]
        )
        self.assertEqual(args.system_title_listen_seconds, 30)

    def test_extracts_server_title_from_aare(self):
        title = bytes.fromhex("49534B67754E41CB")
        responding_title = b"\xA4\x0A\x04\x08" + title
        payload = b"\x61" + bytes((len(responding_title),)) + responding_title
        frame = hdlc_frame(payload, target=16, source=1)

        observations = system_title_observations(frame, server_address=1)

        self.assertEqual(len(observations), 1)
        self.assertEqual(observations[0]["kind"], "server")
        self.assertEqual(observations[0]["hex"], "49534B67754E41CB")
        self.assertEqual(observations[0]["source"], "passive_aare")
        self.assertEqual(observations[0]["source_address"], 1)

    def test_general_glo_title_is_attributed_to_frame_sender(self):
        title = bytes.fromhex("4D45544552303031")
        frame = hdlc_frame(b"\xDB\x08" + title + b"\x01\x30", target=16, source=1)

        server = system_title_observations(frame, server_address=1)[0]
        client_frame = hdlc_frame(
            b"\xDB\x08" + title + b"\x01\x30", target=1, source=16
        )
        client = system_title_observations(client_frame, server_address=1)[0]

        self.assertEqual(server["kind"], "server")
        self.assertEqual(client["kind"], "client")
        self.assertEqual(server["source"], "passive_general_glo_ciphering")

    def test_rejects_non_eight_byte_general_glo_title(self):
        frame = hdlc_frame(b"\xDB\x07ABCDEFG\x01\x30")
        self.assertEqual(system_title_observations(frame, server_address=1), [])

    def test_rejects_frame_with_invalid_checksum(self):
        frame = bytearray(
            hdlc_frame(b"\xDB\x08METER001\x01\x30", target=16, source=1)
        )
        frame[-2] ^= 0x01
        self.assertEqual(system_title_observations(bytes(frame), server_address=1), [])

    def test_stream_parser_keeps_partial_frame_until_complete(self):
        first = hdlc_frame(b"\xDB\x08METER001\x01\x30")
        second = hdlc_frame(b"\x0F\x00")
        buffer = bytearray(b"noise" + first[:8])

        self.assertEqual(extract_hdlc_frames(buffer), [])
        buffer.extend(first[8:] + second)
        frames = extract_hdlc_frames(buffer)

        self.assertEqual(frames, [first, second])
        self.assertEqual(buffer, bytearray())

    def test_stream_parser_accepts_a_flag_shared_between_frames(self):
        first = hdlc_frame(b"\xDB\x08METER001\x01\x30")
        second = hdlc_frame(b"\x0F\x00")
        buffer = bytearray(first[:-1] + second)

        self.assertEqual(extract_hdlc_frames(buffer), [first, second])
        self.assertEqual(buffer, bytearray())

    def test_listener_records_receive_only_evidence(self):
        config = parse_config(
            {
                "version": 1,
                "transport": {"device": "/dev/fake", "baudrate": 9600},
                "profiles": [{"name": "public"}],
            }
        )
        frame = hdlc_frame(b"\xDB\x08METER001\x01\x30", target=16, source=1)
        unrelated_aarq = hdlc_frame(b"\x60\x08PASSWORD", target=1, source=16)
        media = FakeMedia(unrelated_aarq + frame)
        traffic = FakeTraffic()
        clock = iter((0.0, 0.0, 0.1, 1.1, 1.2))

        with patch(
            "dlms_enum.system_title_listener.time.monotonic",
            side_effect=lambda: next(clock),
        ):
            result = listen_for_system_titles(
                config,
                baudrate=9600,
                duration_seconds=1,
                traffic=traffic,
                server_address=1,
                media_factory=lambda: media,
            )

        self.assertEqual(result["status"], "completed")
        self.assertEqual(result["frames_seen"], 2)
        self.assertEqual(result["titles"][0]["hex"], "4D45544552303031")
        self.assertTrue(media.opened)
        self.assertTrue(media.closed)
        self.assertEqual(traffic.records[0]["tx_frames"], [])
        self.assertFalse(traffic.records[0]["tx_decoded"]["transmitted"])
        self.assertEqual(traffic.records[0]["rx_frames"], [frame])
        self.assertNotIn(b"PASSWORD", traffic.records[0]["rx_frames"][0])

    def test_role_summary_includes_passive_title_evidence(self):
        markdown = render_summary_report(
            {
                "run": {"id": "test", "status": "completed"},
                "transport": {},
                "profiles": [],
                "system_title_discovery": {
                    "enabled": True,
                    "status": "completed",
                    "frames_seen": 1,
                    "titles": [
                        {
                            "kind": "server",
                            "hex": "4D45544552303031",
                            "source": "passive_general_glo_ciphering",
                            "source_address": 1,
                            "target_address": 16,
                        }
                    ],
                },
            }
        )

        self.assertIn("## Passive system-title discovery", markdown)
        self.assertIn("`4D45544552303031`", markdown)


if __name__ == "__main__":
    unittest.main()
