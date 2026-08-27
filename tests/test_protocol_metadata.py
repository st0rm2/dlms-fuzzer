import unittest

from dlms_enum.gurux_adapter import association_view_selectors, protected_apdu_metadata
from dlms_enum.protocol_metadata import frame_xml_metadata, hdlc_frame_metadata


class ProtocolMetadataTests(unittest.TestCase):
    def test_association_and_invoke_metadata_are_structured(self):
        xml = """<HDLC><TargetAddress Value="10"/><SourceAddress Value="1"/>
        <AssociationResponse><ApplicationContextName Value="LN"/>
        <AssociationResult Value="00"/><ResultSourceDiagnostic>
        <ACSEServiceUser Value="00"/></ResultSourceDiagnostic>
        <InitiateResponse><NegotiatedDlmsVersionNumber Value="06"/>
        <NegotiatedConformance><ConformanceBit Name="Get"/></NegotiatedConformance>
        <NegotiatedMaxPduSize Value="04C8"/><VaaName Value="0007"/>
        </InitiateResponse></AssociationResponse><InvokeIdAndPriority Value="C1"/></HDLC>"""

        metadata = frame_xml_metadata(xml)

        self.assertEqual(metadata["target_address"], 16)
        self.assertEqual(metadata["association_result"], 0)
        self.assertEqual(metadata["negotiated_max_pdu_size"], 1224)
        self.assertEqual(metadata["negotiated_conformance"], ["Get"])
        self.assertEqual(metadata["invoke"]["invoke_id"], 1)
        self.assertEqual(metadata["invoke"]["priority"], "high")
        self.assertEqual(metadata["invoke"]["service_class"], "confirmed")

    def test_hdlc_metadata_includes_sequence_segmentation_and_fcs(self):
        frame = bytes.fromhex(
            "7EA02021037373988180140502008006020080070400000001080400000001CE6A7E"
        )

        metadata = hdlc_frame_metadata(frame)

        self.assertTrue(metadata["frame_complete"])
        self.assertTrue(metadata["fcs_valid"])
        self.assertFalse(metadata["segmented"])
        self.assertEqual(metadata["target_address"], 16)
        self.assertEqual(metadata["source_address"], 1)
        self.assertEqual(metadata["frame_class"], "unnumbered")

    def test_association_view_access_selectors_are_not_discarded(self):
        value = [
            [
                7,
                1,
                bytes((1, 0, 99, 1, 0, 255)),
                [
                    [[1, 1, None], [2, 1, [1, 2]]],
                    [[1, 1]],
                ],
            ]
        ]

        selectors = association_view_selectors(value)

        self.assertEqual(selectors[(7, "1.0.99.1.0.255")], {2: [1, 2]})

    def test_security_control_exposes_suite_and_protection_flags(self):
        content = b"\x31\x00\x00\x00\x2A\xAA" + bytes(12)
        frame = b"\x7E\xE6\xE6\x00\xC8" + bytes((len(content),)) + content + b"\x7E"

        metadata = protected_apdu_metadata(frame, outgoing=True)

        self.assertEqual(metadata["security_suite"], 1)
        self.assertTrue(metadata["authenticated"])
        self.assertTrue(metadata["encrypted"])
        self.assertEqual(metadata["key_scope"], "global")

    def test_general_ciphering_envelope_is_extracted(self):
        content = b"\x31\x00\x00\x00\x2A\xAA" + bytes(12)
        envelope = (
            b"\xDD"
            + b"\x08\x00\x00\x00\x00\x00\x00\x00\x2A"
            + b"\x08ORIGIN01"
            + b"\x08RECIP001"
            + b"\x00"
            + b"\x00"
            + b"\x03\x01\x01\x02"
            + bytes((len(content),))
            + content
        )
        frame = b"\x7E\xE6\xE6\x00" + envelope + b"\x7E"

        metadata = protected_apdu_metadata(frame, outgoing=True)

        self.assertEqual(metadata["transaction_id"], 42)
        self.assertEqual(metadata["originator_system_title"], b"ORIGIN01".hex().upper())
        self.assertEqual(metadata["recipient_system_title"], b"RECIP001".hex().upper())
        self.assertEqual(metadata["key_parameters"], 2)
        self.assertEqual(metadata["security_suite"], 1)


if __name__ == "__main__":
    unittest.main()
