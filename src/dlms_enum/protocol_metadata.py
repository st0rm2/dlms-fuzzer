"""Small, loss-aware extractors for metadata already present in DLMS frames."""

from __future__ import annotations

import re
import xml.etree.ElementTree as ET
from typing import Any

from gurux_dlms import _GXFCS16


_SIMPLE_TAGS = {
    "TargetAddress": "target_address",
    "SourceAddress": "source_address",
    "FrameType": "frame_type",
    "ApplicationContextName": "application_context",
    "AssociationResult": "association_result",
    "ProtocolVersion": "acse_protocol_version",
    "ProposedDlmsVersionNumber": "proposed_dlms_version",
    "NegotiatedDlmsVersionNumber": "negotiated_dlms_version",
    "ProposedMaxPduSize": "proposed_max_pdu_size",
    "NegotiatedMaxPduSize": "negotiated_max_pdu_size",
    "VaaName": "vaa_name",
    "ProposedQualityOfService": "proposed_quality_of_service",
    "NegotiatedQualityOfService": "negotiated_quality_of_service",
    "LongInvokeIdAndPriority": "long_invoke_id_and_priority",
    "BlockNumber": "block_number",
    "BlockNumberAck": "block_number_ack",
    "LastBlock": "last_block",
    "WindowSize": "window_size",
    "AccessSelector": "access_selector",
    "DataAccessError": "data_access_error",
    "ActionResult": "action_result",
    "StateError": "state_error",
    "ServiceError": "service_error",
}


def _tag(element: ET.Element) -> str:
    return element.tag.rsplit("}", 1)[-1]


def _value(element: ET.Element) -> str | None:
    return element.attrib.get("Value") or (
        element.text.strip() if element.text and element.text.strip() else None
    )


def _hex_number(value: str | None) -> int | None:
    if value is None:
        return None
    candidate = value.strip()
    if not re.fullmatch(r"(?:0x)?[0-9A-Fa-f]+", candidate):
        return None
    try:
        return int(candidate.removeprefix("0x").removeprefix("0X"), 16)
    except ValueError:
        return None


def _invoke_metadata(value: str | None, *, long: bool = False) -> dict[str, Any]:
    raw = _hex_number(value)
    if raw is None:
        return {"raw": value}
    if long:
        return {
            "raw": f"0x{raw:08X}",
            "invoke_id": raw & 0x00FFFFFF,
            "priority": "high" if raw & 0x80000000 else "normal",
            "service_class": "confirmed" if raw & 0x40000000 else "unconfirmed",
        }
    return {
        "raw": f"0x{raw:02X}",
        "invoke_id": raw & 0x0F,
        "priority": "high" if raw & 0x80 else "normal",
        "service_class": "confirmed" if raw & 0x40 else "unconfirmed",
    }


def _xml_projection(element: ET.Element) -> Any:
    children = list(element)
    value = _value(element)
    if not children:
        number = _hex_number(value)
        return number if number is not None else value
    projected: dict[str, Any] = {}
    for child in children:
        key = _tag(child)
        item = _xml_projection(child)
        if key in projected:
            previous = projected[key]
            projected[key] = previous + [item] if isinstance(previous, list) else [previous, item]
        else:
            projected[key] = item
    return projected


def frame_xml_metadata(xml: str | None) -> dict[str, Any]:
    """Extract stable JSON fields from Gurux translator XML.

    The XML is still retained as canonical decoded evidence. This projection is
    intentionally small and makes common fields searchable without depending on
    an XML parser downstream.
    """

    if not xml:
        return {}
    try:
        root = ET.fromstring(xml)
    except ET.ParseError:
        return {"metadata_parse_error": "invalid_translator_xml"}

    result: dict[str, Any] = {}
    conformance: dict[str, list[str]] = {"proposed": [], "negotiated": []}
    for element in root.iter():
        name = _tag(element)
        value = _value(element)
        if name == "InvokeIdAndPriority":
            result["invoke"] = _invoke_metadata(value)
        elif name == "LongInvokeIdAndPriority":
            result["invoke"] = _invoke_metadata(value, long=True)
        elif name == "LastBlock":
            result["last_block"] = bool(_hex_number(value))
        elif name == "ConformanceBit":
            bit = element.attrib.get("Name")
            # ElementTree has no parent link. The complete XML contains at most
            # one conformance block per frame, so identify its enclosing form.
            parent_kind = None
            if "<NegotiatedConformance" in xml:
                parent_kind = "negotiated"
            elif "<ProposedConformance" in xml:
                parent_kind = "proposed"
            if bit and parent_kind:
                conformance[parent_kind].append(bit)
        elif name in {"ACSEServiceUser", "ACSEServiceProvider"}:
            result["result_source_diagnostic"] = {
                "source": "user" if name.endswith("User") else "provider",
                "code": _hex_number(value),
                "raw": value,
            }
        elif name in {"AccessSelection", "SelectiveAccessDescriptor"}:
            result["selective_access"] = _xml_projection(element)
        elif name in _SIMPLE_TAGS and value is not None:
            key = _SIMPLE_TAGS[name]
            number = _hex_number(value)
            result[key] = number if number is not None else value

    for kind, values in conformance.items():
        if values:
            result[f"{kind}_conformance"] = values
    return result


def _hdlc_address(frame: bytes, offset: int) -> tuple[int, int] | None:
    value = 0
    for index in range(offset, min(offset + 4, len(frame))):
        octet = frame[index]
        value = (value << 7) | (octet >> 1)
        if octet & 1:
            return value, index + 1
    return None


def hdlc_frame_metadata(frame: bytes) -> dict[str, Any]:
    """Extract link-layer addressing, sequencing, segmentation and FCS state."""

    if len(frame) < 9 or frame[0] != 0x7E or frame[1] & 0xF0 != 0xA0:
        return {}
    frame_length = ((frame[1] & 0x07) << 8) | frame[2]
    closing_flag = frame_length + 1
    complete = closing_flag < len(frame) and frame[closing_flag] == 0x7E
    target = _hdlc_address(frame, 3)
    source = _hdlc_address(frame, target[1]) if target else None
    control_offset = source[1] if source else None
    control = frame[control_offset] if control_offset is not None and control_offset < len(frame) else None
    metadata: dict[str, Any] = {
        "frame_length": frame_length,
        "frame_complete": complete,
        "segmented": bool(frame[1] & 0x08),
        "target_address": target[0] if target else None,
        "source_address": source[0] if source else None,
    }
    if complete:
        expected = _GXFCS16.countFCS16(frame, 1, frame_length - 2)
        observed = int.from_bytes(frame[closing_flag - 2 : closing_flag], "big")
        metadata["fcs_valid"] = expected == observed
    if control is None:
        return metadata
    metadata.update(
        {
            "control": f"0x{control:02X}",
            "poll_final": bool(control & 0x10),
        }
    )
    if control & 0x01 == 0:
        metadata.update(
            {
                "frame_class": "information",
                "send_sequence": (control >> 1) & 0x07,
                "receive_sequence": (control >> 5) & 0x07,
            }
        )
    elif control & 0x03 == 0x01:
        metadata.update(
            {
                "frame_class": "supervisory",
                "supervisory_function": {
                    0: "receive_ready",
                    1: "receive_not_ready",
                    2: "reject",
                    3: "selective_reject",
                }[(control >> 2) & 0x03],
                "receive_sequence": (control >> 5) & 0x07,
            }
        )
    else:
        metadata["frame_class"] = "unnumbered"
    return metadata
