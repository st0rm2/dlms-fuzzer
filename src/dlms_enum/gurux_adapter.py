"""Gurux-backed serial HDLC sessions for discovery and authentication scans."""

from __future__ import annotations

import contextlib
import io
import time
from collections.abc import Callable
from typing import Any

from gurux_common import ReceiveParameters, TimeoutException
from gurux_common.io import Parity, StopBits
from gurux_dlms import (
    GXByteBuffer,
    GXDLMSClient,
    GXDLMSException,
    GXDLMSTranslator,
    GXReplyData,
)
from gurux_dlms.enums import Authentication, Command, Conformance, InterfaceType, ObjectType, Security
from gurux_dlms.objects.enums import SecuritySuite
from gurux_dlms.secure.GXDLMSSecureClient import GXDLMSSecureClient
from gurux_serial import GXSerial

from .config import (
    AppConfig,
    LlsProfile,
    SERVER_ADDRESSING_TYPES,
    SecureProfile,
    resolve_lls_password,
)
from .counter_state import InvocationCounterLease
from .protocol_metadata import frame_xml_metadata, hdlc_frame_metadata
from .result_model import Outcome, classify_exception, enum_name, normalize_value
from .traffic_logger import TrafficLogger


_PROTECTED_COMMANDS = {
    int(Command.GLO_INITIATE_REQUEST): "glo-initiate-request",
    int(Command.GLO_INITIATE_RESPONSE): "glo-initiate-response",
    int(Command.GLO_GET_REQUEST): "glo-get-request",
    int(Command.GLO_GET_RESPONSE): "glo-get-response",
    int(Command.GLO_METHOD_REQUEST): "glo-action-request",
    int(Command.GLO_METHOD_RESPONSE): "glo-action-response",
    int(Command.GLO_SET_REQUEST): "glo-set-request",
    int(Command.GLO_SET_RESPONSE): "glo-set-response",
    int(Command.GLO_EVENT_NOTIFICATION): "glo-event-notification",
    int(Command.DED_GET_REQUEST): "ded-get-request",
    int(Command.DED_GET_RESPONSE): "ded-get-response",
    int(Command.DED_SET_REQUEST): "ded-set-request",
    int(Command.DED_SET_RESPONSE): "ded-set-response",
    int(Command.DED_METHOD_REQUEST): "ded-action-request",
    int(Command.DED_METHOD_RESPONSE): "ded-action-response",
    int(Command.GENERAL_GLO_CIPHERING): "general-glo-ciphering",
    int(Command.GENERAL_DED_CIPHERING): "general-ded-ciphering",
    int(Command.GENERAL_CIPHERING): "general-ciphering",
}
_COMMAND_VALUES = {int(item) for item in Command}


def _quiet_gurux(call: Any, *args: Any, **kwargs: Any) -> Any:
    """Call Gurux without its unconditional cipher-status stdout diagnostics."""

    with contextlib.redirect_stdout(io.StringIO()):
        return call(*args, **kwargs)


def _hdlc_information_end(frame: bytes) -> int:
    """Return the end of the HDLC information field when framing is complete."""

    if len(frame) < 4 or frame[0] != 0x7E or frame[1] & 0xF0 != 0xA0:
        return len(frame)
    frame_length = ((frame[1] & 0x07) << 8) | frame[2]
    closing_flag = frame_length + 1
    if closing_flag >= len(frame) or frame[closing_flag] != 0x7E:
        return len(frame)
    # The two octets immediately before the closing flag are the frame FCS.
    return closing_flag - 2


def _axdr_length(data: bytes, offset: int) -> tuple[int, int] | None:
    """Decode an A-XDR definite length and return (length, content offset)."""

    if offset >= len(data):
        return None
    first = data[offset]
    if first < 0x80:
        return first, offset + 1
    octet_count = first & 0x7F
    if octet_count == 0 or octet_count > 4 or offset + 1 + octet_count > len(data):
        return None
    start = offset + 1
    return int.from_bytes(data[start:start + octet_count], "big"), start + octet_count


def _security_control(value: int) -> bool:
    return value & 0x30 != 0 and value & 0x0F <= 2


def _protected_content(payload: bytes, command_offset: int) -> tuple[int, int] | None:
    decoded_length = _axdr_length(payload, command_offset + 1)
    if decoded_length is None:
        return None
    declared_length, content_offset = decoded_length
    if content_offset >= len(payload) or not _security_control(payload[content_offset]):
        return None
    return declared_length, content_offset


def _general_ciphering_content(
    payload: bytes, command_offset: int
) -> tuple[dict[str, Any], tuple[int, int] | None]:
    """Parse the clear envelope that precedes general-ciphering content."""

    offset = command_offset + 1
    metadata: dict[str, Any] = {}

    def take(label: str) -> bytes | None:
        nonlocal offset
        decoded = _axdr_length(payload, offset)
        if decoded is None:
            return None
        length, content_offset = decoded
        end = content_offset + length
        if end > len(payload):
            return None
        offset = end
        value = payload[content_offset:end]
        metadata[label] = value.hex().upper()
        return value

    transaction = take("transaction_id_hex")
    if transaction is None:
        return metadata, None
    metadata["transaction_id"] = int.from_bytes(transaction, "big")
    if take("originator_system_title") is None:
        return metadata, None
    if take("recipient_system_title") is None:
        return metadata, None
    if take("ciphering_datetime_hex") is None:
        return metadata, None
    if take("other_information_hex") is None:
        return metadata, None
    if offset + 4 > len(payload):
        return metadata, None
    metadata["key_info_length"] = payload[offset]
    metadata["agreed_key_choice"] = payload[offset + 1]
    metadata["key_parameters_length"] = payload[offset + 2]
    metadata["key_parameters"] = payload[offset + 3]
    offset += 4
    if metadata["key_parameters"] == 1:
        key_data = take("key_ciphered_data_hex")
        if key_data is None:
            return metadata, None
    content = _axdr_length(payload, offset)
    if content is None:
        return metadata, None
    declared_length, security_offset = content
    if security_offset >= len(payload) or not _security_control(payload[security_offset]):
        return metadata, None
    return metadata, (declared_length, security_offset)


def protected_apdu_metadata(frame: bytes, *, outgoing: bool) -> dict[str, Any]:
    """Describe a protected APDU and retain only its ciphered evidence bytes."""

    marker = b"\xE6\xE6\x00" if outgoing else b"\xE6\xE7\x00"
    offset = frame.find(marker)
    if offset < 0:
        return {"protected": False}
    information_end = _hdlc_information_end(frame)
    payload = frame[offset + len(marker):information_end]
    if not payload:
        return {"protected": False}
    indexes: list[tuple[int, int]] = []
    if payload[0] in _PROTECTED_COMMANDS:
        indexes.append((0, payload[0]))
    elif payload[0] in (int(Command.AARQ), int(Command.AARE), int(Command.RELEASE_REQUEST), int(Command.RELEASE_RESPONSE)):
        command = (
            int(Command.GLO_INITIATE_REQUEST)
            if payload[0] in (int(Command.AARQ), int(Command.RELEASE_REQUEST))
            else int(Command.GLO_INITIATE_RESPONSE)
        )
        search_from = 1
        while True:
            found = payload.find(bytes((command,)), search_from)
            if found < 0:
                break
            # Select the actual nested protected APDU, not a coincidental command
            # octet or BER length in an authentication value.
            if _protected_content(payload, found) is not None:
                indexes.append((found, command))
                break
            search_from = found + 1
    if not indexes:
        return {
            "protected": False,
            "outer_command": enum_name(Command(payload[0])) if payload[0] in _COMMAND_VALUES else f"0x{payload[0]:02X}",
            "outer_command_code": payload[0],
        }
    command_offset, command = indexes[0]
    general_sender_title = None
    general_metadata: dict[str, Any] = {}
    general_content: tuple[int, int] | None = None
    if command in {
        int(Command.GENERAL_GLO_CIPHERING),
        int(Command.GENERAL_DED_CIPHERING),
    }:
        title_length = _axdr_length(payload, command_offset + 1)
        if title_length is not None:
            length, title_offset = title_length
            general_sender_title = payload[title_offset : title_offset + length]
            content_command_offset = title_offset + length
            if content_command_offset < len(payload):
                indexes[0] = (content_command_offset - 1, command)
    command_offset, command = indexes[0]
    if command == int(Command.GENERAL_CIPHERING):
        general_metadata, general_content = _general_ciphering_content(
            payload, command_offset
        )
    protected_content = general_content or _protected_content(payload, command_offset)
    result: dict[str, Any] = {
        "protected": True,
        "protected_command": _PROTECTED_COMMANDS[command],
        "protected_command_code": command,
    }
    if general_sender_title:
        result["originator_system_title"] = general_sender_title.hex().upper()
    result.update(general_metadata)
    if protected_content is not None:
        declared_length, security_offset = protected_content
    else:
        # Preserve the earlier best-effort metadata behavior for malformed or
        # partial captures that still expose the Suite 0 security header.
        declared_length = 0
        security_offset = next(
            (
                index
                for index in range(command_offset + 1, min(len(payload), command_offset + 8))
                if _security_control(payload[index])
            ),
            -1,
        )

    if security_offset >= 0 and len(payload) >= security_offset + 5:
        control = payload[security_offset]
        result.update(
            {
                "security_control": f"0x{control:02X}",
                "security_suite": control & 0x0F,
                "authenticated": bool(control & 0x10),
                "encrypted": bool(control & 0x20),
                "broadcast_key": bool(control & 0x40),
                "compressed": bool(control & 0x80),
                "key_scope": (
                    "dedicated"
                    if command in {
                        int(Command.GENERAL_DED_CIPHERING),
                        int(Command.DED_GET_REQUEST),
                        int(Command.DED_GET_RESPONSE),
                        int(Command.DED_SET_REQUEST),
                        int(Command.DED_SET_RESPONSE),
                        int(Command.DED_METHOD_REQUEST),
                        int(Command.DED_METHOD_RESPONSE),
                    }
                    else "global"
                ),
            }
        )
        result["invocation_counter"] = int.from_bytes(
            payload[security_offset + 1:security_offset + 5], "big"
        )
        tag_length = 12 if control & 0x10 else 0
        if declared_length >= 5 + tag_length:
            captured_content = payload[
                security_offset:min(security_offset + declared_length, len(payload))
            ]
            ciphertext_length = declared_length - 5 - tag_length
            captured_ciphertext = captured_content[5:5 + ciphertext_length]
            tag_offset = 5 + ciphertext_length
            captured_tag = captured_content[tag_offset:tag_offset + tag_length]
            result.update(
                {
                    "protected_payload_declared_length": declared_length,
                    "protected_payload_captured_length": len(captured_content),
                    "protected_payload_complete": len(captured_content) == declared_length,
                    "ciphertext_hex": captured_ciphertext.hex().upper(),
                    "ciphertext_declared_length": ciphertext_length,
                    "ciphertext_captured_length": len(captured_ciphertext),
                    "ciphertext_complete": len(captured_ciphertext) == ciphertext_length,
                    "authentication_tag_hex": captured_tag.hex().upper(),
                    "authentication_tag_complete": len(captured_tag) == tag_length,
                }
            )
    return result


def _logical_name(value: Any) -> str | None:
    if isinstance(value, (bytes, bytearray, memoryview)) and len(value) == 6:
        return ".".join(str(item) for item in bytes(value))
    if isinstance(value, str) and value.count(".") == 5:
        return value
    return None


def _system_title_metadata(value: bytes | None) -> dict[str, Any] | None:
    if not value:
        return None
    raw = bytes(value)
    manufacturer = raw[:3]
    return {
        "hex": raw.hex().upper(),
        "length": len(raw),
        "valid_length": len(raw) == 8,
        "manufacturer_id": (
            manufacturer.decode("ascii") if len(raw) >= 3 and manufacturer.isalpha() else None
        ),
        "device_identifier_hex": raw[3:].hex().upper() if len(raw) > 3 else "",
    }


def association_view_selectors(value: Any) -> dict[tuple[int, str], dict[int, Any]]:
    """Return attribute access-selector lists from a raw Association View.

    Gurux Python currently applies the access mode while dropping the selector
    list. Extract it from the decoded object-list value before that happens.
    """

    found: dict[tuple[int, str], dict[int, Any]] = {}
    if not isinstance(value, (list, tuple)):
        return found
    for item in value:
        if not isinstance(item, (list, tuple)) or len(item) < 4:
            continue
        try:
            class_id = int(item[0])
        except (TypeError, ValueError):
            continue
        logical_name = _logical_name(item[2])
        rights = item[3]
        if logical_name is None or not isinstance(rights, (list, tuple)) or not rights:
            continue
        attributes = rights[0]
        if not isinstance(attributes, (list, tuple)):
            continue
        selectors: dict[int, Any] = {}
        for attribute in attributes:
            if not isinstance(attribute, (list, tuple)) or len(attribute) < 3:
                continue
            try:
                attribute_id = int(attribute[0])
            except (TypeError, ValueError):
                continue
            selector_list = normalize_value(attribute[2])
            if selector_list not in (None, []):
                selectors[attribute_id] = selector_list
        if selectors:
            found[(class_id, logical_name)] = selectors
    return found


class GuruxSession:
    """One unauthenticated logical-name association at one baud rate."""

    def __init__(
        self,
        config: AppConfig,
        baudrate: int,
        traffic: TrafficLogger,
        *,
        server_logical_address: int | None = None,
        server_physical_address: int | None = None,
        server_address_size: int = 0,
        client_address: int | None = None,
        profile_name: str | None = None,
    ):
        self.config = config
        self.baudrate = baudrate
        self.traffic = traffic
        profile = config.profile
        self.profile_name = profile_name or profile.role
        self.authentication_name = "none"
        self.security_name = "none"
        self.association_phase = "endpoint_discovery"
        self.association_purpose = "public_association"
        self.server_logical_address = (
            profile.server_logical_address
            if server_logical_address is None
            else server_logical_address
        )
        self.server_physical_address = (
            profile.server_physical_address
            if server_physical_address is None
            else server_physical_address
        )
        self.server_address_size = server_address_size
        server_address = GXDLMSClient.getServerAddress(
            self.server_logical_address,
            self.server_physical_address,
            server_address_size,
        )
        self.client = GXDLMSSecureClient(
            True,
            profile.client_address if client_address is None else client_address,
            server_address,
            Authentication.NONE,
            None,
            InterfaceType.HDLC,
        )
        if server_address_size:
            self.client.serverAddressSize = server_address_size
        self.client.maxReceivePDUSize = profile.proposed_max_pdu_size
        self.media = GXSerial(None)
        self.media.port = config.transport.device
        self.media.baudRate = baudrate
        self.media.dataBits = config.transport.serial.data_bits
        self.media.parity = {
            "none": Parity.NONE,
            "even": Parity.EVEN,
            "odd": Parity.ODD,
            "mark": Parity.MARK,
            "space": Parity.SPACE,
        }[config.transport.serial.parity]
        self.media.stopBits = {
            1.0: StopBits.ONE,
            1.5: StopBits.ONE_POINT_FIVE,
            2.0: StopBits.TWO,
        }[config.transport.serial.stop_bits]
        self._open = False
        self._linked = False
        self._associated = False
        self._response_timeout_ms = config.transport.response_timeout_ms
        self._association_protocol_metadata: dict[str, Any] = {}

    def set_response_timeout(self, timeout_ms: int) -> None:
        """Set the timeout used by subsequent exchanges in this session."""

        if timeout_ms <= 0:
            raise ValueError("response timeout must be positive")
        self._response_timeout_ms = int(timeout_ms)

    def _endpoint_context(self) -> dict[str, Any]:
        address_size = self.server_address_size or int(self.client.serverAddressSize)
        return {
            "baudrate": self.baudrate,
            "server_address": int(self.client.serverAddress),
            "server_logical_address": self.server_logical_address,
            "server_physical_address": self.server_physical_address,
            "server_address_size": address_size,
            "server_addressing_type": SERVER_ADDRESSING_TYPES.get(address_size, "unknown"),
        }

    @staticmethod
    def _bytes(value: Any) -> bytes:
        if value is None:
            return b""
        if isinstance(value, GXByteBuffer):
            return bytes(value.array())
        return bytes(value)

    @staticmethod
    def _frame_xml(frame: bytes) -> dict[str, Any]:
        if not frame:
            return {"xml": None}
        try:
            translator = GXDLMSTranslator()
            translator.comments = True
            translator.omitXmlDeclaration = True
            translator.omitXmlNameSpace = True
            # Some Gurux translation paths print cipher status directly. Keep
            # protocol translation out of terminal output and log only the
            # returned XML after the traffic logger applies challenge redaction.
            with contextlib.redirect_stdout(io.StringIO()):
                xml = translator.messageToXml(bytearray(frame))
            metadata = frame_xml_metadata(xml)
            metadata.update(hdlc_frame_metadata(frame))
            return {"xml": xml, "metadata": metadata}
        except Exception as exc:  # logging must never break a scan
            return {"decode_error": f"{type(exc).__name__}: {exc}"}

    @staticmethod
    def _reply_structure(reply: GXReplyData) -> dict[str, Any]:
        command = getattr(reply, "command", Command.NONE)
        error = int(getattr(reply, "error", 0) or 0)
        return {
            "command": enum_name(command) or str(int(command)),
            "command_code": int(command),
            "error_code": error,
            "data_type": enum_name(getattr(reply, "valueType", None)),
            "value": normalize_value(getattr(reply, "value", None)),
            "more_data": int(getattr(reply, "moreData", 0) or 0),
        }

    def _before_transmit(
        self, raw_tx: bytes, *, operation: str, purpose: str
    ) -> dict[str, Any]:
        return protected_apdu_metadata(raw_tx, outgoing=True)

    def _after_transmit(
        self,
        raw_tx: bytes,
        metadata: dict[str, Any],
        *,
        operation: str,
        purpose: str,
    ) -> None:
        """Observe a frame only after the media send call has succeeded."""

    def _after_receive(
        self, raw_rx: list[bytes], *, operation: str, purpose: str
    ) -> dict[str, Any]:
        combined = b"".join(raw_rx)
        metadata = protected_apdu_metadata(combined, outgoing=False)
        if metadata.get("protected"):
            return metadata
        for frame in raw_rx:
            metadata = protected_apdu_metadata(frame, outgoing=False)
            if metadata.get("protected"):
                return metadata
        return protected_apdu_metadata(raw_rx[0], outgoing=False) if raw_rx else {"protected": False}

    def _exchange_packet(
        self,
        packet: Any,
        reply: GXReplyData,
        *,
        phase: str,
        purpose: str,
        operation: str,
        attempt: int,
        object_context: dict[str, Any] | None = None,
        tx_context: dict[str, Any] | None = None,
    ) -> None:
        raw_tx = self._bytes(packet)
        raw_rx: list[bytes] = []
        started = time.monotonic()
        outcome = Outcome.SUCCESS
        caught: BaseException | None = None
        receive = ReceiveParameters()
        receive.eop = 0x7E
        receive.allData = True
        receive.waitTime = getattr(
            self, "_response_timeout_ms", self.config.transport.response_timeout_ms
        )
        receive.count = 5
        self.media.eop = receive.eop
        frame_data = GXByteBuffer()
        notification = GXReplyData()
        tx_protocol: dict[str, Any] = {}
        rx_protocol: dict[str, Any] = {}

        try:
            with self.media.getSynchronous():
                if raw_tx:
                    tx_protocol = self._before_transmit(
                        raw_tx, operation=operation, purpose=purpose
                    )
                    self.media.send(bytearray(raw_tx))
                    self._after_transmit(
                        raw_tx,
                        tx_protocol,
                        operation=operation,
                        purpose=purpose,
                    )
                while not _quiet_gurux(
                    self.client.getData, frame_data, reply, notification
                ):
                    if notification.data.size:
                        raise RuntimeError("unsolicited notification received during request")
                    if not self.media.receive(receive):
                        raise TimeoutException("no complete reply received from the meter")
                    received = self._bytes(receive.reply)
                    raw_rx.append(received)
                    frame_data.set(received)
                    receive.reply = None
            rx_protocol = self._after_receive(
                raw_rx, operation=operation, purpose=purpose
            )
            if reply.error:
                raise GXDLMSException(reply.error)
        except BaseException as exc:
            caught = exc
            outcome = classify_exception(exc)
        finally:
            tx_decoded = dict(tx_context or {})
            tx_decoded.update(tx_protocol)
            tx_protocol_frames = [self._frame_xml(raw_tx)] if raw_tx else []
            tx_decoded["protocol_frames"] = tx_protocol_frames
            rx_decoded = self._reply_structure(reply)
            rx_decoded.update(rx_protocol)
            rx_protocol_frames = [self._frame_xml(frame) for frame in raw_rx]
            rx_decoded["protocol_frames"] = rx_protocol_frames
            if operation == "AARQ":
                request_metadata = next(
                    (
                        item.get("metadata", {})
                        for item in tx_protocol_frames
                        if item.get("metadata")
                    ),
                    {},
                )
                response_metadata = next(
                    (
                        item.get("metadata", {})
                        for item in rx_protocol_frames
                        if item.get("metadata")
                    ),
                    {},
                )
                self._association_protocol_metadata = {
                    "request": request_metadata,
                    "response": response_metadata,
                }
            if caught is not None:
                rx_decoded["exception"] = {
                    "type": type(caught).__name__, "message": str(caught)
                }
            context = self._endpoint_context()
            context.update(object_context or {})
            logged_tx_frames = [raw_tx] if raw_tx else []
            logged_rx_frames = raw_rx
            if (
                self.config.output.redact_secrets
                and getattr(self, "authentication_name", None) == "low"
                and operation == "AARQ"
            ):
                # LLS carries the reusable password in the ACSE AARQ. Preserve
                # the redacted translator output and all response evidence, but
                # never serialize the credential-bearing raw request frame.
                logged_tx_frames = []
                tx_decoded["credential_bearing_raw_frame_omitted"] = True
            if (
                self.config.output.redact_secrets
                and operation == "GET"
                and int((object_context or {}).get("class_id", -1)) == 15
                and int((object_context or {}).get("attribute_id", -1)) == 7
            ):
                # A compliant meter should not expose the Association secret,
                # but a scanner must also be safe when a meter is misconfigured.
                logged_rx_frames = []
                rx_decoded["value"] = "<redacted>"
                rx_decoded["protocol_frames"] = [
                    {
                        "xml": "<redacted sensitive Association LN secret response>",
                        "metadata": item.get("metadata", {}),
                    }
                    for item in rx_protocol_frames
                ]
                rx_decoded["sensitive_raw_frame_omitted"] = True
            self.traffic.log(
                profile=self.profile_name,
                phase=phase,
                purpose=purpose,
                object_context=context,
                operation=operation,
                attempt=attempt,
                tx_frames=logged_tx_frames,
                tx_decoded=tx_decoded,
                rx_frames=logged_rx_frames,
                rx_decoded=rx_decoded,
                elapsed_ms=(time.monotonic() - started) * 1000,
                result=outcome.value,
            )
            if self.config.transport.inter_request_delay_ms:
                time.sleep(self.config.transport.inter_request_delay_ms / 1000)
        if caught is not None:
            raise caught

    def _read_blocks(
        self,
        packets: Any,
        reply: GXReplyData,
        *,
        phase: str,
        purpose: str,
        operation: str,
        attempt: int,
        object_context: dict[str, Any] | None = None,
        tx_context: dict[str, Any] | None = None,
    ) -> None:
        packet_list = packets if isinstance(packets, list) else [packets]
        for packet_number, packet in enumerate(packet_list, 1):
            reply.clear()
            context = dict(tx_context or {})
            context["request_fragment"] = packet_number
            self._exchange_packet(
                packet,
                reply,
                phase=phase,
                purpose=purpose,
                operation=operation,
                attempt=attempt,
                object_context=object_context,
                tx_context=context,
            )
        block_number = 0
        while reply.isMoreData():
            block_number += 1
            packet = (
                None
                if reply.isStreaming()
                else _quiet_gurux(self.client.receiverReady, reply)
            )
            context = dict(tx_context or {})
            context["continuation_block"] = block_number
            self._exchange_packet(
                packet,
                reply,
                phase=phase,
                purpose=purpose,
                operation=operation,
                attempt=attempt,
                object_context=object_context,
                tx_context=context,
            )

    def connect(self) -> dict[str, Any]:
        self.media.open()
        self._open = True
        reply = GXReplyData()
        snrm = _quiet_gurux(self.client.snrmRequest)
        if snrm:
            self._exchange_packet(
                snrm,
                reply,
                phase="endpoint_discovery",
                purpose="hdlc_link_setup",
                operation="SNRM",
                attempt=1,
                tx_context={"message": "set-normal-response-mode"},
            )
            _quiet_gurux(self.client.parseUAResponse, reply.data)
            self._linked = True

        reply.clear()
        self._read_blocks(
            _quiet_gurux(self.client.aarqRequest),
            reply,
            phase=self.association_phase,
            purpose=self.association_purpose,
            operation="AARQ",
            attempt=1,
            tx_context={
                "message": "application-association-request",
                "authentication": self.authentication_name,
                "referencing": "logical-name",
            },
        )
        _quiet_gurux(self.client.parseAareResponse, reply.data)
        self._associated = True
        return self.association_details()

    def association_details(self) -> dict[str, Any]:
        conformance = self.client.negotiatedConformance
        conformance_names = [
            item.name.lower()
            for item in Conformance
            if item != Conformance.NONE and conformance & item
        ]
        source_title = self.client.settings.sourceSystemTitle
        return {
            "profile": self.profile_name,
            "authentication": self.authentication_name,
            "security": self.security_name,
            "client_address": int(self.client.clientAddress),
            "server_address": int(self.client.serverAddress),
            "server_logical_address": self.server_logical_address,
            "server_physical_address": self.server_physical_address,
            "server_address_size": self.server_address_size or int(self.client.serverAddressSize),
            "server_addressing_type": self._endpoint_context()["server_addressing_type"],
            "dlms_version": int(self.client.settings.dlmsVersion),
            "max_receive_pdu_size": int(self.client.maxReceivePDUSize),
            "negotiated_conformance": conformance_names,
            "hdlc": {
                "max_info_tx": int(self.client.hdlcSettings.maxInfoTX),
                "max_info_rx": int(self.client.hdlcSettings.maxInfoRX),
                "window_size_tx": int(self.client.hdlcSettings.windowSizeTX),
                "window_size_rx": int(self.client.hdlcSettings.windowSizeRX),
            },
            "server_system_title": bytes(source_title).hex().upper() if source_title else None,
            "server_system_title_metadata": _system_title_metadata(source_title),
            "protocol_metadata": self._association_protocol_metadata,
        }

    def discover_objects(self, attempt: int) -> Any:
        reply = GXReplyData()
        self._read_blocks(
            _quiet_gurux(self.client.getObjectsRequest),
            reply,
            phase=f"{self.profile_name}_reconnaissance",
            purpose="association_view_scan",
            operation="GET",
            attempt=attempt,
            object_context={"class_id": 15, "logical_name": "0.0.40.0.0.255", "attribute_id": 2},
            tx_context={"service": "get-request", "attribute": "object-list"},
        )
        raw_selectors = association_view_selectors(reply.value)
        objects = _quiet_gurux(
            self.client.parseObjects,
            reply.data,
            onlyKnownObjects=False,
            ignoreInactiveObjects=False,
        )
        for target in objects:
            selectors = raw_selectors.get(
                (int(target.objectType), str(target.logicalName)), {}
            )
            setattr(target, "_dlms_access_selectors", selectors)
        return objects

    def create_object(self, class_id: int, logical_name: str) -> Any:
        try:
            target = self.client.createObject(ObjectType(class_id))
        except ValueError:
            target = self.client.createObject(class_id)
        target.logicalName = logical_name
        return target

    def read_attribute(
        self,
        target: Any,
        attribute_id: int,
        attempt: int,
        *,
        phase: str = "get_scan",
        purpose: str = "object_attribute_read",
    ) -> dict[str, Any]:
        context = {
            "class_id": int(target.objectType),
            "logical_name": str(target.logicalName),
            "object_version": int(getattr(target, "version", 0)),
            "attribute_id": attribute_id,
        }
        reply = GXReplyData()
        self._read_blocks(
            _quiet_gurux(self.client.read, target, attribute_id),
            reply,
            phase=phase,
            purpose=purpose,
            operation="GET",
            attempt=attempt,
            object_context=context,
            tx_context={"service": "get-request", "attribute_id": attribute_id},
        )
        raw_value = reply.value
        return self._decode_attribute_value(
            target,
            attribute_id,
            raw_value,
            dlms_data_type=enum_name(getattr(reply, "valueType", None)),
        )

    def _decode_attribute_value(
        self,
        target: Any,
        attribute_id: int,
        raw_value: Any,
        *,
        dlms_data_type: str | None,
    ) -> dict[str, Any]:
        class_decode_error = None
        try:
            decoded = _quiet_gurux(
                self.client.updateValue, target, attribute_id, raw_value
            )
        except (AttributeError, NotImplementedError, ValueError) as exc:
            # Unknown/new interface classes can still carry a completely valid
            # xDLMS value. Preserve Gurux's APDU-level decoding even when no
            # class-specific setter exists.
            decoded = raw_value
            class_decode_error = f"{type(exc).__name__}: {exc}"
        try:
            interface_data_type = enum_name(target.getDataType(attribute_id))
        except Exception:
            interface_data_type = None
        try:
            ui_data_type = enum_name(target.getUIDataType(attribute_id))
        except Exception:
            ui_data_type = None
        result = {
            "value": normalize_value(decoded),
            "raw_value": normalize_value(raw_value),
            "dlms_data_type": dlms_data_type,
            "interface_data_type": interface_data_type,
            "ui_data_type": ui_data_type,
        }
        if class_decode_error:
            result["class_decode_note"] = class_decode_error
        return result

    def read_attributes(
        self,
        requests: list[tuple[Any, int]],
        attempt: int,
    ) -> list[dict[str, Any]]:
        """Read an ordered list of attributes in one GET-with-list service."""

        if not 2 <= len(requests) <= 10:
            raise ValueError("GET-with-list requires from 2 to 10 attributes")
        generated = _quiet_gurux(self.client.readList, requests)
        if len(generated) != 1:
            raise RuntimeError("Gurux split one bounded GET list unexpectedly")
        packets = generated[0]
        reply = GXReplyData()
        targets = [
            {
                "class_id": int(target.objectType),
                "logical_name": str(target.logicalName),
                "object_version": int(getattr(target, "version", 0)),
                "attribute_id": attribute_id,
            }
            for target, attribute_id in requests
        ]
        self._read_blocks(
            packets,
            reply,
            phase="get_scan",
            purpose="object_attribute_list_read",
            operation="GET",
            attempt=attempt,
            object_context={"batch_size": len(requests), "targets": targets},
            tx_context={"service": "get-request-with-list", "targets": targets},
        )
        values = reply.value
        if not isinstance(values, list) or len(values) != len(requests):
            raise RuntimeError("GET-with-list response count does not match its request")
        results: list[dict[str, Any]] = []
        for (target, attribute_id), raw_value in zip(requests, values, strict=True):
            results.append(
                self._decode_attribute_value(
                    target,
                    attribute_id,
                    raw_value,
                    dlms_data_type=None,
                )
            )
        return results

    def read_bootstrap_value(
        self,
        class_id: int,
        logical_name: str,
        attribute_id: int,
        *,
        purpose: str,
    ) -> Any:
        target = self.create_object(class_id, logical_name)
        reply = GXReplyData()
        self._read_blocks(
            _quiet_gurux(self.client.read, target, attribute_id),
            reply,
            phase="invocation_counter_bootstrap",
            purpose=purpose,
            operation="GET",
            attempt=1,
            object_context={
                "class_id": class_id,
                "logical_name": logical_name,
                "attribute_id": attribute_id,
                "association_role": "public_bootstrap",
            },
            tx_context={"service": "get-request", "bootstrap": True},
        )
        value = reply.value
        try:
            return _quiet_gurux(
                self.client.updateValue, target, attribute_id, value
            )
        except (AttributeError, NotImplementedError, ValueError):
            return value

    def read_meter_identity(self) -> str:
        value = self.read_bootstrap_value(
            1, "0.0.42.0.0.255", 2, purpose="meter_identity_read"
        )
        if isinstance(value, (bytes, bytearray, memoryview)):
            raw = bytes(value)
            try:
                text = raw.decode("ascii")
                if text.isprintable():
                    return text
            except UnicodeDecodeError:
                pass
            return raw.hex().upper()
        return str(value)

    def read_invocation_counter(self, profile: SecureProfile) -> int:
        settings = profile.invocation_counter
        value = self.read_bootstrap_value(
            settings.class_id,
            settings.logical_name,
            settings.attribute_id,
            purpose="invocation_counter_read",
        )
        try:
            counter = int(value)
        except (TypeError, ValueError) as exc:
            raise ValueError("meter invocation-counter value is not an unsigned integer") from exc
        if not 0 <= counter <= 0xFFFFFFFF:
            raise ValueError("meter invocation-counter value is outside the uint32 range")
        return counter

    def close(self) -> list[str]:
        warnings: list[str] = []
        if not self._open:
            return warnings
        if self._associated:
            try:
                release = _quiet_gurux(self.client.releaseRequest)
                if release:
                    reply = GXReplyData()
                    self._read_blocks(
                        release,
                        reply,
                        phase="finalization",
                        purpose="association_release",
                        operation="RLRQ",
                        attempt=1,
                        tx_context={"message": "release-request"},
                    )
            except Exception as exc:
                warnings.append(f"association release failed: {type(exc).__name__}: {exc}")
            self._associated = False
        if self._linked:
            try:
                disconnect = _quiet_gurux(self.client.disconnectRequest)
                if disconnect:
                    reply = GXReplyData()
                    self._exchange_packet(
                        disconnect,
                        reply,
                        phase="finalization",
                        purpose="hdlc_disconnect",
                        operation="DISC",
                        attempt=1,
                        tx_context={"message": "disconnect-request"},
                    )
            except Exception as exc:
                warnings.append(f"HDLC disconnect failed: {type(exc).__name__}: {exc}")
            self._linked = False
        try:
            self.media.resetSynchronousBuffer()
            self.media.close()
        except Exception as exc:
            warnings.append(f"serial close failed: {type(exc).__name__}: {exc}")
        self._open = False
        if self.config.transport.session_guard_ms:
            time.sleep(self.config.transport.session_guard_ms / 1000)
        return warnings

    def reconnect(self) -> dict[str, Any]:
        """Drop a potentially wedged link and establish a fresh association."""

        try:
            self.media.resetSynchronousBuffer()
        except Exception:
            pass
        try:
            self.media.close()
        finally:
            self._open = False
            self._linked = False
            self._associated = False
        # snrmRequest() clears Gurux's connection flags but does not reset the
        # HDLC sender/receiver sequence. Without this reset a valid UA can be
        # discarded after an interrupted association and the reconnect times
        # out even though the meter answered.
        try:
            self.client.settings.resetFrameSequence()
        except Exception:
            pass
        if self.config.transport.session_guard_ms:
            time.sleep(self.config.transport.session_guard_ms / 1000)
        try:
            return self.connect()
        except Exception:
            try:
                self.media.close()
            finally:
                self._open = False
                self._linked = False
                self._associated = False
            raise


class GuruxLlsSession(GuruxSession):
    """LLS password association without xDLMS APDU ciphering."""

    def __init__(
        self,
        config: AppConfig,
        baudrate: int,
        traffic: TrafficLogger,
        *,
        server_logical_address: int,
        server_physical_address: int,
        server_address_size: int,
    ):
        profile = config.profile
        if not isinstance(profile, LlsProfile):
            raise TypeError("GuruxLlsSession requires lls configuration")
        super().__init__(
            config,
            baudrate,
            traffic,
            server_logical_address=server_logical_address,
            server_physical_address=server_physical_address,
            server_address_size=server_address_size,
            client_address=profile.client_address,
            profile_name=profile.role,
        )
        self.authentication_name = "low"
        self.association_phase = "lls_association"
        self.association_purpose = "password_association"
        self.client.authentication = Authentication.LOW
        self.client.password = bytearray(resolve_lls_password(profile))


class GuruxAuthenticationProbeSession(GuruxSession):
    """One LOW or password-based HLS authentication probe."""

    _SUPPORTED = {
        Authentication.LOW: "low",
        Authentication.HIGH: "high",
        Authentication.HIGH_MD5: "high_md5",
        Authentication.HIGH_SHA1: "high_sha1",
        Authentication.HIGH_SHA256: "high_sha256",
    }

    def __init__(
        self,
        config: AppConfig,
        baudrate: int,
        traffic: TrafficLogger,
        authentication: Authentication,
        *,
        client_address: int,
        profile_name: str,
        password: bytes,
        client_system_title: bytes | None = None,
        server_logical_address: int,
        server_physical_address: int,
        server_address_size: int,
    ):
        if authentication not in self._SUPPORTED:
            raise ValueError("unsupported password authentication probe")
        super().__init__(
            config,
            baudrate,
            traffic,
            server_logical_address=server_logical_address,
            server_physical_address=server_physical_address,
            server_address_size=server_address_size,
            client_address=client_address,
            profile_name=profile_name,
        )
        self.authentication = authentication
        self.aarq_accepted = False
        self.authentication_name = self._SUPPORTED[authentication]
        self.association_phase = "authentication_scan"
        self.association_purpose = f"probe_{self.authentication_name}"
        self.client.authentication = authentication
        self.client.password = bytearray(password)
        if client_system_title is not None:
            self.client.ciphering.systemTitle = bytearray(client_system_title)

    def connect(self) -> dict[str, Any]:
        details = super().connect()
        self.aarq_accepted = True
        if self.authentication == Authentication.LOW:
            return details
        if not self.client.isAuthenticationRequired:
            self._associated = False
            raise RuntimeError(
                f"{self.authentication_name} AARE did not require the HLS exchange"
            )

        # AARE acceptance is only phase one of HLS. Validate the server's
        # challenge response before reporting this mechanism as successful.
        self._associated = False
        reply = GXReplyData()
        self._read_blocks(
            _quiet_gurux(self.client.getApplicationAssociationRequest),
            reply,
            phase="authentication_scan",
            purpose=f"validate_{self.authentication_name}",
            operation="HLS_ACTION",
            attempt=1,
            object_context={
                "class_id": 15,
                "logical_name": "0.0.40.0.0.255",
                "method_id": 1,
                "only_permitted_action": True,
            },
            tx_context={"service": "action-request", "challenge": "<redacted>"},
        )
        try:
            _quiet_gurux(
                self.client.parseApplicationAssociationResponse, reply.data
            )
        except Exception as exc:
            raise RuntimeError(
                f"{self.authentication_name} server challenge validation failed "
                f"({type(exc).__name__})"
            ) from None
        self._associated = True
        return self.association_details()

    def association_details(self) -> dict[str, Any]:
        details = super().association_details()
        details["hls_validated"] = (
            self._associated if self.authentication != Authentication.LOW else None
        )
        return details


class GuruxSecureSession(GuruxSession):
    """HLS-GMAC Security Suite 0 association with protected xDLMS services."""

    def __init__(
        self,
        config: AppConfig,
        baudrate: int,
        traffic: TrafficLogger,
        counter_lease: InvocationCounterLease,
        gak: bytes,
        guek: bytes,
        *,
        server_logical_address: int,
        server_physical_address: int,
        server_address_size: int,
    ):
        profile = config.profile
        if not isinstance(profile, SecureProfile):
            raise TypeError("GuruxSecureSession requires hls_gmac_suite0 configuration")
        super().__init__(
            config,
            baudrate,
            traffic,
            server_logical_address=server_logical_address,
            server_physical_address=server_physical_address,
            server_address_size=server_address_size,
            client_address=profile.client_address,
            profile_name=profile.role,
        )
        self.counter_lease = counter_lease
        self._gak = bytes(gak)
        self._guek = bytes(guek)
        self.authentication_name = "high_gmac"
        self.aarq_accepted = False
        self.security_name = "authentication_encryption"
        self._configure_secure_client(self.client)
        self._used_invocation_counters: list[int] = []
        self._replay_probe_counter: int | None = None

    def _configure_secure_client(self, client: Any) -> None:
        """Apply this session's Suite 0 identity and current leased counter."""

        profile = self.config.profile
        if not isinstance(profile, SecureProfile):
            raise TypeError("secure protocol client requires hls_gmac_suite0 configuration")
        client.authentication = Authentication.HIGH_GMAC
        client.ciphering.systemTitle = bytearray(profile.client_system_title)
        client.ciphering.authenticationKey = bytearray(self._gak)
        client.ciphering.blockCipherKey = bytearray(self._guek)
        client.ciphering.security = Security.AUTHENTICATION_ENCRYPTION
        client.ciphering.securitySuite = SecuritySuite.SUITE_0
        client.ciphering.invocationCounter = int(self.counter_lease.next_counter)
        client.useProtectedRelease = True

    def _replace_secure_client(self) -> None:
        """Replace all Gurux protocol state while preserving the counter lease."""

        profile = self.config.profile
        if not isinstance(profile, SecureProfile):
            raise TypeError("secure protocol client requires hls_gmac_suite0 configuration")
        server_address = GXDLMSClient.getServerAddress(
            self.server_logical_address,
            self.server_physical_address,
            self.server_address_size,
        )
        client = GXDLMSSecureClient(
            True,
            profile.client_address,
            server_address,
            Authentication.NONE,
            None,
            InterfaceType.HDLC,
        )
        if self.server_address_size:
            client.serverAddressSize = self.server_address_size
        client.maxReceivePDUSize = profile.proposed_max_pdu_size
        self._configure_secure_client(client)
        client.settings.resetFrameSequence()
        self.client = client
        self._replay_probe_counter = None

    def _teardown_for_secure_recovery(self, *, attempt_release: bool) -> list[str]:
        """Best-effort RLRQ, mandatory DISC, and local protocol/media reset."""

        warnings: list[str] = []
        if self._open and attempt_release and self._associated:
            try:
                release = _quiet_gurux(self.client.releaseRequest)
                if release:
                    reply = GXReplyData()
                    self._read_blocks(
                        release,
                        reply,
                        phase="invocation_counter_recovery",
                        purpose="association_release",
                        operation="RLRQ",
                        attempt=1,
                        tx_context={"message": "recovery-release-request"},
                    )
            except Exception as exc:
                warnings.append(
                    f"association release failed: {type(exc).__name__}: {exc}"
                )
        self._associated = False

        # Always generate DISC with force=True. Besides notifying the meter,
        # Gurux's disconnectRequest resets its HDLC sequence state.
        if self._open:
            try:
                disconnect = _quiet_gurux(self.client.disconnectRequest, True)
                if disconnect:
                    reply = GXReplyData()
                    self._exchange_packet(
                        disconnect,
                        reply,
                        phase="invocation_counter_recovery",
                        purpose="hdlc_disconnect",
                        operation="DISC",
                        attempt=1,
                        tx_context={"message": "forced-recovery-disconnect"},
                    )
            except Exception as exc:
                warnings.append(f"HDLC disconnect failed: {type(exc).__name__}: {exc}")
        self._linked = False
        try:
            self.client.settings.resetFrameSequence()
        except Exception as exc:
            warnings.append(f"HDLC sequence reset failed: {type(exc).__name__}: {exc}")
        try:
            self.media.resetSynchronousBuffer()
            self.media.close()
        except Exception as exc:
            warnings.append(f"serial close failed: {type(exc).__name__}: {exc}")
        self._open = False
        if self.config.transport.session_guard_ms:
            time.sleep(self.config.transport.session_guard_ms / 1000)
        return warnings

    def reconnect(self) -> dict[str, Any]:
        """Reconnect with a clean teardown and a fresh Gurux protocol client."""

        self._teardown_for_secure_recovery(attempt_release=self._associated)
        self._replace_secure_client()
        try:
            return self.connect()
        except Exception:
            try:
                self._teardown_for_secure_recovery(attempt_release=False)
            except Exception:
                pass
            raise

    def _restore_after_failed_safe_get(
        self,
        progress: Callable[[dict[str, Any]], None],
        recovery: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Restore association, waiting once if the meter rejects the fresh AARQ."""

        recovery = recovery if recovery is not None else {}
        recovery.update(
            {
                "cleanup_warnings": self._teardown_for_secure_recovery(
                    attempt_release=True
                ),
                "fresh_client": True,
                "waited_ms": 0,
            }
        )
        self._replace_secure_client()
        try:
            self.connect()
            recovery["reconnect_attempts"] = 1
            return recovery
        except Exception as first_error:
            recovery["reconnect_attempts"] = 1
            recovery["first_reconnect_error"] = (
                f"{type(first_error).__name__}: {first_error}"
            )
            wait_ms = int(
                self.config.profile.invocation_counter.recovery_wait_ms
            )
            if classify_exception(first_error) != Outcome.DLMS_ERROR or wait_ms <= 0:
                raise

        recovery["cleanup_warnings"].extend(
            self._teardown_for_secure_recovery(attempt_release=False)
        )
        progress(
            {
                "phase": "invocation_counter_recovery_wait",
                "wait_ms": wait_ms,
                "message": (
                    "Meter rejected the fresh secure association; waiting "
                    f"{wait_ms} ms for its client association/security timeout"
                ),
            }
        )
        time.sleep(wait_ms / 1000)
        recovery["waited_ms"] = wait_ms
        self._replace_secure_client()
        try:
            self.connect()
        except Exception as second_error:
            recovery["reconnect_attempts"] = 2
            recovery["second_reconnect_error"] = (
                f"{type(second_error).__name__}: {second_error}"
            )
            try:
                recovery["cleanup_warnings"].extend(
                    self._teardown_for_secure_recovery(attempt_release=False)
                )
            except Exception:
                pass
            raise RuntimeError(
                "meter still rejects the secure client after its configured recovery "
                f"wait ({wait_ms} ms); wait longer or use an authorized meter "
                "reset/admin unlock"
            ) from second_error
        recovery["reconnect_attempts"] = 2
        return recovery

    def _endpoint_context(self) -> dict[str, Any]:
        context = super()._endpoint_context()
        server_title = self.client.settings.sourceSystemTitle
        context.update(
            {
                "authentication_mechanism": "high_gmac",
                "security_suite": 0,
                "security_policy": "authentication_encryption",
                "client_system_title": bytes(self.client.ciphering.systemTitle).hex().upper(),
                "client_system_title_metadata": _system_title_metadata(
                    self.client.ciphering.systemTitle
                ),
                "server_system_title": bytes(server_title).hex().upper() if server_title else None,
                "server_system_title_metadata": _system_title_metadata(server_title),
            }
        )
        return context

    @staticmethod
    def _expected_protected_command(operation: str) -> str | None:
        return {
            "AARQ": "glo-initiate-request",
            "HLS_ACTION": "glo-action-request",
            "GET": "glo-get-request",
        }.get(operation)

    @staticmethod
    def _expected_protected_response(operation: str) -> str | None:
        return {
            "AARQ": "glo-initiate-response",
            "HLS_ACTION": "glo-action-response",
            "GET": "glo-get-response",
        }.get(operation)

    def _before_transmit(
        self, raw_tx: bytes, *, operation: str, purpose: str
    ) -> dict[str, Any]:
        metadata = protected_apdu_metadata(raw_tx, outgoing=True)
        expected = self._expected_protected_command(operation)
        has_xdlms_apdu = metadata.get("protected") or "outer_command_code" in metadata
        if expected and has_xdlms_apdu and metadata.get("protected_command") != expected:
            raise RuntimeError(
                f"refusing plaintext or incorrectly protected {operation}; expected {expected}"
            )
        if metadata.get("protected"):
            transmitted_counter = metadata.get("invocation_counter")
            replay_probe_counter = getattr(self, "_replay_probe_counter", None)
            if replay_probe_counter is not None:
                if transmitted_counter != replay_probe_counter:
                    raise RuntimeError(
                        "generated replay probe did not use the requested invocation counter"
                    )
                metadata.update(
                    {
                        "counter_reuse_probe": True,
                        "counter_state_persisted": False,
                        "authentication_mechanism": "high_gmac",
                        "security_suite": 0,
                        "security_policy": "authentication_encryption",
                        "client_system_title": bytes(
                            self.client.ciphering.systemTitle
                        ).hex().upper(),
                    }
                )
                return metadata
            # Gurux increments while generating an APDU. Persist that next value
            # under the exclusive lease before the first byte can reach media.
            previous_next = int(self.counter_lease.next_counter)
            generated_next = int(self.client.ciphering.invocationCounter)
            metadata["generated_counter_range"] = {
                "first_counter": previous_next,
                "next_counter": generated_next,
                "count": generated_next - previous_next,
            }
            self.counter_lease.persist_next(generated_next)
            metadata.update(
                {
                    "authentication_mechanism": "high_gmac",
                    "security_suite": 0,
                    "security_policy": "authentication_encryption",
                    "client_system_title": bytes(self.client.ciphering.systemTitle).hex().upper(),
                }
            )
        return metadata

    def _after_transmit(
        self,
        raw_tx: bytes,
        metadata: dict[str, Any],
        *,
        operation: str,
        purpose: str,
    ) -> None:
        if metadata.get("protected") and not metadata.get("counter_reuse_probe"):
            transmitted_counter = metadata.get("invocation_counter")
            used_counters = getattr(self, "_used_invocation_counters", None)
            if isinstance(transmitted_counter, int) and used_counters is not None:
                used_counters.append(transmitted_counter)

    def _generate_replay_get(
        self, target: Any, attribute_id: int, reused_counter: int
    ) -> Any:
        """Generate a protected GET without changing the safe next counter."""

        safe_next = int(self.client.ciphering.invocationCounter)
        try:
            self.client.ciphering.invocationCounter = reused_counter
            return _quiet_gurux(self.client.read, target, attribute_id)
        finally:
            self.client.ciphering.invocationCounter = safe_next

    def test_invocation_counter_reuse(
        self,
        progress: Callable[[dict[str, Any]], None] | None = None,
    ) -> dict[str, Any]:
        """Send two isolated GET probes with stale invocation counters."""

        if not self._associated:
            raise RuntimeError("counter-reuse testing requires a validated secure association")

        progress = progress or (lambda _: None)
        target = self.create_object(15, "0.0.40.0.0.255")
        session_counters = list(self._used_invocation_counters)

        result: dict[str, Any] = {
            "enabled": True,
            "status": "inconclusive",
            "target": {
                "class_id": 15,
                "logical_name": "0.0.40.0.0.255",
                "attribute_id": 1,
            },
            "requested_probes": 2,
            "probes": [],
            "association_restored": False,
        }
        if not session_counters or (
            session_counters[0] == 0 and len(session_counters) < 2
        ):
            result["preparation_error"] = (
                "no eligible transmitted session counter was available"
            )
            result.update(
                {
                    "attempted_probes": 0,
                    "accepted_probes": 0,
                    "device_allows_reuse": False,
                    "association_restored": self._associated,
                }
            )
            return result

        session_counter_index = 1 if session_counters[0] == 0 else 0
        replay_counters = [0, session_counters[session_counter_index]]
        for sequence, reused_counter in enumerate(replay_counters, 1):
            probe = {
                "sequence": sequence,
                "reused_counter": reused_counter,
                "reused_counter_hex": f"0x{reused_counter:08X}",
                "source": (
                    "initial_zero"
                    if sequence == 1
                    else (
                        "second_session_counter"
                        if session_counter_index == 1
                        else "first_session_counter"
                    )
                ),
                "accepted": False,
            }
            progress(
                {
                    "phase": "invocation_counter_reuse_attempt",
                    "attempt": sequence,
                    "total": len(replay_counters),
                    "invocation_counter": reused_counter,
                    "invocation_counter_hex": probe["reused_counter_hex"],
                    "message": (
                        f"Attempt {probe['reused_counter_hex']} as invocation counter"
                    ),
                }
            )
            safe_next = int(self.client.ciphering.invocationCounter)
            try:
                packets = self._generate_replay_get(target, 1, reused_counter)
                self._replay_probe_counter = reused_counter
                reply = GXReplyData()
                self._read_blocks(
                    packets,
                    reply,
                    phase="invocation_counter_reuse_test",
                    purpose="stale_counter_get",
                    operation="GET",
                    attempt=sequence,
                    object_context={
                        "class_id": 15,
                        "logical_name": "0.0.40.0.0.255",
                        "attribute_id": 1,
                        "reused_invocation_counter": reused_counter,
                    },
                    tx_context={
                        "service": "get-request",
                        "counter_reuse_probe": True,
                    },
                )
            except Exception as exc:
                probe.update(
                    {
                        "outcome": classify_exception(exc).value,
                        "error": f"{type(exc).__name__}: {exc}",
                    }
                )
            else:
                probe.update({"outcome": Outcome.SUCCESS.value, "accepted": True})
            finally:
                self._replay_probe_counter = None
                self.client.ciphering.invocationCounter = safe_next
            result["probes"].append(probe)

            if probe["accepted"]:
                # An accepted replay is unsafe and must not share an
                # association with the next diagnostic probe.
                try:
                    self.reconnect()
                except Exception as exc:
                    probe["reconnect_error"] = f"{type(exc).__name__}: {exc}"
                    result["restore_error"] = probe["reconnect_error"]
                    break
                continue

            # A conforming meter rejects the stale request. Before tearing down
            # the association, prove whether it still accepts the next leased
            # counter. This consumes and persists exactly one fresh counter.
            safe_counter = max(
                int(self.client.ciphering.invocationCounter),
                int(self.counter_lease.next_counter),
            )
            self.client.ciphering.invocationCounter = safe_counter
            recovery = {
                "safe_counter": safe_counter,
                "safe_get_attempted": True,
                "safe_get_succeeded": False,
            }
            probe["recovery"] = recovery
            progress(
                {
                    "phase": "invocation_counter_recovery_get",
                    "attempt": sequence,
                    "invocation_counter": recovery["safe_counter"],
                    "message": (
                        "Testing the existing association with the next safe "
                        f"counter 0x{recovery['safe_counter']:08X}"
                    ),
                }
            )
            try:
                self.read_attribute(
                    target,
                    1,
                    1,
                    phase="invocation_counter_recovery",
                    purpose="safe_counter_get",
                )
            except Exception as safe_error:
                recovery["safe_get_error"] = (
                    f"{type(safe_error).__name__}: {safe_error}"
                )
                try:
                    self._restore_after_failed_safe_get(progress, recovery)
                except Exception as exc:
                    probe["reconnect_error"] = f"{type(exc).__name__}: {exc}"
                    result["restore_error"] = probe["reconnect_error"]
                    break
            else:
                recovery["safe_get_succeeded"] = True
                recovery["association_continued"] = True

        result["association_restored"] = self._associated
        result["attempted_probes"] = len(result["probes"])
        result["accepted_probes"] = sum(
            bool(item["accepted"]) for item in result["probes"]
        )
        result["device_allows_reuse"] = result["accepted_probes"] > 0
        if result["attempted_probes"] == result["requested_probes"] and self._associated:
            result["status"] = (
                "reuse_accepted"
                if result["device_allows_reuse"]
                else "reuse_not_observed"
            )
        return result

    def _after_receive(
        self, raw_rx: list[bytes], *, operation: str, purpose: str
    ) -> dict[str, Any]:
        metadata = super()._after_receive(raw_rx, operation=operation, purpose=purpose)
        expected = self._expected_protected_response(operation)
        has_xdlms_apdu = metadata.get("protected") or "outer_command_code" in metadata
        if expected and has_xdlms_apdu and metadata.get("protected_command") != expected:
            raise RuntimeError(
                f"secure {operation} response was not the expected {expected}"
            )
        return metadata

    def connect(self) -> dict[str, Any]:
        self.media.open()
        self._open = True
        reply = GXReplyData()
        snrm = _quiet_gurux(self.client.snrmRequest)
        if snrm:
            self._exchange_packet(
                snrm,
                reply,
                phase="secure_link_setup",
                purpose="hdlc_link_setup",
                operation="SNRM",
                attempt=1,
                tx_context={"message": "set-normal-response-mode"},
            )
            _quiet_gurux(self.client.parseUAResponse, reply.data)
            self._linked = True

        reply.clear()
        self._read_blocks(
            _quiet_gurux(self.client.aarqRequest),
            reply,
            phase="secure_association",
            purpose="ciphered_association",
            operation="AARQ",
            attempt=1,
            tx_context={
                "message": "ciphered-application-association-request",
                "authentication": "high_gmac",
                "security_suite": 0,
                "security_policy": "authentication_encryption",
                "referencing": "logical-name",
            },
        )
        _quiet_gurux(self.client.parseAareResponse, reply.data)
        self.aarq_accepted = True
        if not self.client.isAuthenticationRequired:
            raise RuntimeError("HLS-GMAC AARE did not require the HLS authentication exchange")
        server_title = self.client.settings.sourceSystemTitle
        if not server_title or len(server_title) != 8:
            raise RuntimeError("HLS-GMAC AARE did not provide a valid eight-byte server system title")

        reply.clear()
        self._read_blocks(
            _quiet_gurux(self.client.getApplicationAssociationRequest),
            reply,
            phase="hls_authentication",
            purpose="association_ln_authentication",
            operation="HLS_ACTION",
            attempt=1,
            object_context={
                "class_id": 15,
                "logical_name": "0.0.40.0.0.255",
                "method_id": 1,
                "only_permitted_action": True,
            },
            tx_context={"service": "action-request", "challenge": "<redacted>"},
        )
        try:
            # Gurux 1.0.201 prints both challenge values on validation failure.
            # Suppress that upstream diagnostic and expose only a sanitized error.
            _quiet_gurux(
                self.client.parseApplicationAssociationResponse, reply.data
            )
        except Exception as exc:
            raise RuntimeError(
                f"HLS-GMAC server response validation failed ({type(exc).__name__})"
            ) from None
        self._associated = True
        return self.association_details()

    def association_details(self) -> dict[str, Any]:
        details = super().association_details()
        server_title = self.client.settings.sourceSystemTitle
        details.update(
            {
                "security_suite": 0,
                "cipher": "aes_gcm_128",
                "hls_validated": self._associated,
                "client_system_title": bytes(self.client.ciphering.systemTitle).hex().upper(),
                "client_system_title_metadata": _system_title_metadata(
                    self.client.ciphering.systemTitle
                ),
                "server_system_title": bytes(server_title).hex().upper() if server_title else None,
                "server_system_title_metadata": _system_title_metadata(server_title),
                "next_client_invocation_counter": int(self.client.ciphering.invocationCounter),
            }
        )
        return details
