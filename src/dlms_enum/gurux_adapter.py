"""Gurux-backed serial HDLC sessions for public and HLS-GMAC profiles."""

from __future__ import annotations

import contextlib
import io
import time
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

from .config import AppConfig, SecureProfile
from .counter_state import InvocationCounterLease
from .result_model import Outcome, enum_name, normalize_value
from .traffic_logger import TrafficLogger


_PROTECTED_COMMANDS = {
    int(Command.GLO_INITIATE_REQUEST): "glo-initiate-request",
    int(Command.GLO_INITIATE_RESPONSE): "glo-initiate-response",
    int(Command.GLO_GET_REQUEST): "glo-get-request",
    int(Command.GLO_GET_RESPONSE): "glo-get-response",
    int(Command.GLO_METHOD_REQUEST): "glo-action-request",
    int(Command.GLO_METHOD_RESPONSE): "glo-action-response",
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


def _protected_content(payload: bytes, command_offset: int) -> tuple[int, int] | None:
    decoded_length = _axdr_length(payload, command_offset + 1)
    if decoded_length is None:
        return None
    declared_length, content_offset = decoded_length
    if content_offset >= len(payload) or payload[content_offset] != 0x30:
        return None
    return declared_length, content_offset


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
    protected_content = _protected_content(payload, command_offset)
    result: dict[str, Any] = {
        "protected": True,
        "protected_command": _PROTECTED_COMMANDS[command],
        "protected_command_code": command,
    }
    if protected_content is not None:
        declared_length, security_offset = protected_content
    else:
        # Preserve the earlier best-effort metadata behavior for malformed or
        # partial captures that still expose the Suite 0 security header.
        declared_length = 0
        security_offset = payload.find(b"\x30", command_offset + 1, command_offset + 6)

    # Suite 0 AUTHENTICATION_ENCRYPTION uses security-control byte 0x30,
    # a four-octet invocation counter, and a 12-octet AES-GCM tag.
    if security_offset >= 0 and len(payload) >= security_offset + 5:
        result["security_control"] = "0x30"
        result["invocation_counter"] = int.from_bytes(
            payload[security_offset + 1:security_offset + 5], "big"
        )
        if declared_length >= 17:
            captured_content = payload[
                security_offset:min(security_offset + declared_length, len(payload))
            ]
            ciphertext_length = declared_length - 5 - 12
            captured_ciphertext = captured_content[5:5 + ciphertext_length]
            tag_offset = 5 + ciphertext_length
            captured_tag = captured_content[tag_offset:tag_offset + 12]
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
                    "authentication_tag_complete": len(captured_tag) == 12,
                }
            )
    return result


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
        self.profile_name = profile_name or profile.name
        self.authentication_name = "none"
        self.security_name = "none"
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

    def _endpoint_context(self) -> dict[str, Any]:
        labels = {1: "1-byte addressing", 2: "2-Byte addressing", 4: "4-byte addressing"}
        return {
            "baudrate": self.baudrate,
            "server_address": int(self.client.serverAddress),
            "server_logical_address": self.server_logical_address,
            "server_physical_address": self.server_physical_address,
            "server_address_size": self.server_address_size or int(self.client.serverAddressSize),
            "server_addressing_type": labels.get(
                self.server_address_size or int(self.client.serverAddressSize), "unknown"
            ),
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
            return {"xml": xml}
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
        receive.waitTime = self.config.transport.response_timeout_ms
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
            name = type(exc).__name__.lower()
            if "timeout" in name:
                outcome = Outcome.TIMEOUT
            elif isinstance(exc, GXDLMSException):
                outcome = Outcome.DLMS_ERROR
            elif isinstance(exc, OSError):
                outcome = Outcome.TRANSPORT_ERROR
            else:
                outcome = Outcome.PROTOCOL_ERROR
        finally:
            tx_decoded = dict(tx_context or {})
            tx_decoded.update(tx_protocol)
            tx_decoded["protocol_frames"] = [self._frame_xml(raw_tx)] if raw_tx else []
            rx_decoded = self._reply_structure(reply)
            rx_decoded.update(rx_protocol)
            rx_decoded["protocol_frames"] = [self._frame_xml(frame) for frame in raw_rx]
            if caught is not None:
                rx_decoded["exception"] = {
                    "type": type(caught).__name__, "message": str(caught)
                }
            context = self._endpoint_context()
            context.update(object_context or {})
            self.traffic.log(
                profile=self.profile_name,
                phase=phase,
                purpose=purpose,
                object_context=context,
                operation=operation,
                attempt=attempt,
                tx_frames=[raw_tx] if raw_tx else [],
                tx_decoded=tx_decoded,
                rx_frames=raw_rx,
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
            phase="endpoint_discovery",
            purpose="public_association",
            operation="AARQ",
            attempt=1,
            tx_context={
                "message": "application-association-request",
                "authentication": "none",
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
        return _quiet_gurux(
            self.client.parseObjects,
            reply.data,
            onlyKnownObjects=False,
            ignoreInactiveObjects=False,
        )

    def create_object(self, class_id: int, logical_name: str) -> Any:
        try:
            target = self.client.createObject(ObjectType(class_id))
        except ValueError:
            target = self.client.createObject(class_id)
        target.logicalName = logical_name
        return target

    def read_attribute(self, target: Any, attribute_id: int, attempt: int) -> dict[str, Any]:
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
            phase="get_scan",
            purpose="object_attribute_read",
            operation="GET",
            attempt=attempt,
            object_context=context,
            tx_context={"service": "get-request", "attribute_id": attribute_id},
        )
        raw_value = reply.value
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
            "dlms_data_type": enum_name(getattr(reply, "valueType", None)),
            "interface_data_type": interface_data_type,
            "ui_data_type": ui_data_type,
        }
        if class_decode_error:
            result["class_decode_note"] = class_decode_error
        return result

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
            profile_name=profile.name,
        )
        self.counter_lease = counter_lease
        self.authentication_name = "high_gmac"
        self.security_name = "authentication_encryption"
        self.client.authentication = Authentication.HIGH_GMAC
        self.client.ciphering.systemTitle = bytearray(profile.client_system_title)
        self.client.ciphering.authenticationKey = bytearray(gak)
        self.client.ciphering.blockCipherKey = bytearray(guek)
        self.client.ciphering.security = Security.AUTHENTICATION_ENCRYPTION
        self.client.ciphering.securitySuite = SecuritySuite.SUITE_0
        self.client.ciphering.invocationCounter = counter_lease.next_counter
        self.client.useProtectedRelease = True

    def _endpoint_context(self) -> dict[str, Any]:
        context = super()._endpoint_context()
        server_title = self.client.settings.sourceSystemTitle
        context.update(
            {
                "authentication_mechanism": "high_gmac",
                "security_suite": 0,
                "security_policy": "authentication_encryption",
                "client_system_title": bytes(self.client.ciphering.systemTitle).hex().upper(),
                "server_system_title": bytes(server_title).hex().upper() if server_title else None,
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
                "profile": self.profile_name,
                "authentication": "high_gmac",
                "security": "authentication_encryption",
                "security_suite": 0,
                "cipher": "aes_gcm_128",
                "hls_validated": self._associated,
                "client_system_title": bytes(self.client.ciphering.systemTitle).hex().upper(),
                "server_system_title": bytes(server_title).hex().upper() if server_title else None,
                "next_client_invocation_counter": int(self.client.ciphering.invocationCounter),
            }
        )
        return details
