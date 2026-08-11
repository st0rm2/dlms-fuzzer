"""Gurux-backed direct serial HDLC transport and public association."""

from __future__ import annotations

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
from gurux_dlms.enums import Authentication, Command, Conformance, InterfaceType, ObjectType
from gurux_dlms.secure.GXDLMSSecureClient import GXDLMSSecureClient
from gurux_serial import GXSerial

from .config import AppConfig
from .result_model import Outcome, enum_name, normalize_value
from .traffic_logger import TrafficLogger


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
    ):
        self.config = config
        self.baudrate = baudrate
        self.traffic = traffic
        profile = config.profile
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
            profile.client_address,
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
            return {"xml": translator.messageToXml(bytearray(frame))}
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

        try:
            with self.media.getSynchronous():
                if raw_tx:
                    self.media.send(bytearray(raw_tx))
                while not self.client.getData(frame_data, reply, notification):
                    if notification.data.size:
                        raise RuntimeError("unsolicited notification received during request")
                    if not self.media.receive(receive):
                        raise TimeoutException("no complete reply received from the meter")
                    received = self._bytes(receive.reply)
                    raw_rx.append(received)
                    frame_data.set(received)
                    receive.reply = None
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
            tx_decoded["protocol_frames"] = [self._frame_xml(raw_tx)] if raw_tx else []
            rx_decoded = self._reply_structure(reply)
            rx_decoded["protocol_frames"] = [self._frame_xml(frame) for frame in raw_rx]
            if caught is not None:
                rx_decoded["exception"] = {
                    "type": type(caught).__name__, "message": str(caught)
                }
            context = self._endpoint_context()
            context.update(object_context or {})
            self.traffic.log(
                profile="public",
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
            packet = None if reply.isStreaming() else self.client.receiverReady(reply)
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
        snrm = self.client.snrmRequest()
        if snrm:
            self._exchange_packet(
                snrm,
                reply,
                phase="serial_and_baud_discovery",
                purpose="hdlc_link_setup",
                operation="SNRM",
                attempt=1,
                tx_context={"message": "set-normal-response-mode"},
            )
            self.client.parseUAResponse(reply.data)
            self._linked = True

        reply.clear()
        self._read_blocks(
            self.client.aarqRequest(),
            reply,
            phase="serial_and_baud_discovery",
            purpose="public_association",
            operation="AARQ",
            attempt=1,
            tx_context={
                "message": "application-association-request",
                "authentication": "none",
                "referencing": "logical-name",
            },
        )
        self.client.parseAareResponse(reply.data)
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
            "profile": "public",
            "authentication": "none",
            "security": "none",
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
            self.client.getObjectsRequest(),
            reply,
            phase="public_reconnaissance",
            purpose="association_view_scan",
            operation="GET",
            attempt=attempt,
            object_context={"class_id": 15, "logical_name": "0.0.40.0.0.255", "attribute_id": 2},
            tx_context={"service": "get-request", "attribute": "object-list"},
        )
        return self.client.parseObjects(
            reply.data, onlyKnownObjects=False, ignoreInactiveObjects=False
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
            self.client.read(target, attribute_id),
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
            decoded = self.client.updateValue(target, attribute_id, raw_value)
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

    def close(self) -> list[str]:
        warnings: list[str] = []
        if not self._open:
            return warnings
        if self._associated:
            try:
                release = self.client.releaseRequest()
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
                disconnect = self.client.disconnectRequest()
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
