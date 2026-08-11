"""Strict configuration loading for the public GET-only milestone."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Mapping

DEFAULT_BAUD_RATES = (300, 600, 1200, 2400, 4800, 9600, 19200, 38400, 57600, 115200)


class ConfigError(ValueError):
    """The supplied configuration is invalid or unsupported."""


@dataclass(frozen=True)
class SerialSettings:
    parity: str = "none"
    data_bits: int = 8
    stop_bits: float = 1


@dataclass(frozen=True)
class TransportConfig:
    device: str
    baudrate: int | str = "auto"
    baudrate_candidates: tuple[int, ...] = DEFAULT_BAUD_RATES
    serial: SerialSettings = SerialSettings()
    response_timeout_ms: int = 3000
    inter_request_delay_ms: int = 100
    session_guard_ms: int = 500


@dataclass(frozen=True)
class ScanConfig:
    mode: str = "get"
    total_get_attempts: int = 2
    association_view_first: bool = True
    common_catalogue: bool = True


@dataclass(frozen=True)
class PublicProfile:
    name: str = "public"
    client_address: int = 16
    server_logical_address: int = 1
    server_physical_address: int = 1
    proposed_max_pdu_size: int = 0xFFFF


@dataclass(frozen=True)
class OutputConfig:
    directory: str = "./runs"
    report_file: str = "report.json"
    traffic_file: str = "traffic.jsonl"
    redact_secrets: bool = True


@dataclass(frozen=True)
class AppConfig:
    version: int
    transport: TransportConfig
    scan: ScanConfig
    profile: PublicProfile
    output: OutputConfig

    def redacted_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["profiles"] = [
            {
                "name": self.profile.name,
                "client_address": self.profile.client_address,
                "server": {
                    "logical_address": self.profile.server_logical_address,
                    "physical_address": self.profile.server_physical_address,
                },
                "authentication": {"mechanism": "none"},
                "security": {"policy": "none"},
                "proposed_max_pdu_size": self.profile.proposed_max_pdu_size,
            }
        ]
        data.pop("profile")
        return data


def _mapping(value: Any, label: str) -> Mapping[str, Any]:
    if value is None:
        return {}
    if not isinstance(value, Mapping):
        raise ConfigError(f"{label} must be a mapping")
    return value


def _only_keys(data: Mapping[str, Any], allowed: set[str], label: str) -> None:
    unknown = sorted(set(data) - allowed)
    if unknown:
        raise ConfigError(f"{label} contains unsupported keys: {', '.join(unknown)}")


def _integer(value: Any, label: str, minimum: int, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not minimum <= value <= maximum:
        raise ConfigError(f"{label} must be an integer from {minimum} to {maximum}")
    return value


def _positive_ms(value: Any, label: str, *, allow_zero: bool = False) -> int:
    minimum = 0 if allow_zero else 1
    return _integer(value, label, minimum, 3_600_000)


def _parse_transport(raw: Any) -> TransportConfig:
    data = _mapping(raw, "transport")
    _only_keys(
        data,
        {
            "type", "device", "baudrate", "baudrate_candidates", "serial",
            "response_timeout_ms", "inter_request_delay_ms", "session_guard_ms",
        },
        "transport",
    )
    if data.get("type", "serial_hdlc") != "serial_hdlc":
        raise ConfigError("this release supports only transport.type: serial_hdlc")
    device = data.get("device")
    if not isinstance(device, str) or not device.strip():
        raise ConfigError("transport.device must be a non-empty serial device path")
    baudrate = data.get("baudrate", "auto")
    if baudrate != "auto":
        baudrate = _integer(baudrate, "transport.baudrate", 50, 4_000_000)
    candidates_raw = data.get("baudrate_candidates", DEFAULT_BAUD_RATES)
    if not isinstance(candidates_raw, (list, tuple)) or not candidates_raw:
        raise ConfigError("transport.baudrate_candidates must be a non-empty list")
    candidates = tuple(
        _integer(item, f"transport.baudrate_candidates[{pos}]", 50, 4_000_000)
        for pos, item in enumerate(candidates_raw)
    )
    if len(set(candidates)) != len(candidates):
        raise ConfigError("transport.baudrate_candidates must not contain duplicates")

    serial_raw = _mapping(data.get("serial"), "transport.serial")
    _only_keys(serial_raw, {"parity", "data_bits", "stop_bits"}, "transport.serial")
    parity = str(serial_raw.get("parity", "none")).lower()
    if parity not in {"none", "even", "odd", "mark", "space"}:
        raise ConfigError("transport.serial.parity must be none, even, odd, mark, or space")
    data_bits = _integer(serial_raw.get("data_bits", 8), "transport.serial.data_bits", 5, 8)
    stop_bits = serial_raw.get("stop_bits", 1)
    if stop_bits not in (1, 1.5, 2):
        raise ConfigError("transport.serial.stop_bits must be 1, 1.5, or 2")
    return TransportConfig(
        device=device.strip(),
        baudrate=baudrate,
        baudrate_candidates=candidates,
        serial=SerialSettings(parity, data_bits, float(stop_bits)),
        response_timeout_ms=_positive_ms(
            data.get("response_timeout_ms", 3000), "transport.response_timeout_ms"
        ),
        inter_request_delay_ms=_positive_ms(
            data.get("inter_request_delay_ms", 100),
            "transport.inter_request_delay_ms",
            allow_zero=True,
        ),
        session_guard_ms=_positive_ms(
            data.get("session_guard_ms", 500), "transport.session_guard_ms", allow_zero=True
        ),
    )


def _parse_scan(raw: Any) -> ScanConfig:
    data = _mapping(raw, "scan")
    _only_keys(
        data,
        {
            "mode", "total_get_attempts", "association_view_first",
            "common_catalogue", "manufacturer_catalogue", "union_profile_test",
        },
        "scan",
    )
    if str(data.get("mode", "get")).lower() != "get":
        raise ConfigError("this milestone supports only scan.mode: get")
    attempts = _integer(data.get("total_get_attempts", 2), "scan.total_get_attempts", 2, 2)
    manufacturer = data.get("manufacturer_catalogue", "auto")
    if manufacturer not in (None, False, "auto"):
        raise ConfigError("manufacturer catalogues are deferred; use auto, false, or omit the key")
    if data.get("union_profile_test", True) not in (True, False):
        raise ConfigError("scan.union_profile_test must be boolean")
    for key in ("association_view_first", "common_catalogue"):
        if data.get(key, True) not in (True, False):
            raise ConfigError(f"scan.{key} must be boolean")
    if not data.get("association_view_first", True):
        raise ConfigError("association_view_first must remain true in this milestone")
    return ScanConfig(
        total_get_attempts=attempts,
        association_view_first=True,
        common_catalogue=bool(data.get("common_catalogue", True)),
    )


def _parse_profile(raw: Any) -> PublicProfile:
    if raw is None:
        profiles = [{}]
    elif isinstance(raw, list):
        profiles = raw
    else:
        raise ConfigError("profiles must be a list")
    if len(profiles) != 1:
        raise ConfigError("this milestone requires exactly one public profile")
    data = _mapping(profiles[0], "profiles[0]")
    _only_keys(
        data,
        {
            "name", "client_address", "server", "authentication", "security",
            "proposed_max_pdu_size", "hdlc",
        },
        "profiles[0]",
    )
    if data.get("name", "public") != "public":
        raise ConfigError("the only supported profile name is public")
    auth = _mapping(data.get("authentication"), "profiles[0].authentication")
    if auth.get("mechanism", "none") != "none" or set(auth) - {"mechanism"}:
        raise ConfigError("the public profile must use authentication.mechanism: none")
    security = _mapping(data.get("security"), "profiles[0].security")
    if security.get("policy", "none") != "none" or set(security) - {"policy"}:
        raise ConfigError("the public profile must use security.policy: none")
    if data.get("hdlc") not in (None, {}):
        raise ConfigError("per-profile HDLC overrides are deferred")
    server = _mapping(data.get("server"), "profiles[0].server")
    _only_keys(server, {"logical_address", "physical_address"}, "profiles[0].server")
    return PublicProfile(
        client_address=_integer(data.get("client_address", 16), "profiles[0].client_address", 1, 0x3FFF),
        server_logical_address=_integer(server.get("logical_address", 1), "server.logical_address", 0, 0x3FFF),
        server_physical_address=_integer(server.get("physical_address", 1), "server.physical_address", 0, 0x3FFF),
        proposed_max_pdu_size=_integer(
            data.get("proposed_max_pdu_size", 0xFFFF), "profiles[0].proposed_max_pdu_size", 64, 0xFFFF
        ),
    )


def _parse_output(raw: Any) -> OutputConfig:
    data = _mapping(raw, "output")
    _only_keys(data, {"directory", "report_file", "traffic_file", "redact_secrets"}, "output")
    values: dict[str, Any] = {}
    for key, default in (
        ("directory", "./runs"), ("report_file", "report.json"), ("traffic_file", "traffic.jsonl")
    ):
        value = data.get(key, default)
        if not isinstance(value, str) or not value.strip():
            raise ConfigError(f"output.{key} must be a non-empty path")
        values[key] = value.strip()
    if Path(values["report_file"]).name != values["report_file"]:
        raise ConfigError("output.report_file must be a file name, not a path")
    if Path(values["traffic_file"]).name != values["traffic_file"]:
        raise ConfigError("output.traffic_file must be a file name, not a path")
    redact = data.get("redact_secrets", True)
    if redact is not True:
        raise ConfigError("output.redact_secrets must remain true")
    return OutputConfig(**values, redact_secrets=True)


def parse_config(data: Any) -> AppConfig:
    root = _mapping(data, "configuration")
    _only_keys(root, {"version", "transport", "scan", "profiles", "output"}, "configuration")
    version = _integer(root.get("version", 1), "version", 1, 1)
    return AppConfig(
        version=version,
        transport=_parse_transport(root.get("transport")),
        scan=_parse_scan(root.get("scan")),
        profile=_parse_profile(root.get("profiles")),
        output=_parse_output(root.get("output")),
    )


def load_config(path: str | Path) -> AppConfig:
    try:
        import yaml
    except ModuleNotFoundError as exc:
        raise RuntimeError("PyYAML is required to load configuration files") from exc
    config_path = Path(path)
    try:
        raw = yaml.safe_load(config_path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise ConfigError(f"cannot read {config_path}: {exc}") from exc
    except yaml.YAMLError as exc:
        raise ConfigError(f"invalid YAML in {config_path}: {exc}") from exc
    return parse_config(raw)


def dump_config(config: AppConfig, path: str | Path) -> None:
    try:
        import yaml
    except ModuleNotFoundError as exc:
        raise RuntimeError("PyYAML is required to save configuration files") from exc
    Path(path).write_text(yaml.safe_dump(config.redacted_dict(), sort_keys=False), encoding="utf-8")
