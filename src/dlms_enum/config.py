"""Strict configuration and secret handling for public and HLS-GMAC scans."""

from __future__ import annotations

import getpass
import os
import stat
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Callable, Mapping

DEFAULT_BAUD_RATES = (9600, 19200, 4800, 2400, 1200, 600, 300, 38400, 57600, 115200)
SECURE_PROFILE_NAME = "hls_gmac_suite0"


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
    server_address_size: int | str = "auto"
    proposed_max_pdu_size: int = 0xFFFF


@dataclass(frozen=True)
class SecretSource:
    """A deferred key source whose locator/value is omitted from repr output."""

    kind: str
    locator: str | None = field(default=None, repr=False)

    def descriptor(self) -> dict[str, Any]:
        if self.kind == "env":
            return {"source": "environment"}
        if self.kind == "file":
            return {"source": "protected_file"}
        if self.kind == "inline":
            return {"source": "inline", "warning": "laboratory use only"}
        return {"source": "interactive_masked"}


@dataclass(frozen=True)
class SecureSecrets:
    gak: SecretSource = field(repr=False)
    guek: SecretSource = field(repr=False)


@dataclass(frozen=True)
class InvocationCounterConfig:
    public_client_address: int = 16
    class_id: int = 1
    logical_name: str = "0.0.43.1.0.255"
    attribute_id: int = 2
    state_file: str = "~/.local/state/dlms-enum/invocation-counters.json"
    meter_identity: str | None = None
    unsafe_override: int | None = None


@dataclass(frozen=True)
class SecureProfile:
    name: str
    client_address: int
    client_system_title: bytes
    secrets: SecureSecrets = field(repr=False)
    server_logical_address: int = 0
    server_physical_address: int = 1
    server_address_size: int | str = "auto"
    proposed_max_pdu_size: int = 0xFFFF
    invocation_counter: InvocationCounterConfig = InvocationCounterConfig()


ProfileConfig = PublicProfile | SecureProfile


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
    profile: ProfileConfig
    output: OutputConfig
    warnings: tuple[str, ...] = field(default=(), repr=False)

    @property
    def is_secure(self) -> bool:
        return isinstance(self.profile, SecureProfile)

    def redacted_dict(self) -> dict[str, Any]:
        """Return an effective configuration that never materializes key values."""

        transport = asdict(self.transport)
        transport["baudrate_candidates"] = list(self.transport.baudrate_candidates)
        profile: dict[str, Any] = {
            "name": self.profile.name,
            "client_address": self.profile.client_address,
            "server": {
                "logical_address": self.profile.server_logical_address,
                "physical_address": self.profile.server_physical_address,
            },
            "hdlc": {"address_size": self.profile.server_address_size},
            "proposed_max_pdu_size": self.profile.proposed_max_pdu_size,
        }
        if isinstance(self.profile, SecureProfile):
            profile.update(
                {
                    "client_system_title": f"hex:{self.profile.client_system_title.hex().upper()}",
                    "authentication": {"mechanism": "high_gmac"},
                    "security": {
                        "suite": 0,
                        "policy": "authentication_encryption",
                        "cipher": "aes_gcm_128",
                    },
                    "secrets": {
                        "gak": self.profile.secrets.gak.descriptor(),
                        "guek": self.profile.secrets.guek.descriptor(),
                    },
                    "invocation_counter": asdict(self.profile.invocation_counter),
                }
            )
        else:
            profile.update(
                {
                    "authentication": {"mechanism": "none"},
                    "security": {"policy": "none"},
                }
            )
        return {
            "version": self.version,
            "transport": transport,
            "scan": asdict(self.scan),
            "profiles": [profile],
            "output": asdict(self.output),
        }


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
    return _integer(value, label, 0 if allow_zero else 1, 3_600_000)


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
        response_timeout_ms=_positive_ms(data.get("response_timeout_ms", 3000), "transport.response_timeout_ms"),
        inter_request_delay_ms=_positive_ms(
            data.get("inter_request_delay_ms", 100), "transport.inter_request_delay_ms", allow_zero=True
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
            "mode", "total_get_attempts", "association_view_first", "common_catalogue",
            "manufacturer_catalogue", "union_profile_test",
        },
        "scan",
    )
    if str(data.get("mode", "get")).lower() != "get":
        raise ConfigError("this release supports only scan.mode: get")
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
        raise ConfigError("association_view_first must remain true in this release")
    return ScanConfig(
        total_get_attempts=attempts,
        association_view_first=True,
        common_catalogue=bool(data.get("common_catalogue", True)),
    )


def _parse_server_and_hdlc(data: Mapping[str, Any], *, secure: bool) -> tuple[int, int, int | str]:
    server = _mapping(data.get("server"), "profiles[0].server")
    _only_keys(server, {"logical_address", "physical_address"}, "profiles[0].server")
    hdlc = _mapping(data.get("hdlc"), "profiles[0].hdlc")
    _only_keys(hdlc, {"address_size"}, "profiles[0].hdlc")
    address_size = hdlc.get("address_size", "auto")
    if address_size not in ("auto", 1, 2, 4):
        raise ConfigError("profiles[0].hdlc.address_size must be auto, 1, 2, or 4")
    logical = _integer(server.get("logical_address", 0 if secure else 1), "server.logical_address", 0, 0x3FFF)
    physical = _integer(server.get("physical_address", 1), "server.physical_address", 0, 0x3FFF)
    if address_size == 1 and logical != 0:
        raise ConfigError("one-byte server addressing requires server.logical_address: 0")
    if address_size == 2 and (logical >= 0x80 or physical >= 0x80):
        raise ConfigError("two-byte server addressing requires address parts below 128")
    return logical, physical, address_size


def _parse_hex(value: Any, label: str, length: int) -> bytes:
    if not isinstance(value, str):
        raise ConfigError(f"{label} must use hex: followed by exactly {length * 2} hexadecimal characters")
    candidate = value.strip()
    if candidate.lower().startswith("hex:"):
        candidate = candidate[4:]
    if len(candidate) != length * 2:
        raise ConfigError(f"{label} must decode to exactly {length} bytes")
    try:
        decoded = bytes.fromhex(candidate)
    except ValueError as exc:
        raise ConfigError(f"{label} must contain hexadecimal characters only") from exc
    if len(decoded) != length:
        raise ConfigError(f"{label} must decode to exactly {length} bytes")
    return decoded


def _parse_secret_source(raw: Any, label: str, base_directory: Path | None) -> SecretSource:
    if isinstance(raw, str):
        if not raw.lower().startswith("hex:"):
            raise ConfigError(f"{label} string values must use the hex: prefix")
        _parse_hex(raw, label, 16)
        return SecretSource("inline", raw)
    data = _mapping(raw, label)
    _only_keys(data, {"env", "file", "inline", "prompt"}, label)
    selected = [key for key in ("env", "file", "inline", "prompt") if key in data]
    if len(selected) != 1:
        raise ConfigError(f"{label} must select exactly one of env, file, inline, or prompt")
    kind = selected[0]
    value = data[kind]
    if kind == "prompt":
        if value is not True:
            raise ConfigError(f"{label}.prompt must be true")
        return SecretSource("prompt")
    if not isinstance(value, str) or not value.strip():
        raise ConfigError(f"{label}.{kind} must be a non-empty string")
    locator = value.strip()
    if kind == "inline":
        _parse_hex(locator, label, 16)
    if kind == "file" and base_directory is not None:
        path = Path(locator).expanduser()
        if not path.is_absolute():
            locator = str((base_directory / path).resolve())
    return SecretSource(kind, locator)


def _parse_invocation_counter(raw: Any, base_directory: Path | None) -> InvocationCounterConfig:
    data = _mapping(raw, "profiles[0].invocation_counter")
    _only_keys(
        data,
        {
            "public_client_address", "class_id", "logical_name", "attribute_id",
            "state_file", "meter_identity", "unsafe_override",
        },
        "profiles[0].invocation_counter",
    )
    logical_name = data.get("logical_name", "0.0.43.1.0.255")
    if not isinstance(logical_name, str) or len(logical_name.split(".")) != 6:
        raise ConfigError("profiles[0].invocation_counter.logical_name must be a six-part logical name")
    state_file = data.get("state_file", "~/.local/state/dlms-enum/invocation-counters.json")
    if not isinstance(state_file, str) or not state_file.strip():
        raise ConfigError("profiles[0].invocation_counter.state_file must be a non-empty path")
    state_path = Path(state_file.strip()).expanduser()
    if base_directory is not None and not state_path.is_absolute() and state_file != "~/.local/state/dlms-enum/invocation-counters.json":
        state_path = (base_directory / state_path).resolve()
    meter_identity = data.get("meter_identity")
    if meter_identity is not None and (not isinstance(meter_identity, str) or not meter_identity.strip()):
        raise ConfigError("profiles[0].invocation_counter.meter_identity must be a non-empty string")
    unsafe_override = data.get("unsafe_override")
    if unsafe_override is not None:
        unsafe_override = _integer(unsafe_override, "profiles[0].invocation_counter.unsafe_override", 1, 0xFFFFFFFF)
    return InvocationCounterConfig(
        public_client_address=_integer(
            data.get("public_client_address", 16), "profiles[0].invocation_counter.public_client_address", 1, 0x3FFF
        ),
        class_id=_integer(data.get("class_id", 1), "profiles[0].invocation_counter.class_id", 1, 0xFFFF),
        logical_name=logical_name,
        attribute_id=_integer(data.get("attribute_id", 2), "profiles[0].invocation_counter.attribute_id", 1, 0xFF),
        state_file=str(state_path),
        meter_identity=meter_identity.strip() if meter_identity else None,
        unsafe_override=unsafe_override,
    )


def _parse_profile(raw: Any, base_directory: Path | None) -> tuple[ProfileConfig, tuple[str, ...]]:
    if raw is None:
        profiles = [{}]
    elif isinstance(raw, list):
        profiles = raw
    else:
        raise ConfigError("profiles must be a list")
    if len(profiles) != 1:
        raise ConfigError("this release requires exactly one public profile or one hls_gmac_suite0 profile")
    data = _mapping(profiles[0], "profiles[0]")
    _only_keys(
        data,
        {
            "name", "client_address", "client_system_title", "secrets", "server",
            "authentication", "security", "proposed_max_pdu_size", "hdlc", "invocation_counter",
        },
        "profiles[0]",
    )
    name = data.get("name", "public")
    if name not in ("public", SECURE_PROFILE_NAME):
        raise ConfigError("profiles[0].name must be public or hls_gmac_suite0")
    logical, physical, address_size = _parse_server_and_hdlc(data, secure=name == SECURE_PROFILE_NAME)
    max_pdu = _integer(
        data.get("proposed_max_pdu_size", 0xFFFF), "profiles[0].proposed_max_pdu_size", 64, 0xFFFF
    )
    if name == "public":
        auth = _mapping(data.get("authentication"), "profiles[0].authentication")
        if auth.get("mechanism", "none") != "none" or set(auth) - {"mechanism"}:
            raise ConfigError("the public profile must use authentication.mechanism: none")
        security = _mapping(data.get("security"), "profiles[0].security")
        if security.get("policy", "none") != "none" or set(security) - {"policy"}:
            raise ConfigError("the public profile must use security.policy: none")
        if "client_system_title" in data or "secrets" in data or "invocation_counter" in data:
            raise ConfigError("secure credentials and invocation-counter settings require hls_gmac_suite0")
        return (
            PublicProfile(
                client_address=_integer(data.get("client_address", 16), "profiles[0].client_address", 1, 0x3FFF),
                server_logical_address=logical,
                server_physical_address=physical,
                server_address_size=address_size,
                proposed_max_pdu_size=max_pdu,
            ),
            (),
        )

    auth = _mapping(data.get("authentication"), "profiles[0].authentication")
    if auth and (auth.get("mechanism") != "high_gmac" or set(auth) - {"mechanism"}):
        raise ConfigError("hls_gmac_suite0 implies authentication.mechanism: high_gmac")
    security = _mapping(data.get("security"), "profiles[0].security")
    if security:
        _only_keys(security, {"suite", "policy"}, "profiles[0].security")
        if security.get("suite", 0) != 0 or security.get("policy", "authentication_encryption") != "authentication_encryption":
            raise ConfigError("hls_gmac_suite0 requires suite 0 and authentication_encryption")
    system_title = _parse_hex(data.get("client_system_title"), "profiles[0].client_system_title", 8)
    secrets = _mapping(data.get("secrets"), "profiles[0].secrets")
    _only_keys(secrets, {"gak", "guek"}, "profiles[0].secrets")
    if "gak" not in secrets or "guek" not in secrets:
        raise ConfigError("profiles[0].secrets must define both gak and guek")
    gak = _parse_secret_source(secrets["gak"], "profiles[0].secrets.gak", base_directory)
    guek = _parse_secret_source(secrets["guek"], "profiles[0].secrets.guek", base_directory)
    warnings: list[str] = []
    if gak.kind == "inline" or guek.kind == "inline":
        warnings.append("Inline GAK/GUEK values are for laboratory use only and will be redacted from all output.")
    return (
        SecureProfile(
            name=SECURE_PROFILE_NAME,
            client_address=_integer(data.get("client_address", 1), "profiles[0].client_address", 1, 0x3FFF),
            client_system_title=system_title,
            secrets=SecureSecrets(gak=gak, guek=guek),
            server_logical_address=logical,
            server_physical_address=physical,
            server_address_size=address_size,
            proposed_max_pdu_size=max_pdu,
            invocation_counter=_parse_invocation_counter(data.get("invocation_counter"), base_directory),
        ),
        tuple(warnings),
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
    if data.get("redact_secrets", True) is not True:
        raise ConfigError("output.redact_secrets must remain true")
    return OutputConfig(**values, redact_secrets=True)


def parse_config(data: Any, *, base_directory: str | Path | None = None) -> AppConfig:
    root = _mapping(data, "configuration")
    _only_keys(root, {"version", "transport", "scan", "profiles", "output"}, "configuration")
    profile, warnings = _parse_profile(
        root.get("profiles"), Path(base_directory) if base_directory is not None else None
    )
    return AppConfig(
        version=_integer(root.get("version", 1), "version", 1, 1),
        transport=_parse_transport(root.get("transport")),
        scan=_parse_scan(root.get("scan")),
        profile=profile,
        output=_parse_output(root.get("output")),
        warnings=warnings,
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
        mark = getattr(exc, "problem_mark", None)
        location = f" at line {mark.line + 1}, column {mark.column + 1}" if mark else ""
        raise ConfigError(f"invalid YAML in {config_path}{location}") from None
    return parse_config(raw, base_directory=config_path.parent.resolve())


def _decode_secret_text(value: str, label: str) -> bytes:
    candidate = value.strip()
    if candidate.lower().startswith("hex:"):
        candidate = candidate[4:]
    if len(candidate) != 32:
        raise ConfigError(f"{label} must decode to exactly 16 bytes")
    try:
        result = bytes.fromhex(candidate)
    except ValueError as exc:
        raise ConfigError(f"{label} must contain exactly 32 hexadecimal characters") from exc
    if len(result) != 16:
        raise ConfigError(f"{label} must decode to exactly 16 bytes")
    return result


def resolve_secret(
    source: SecretSource,
    label: str,
    *,
    environ: Mapping[str, str] | None = None,
    prompt: Callable[[str], str] | None = None,
) -> bytes:
    """Resolve one AES-128 key without including its value in any exception."""

    environ = os.environ if environ is None else environ
    try:
        if source.kind == "env":
            value = environ.get(str(source.locator))
            if value is None:
                raise ConfigError(f"{label} environment variable is not set")
        elif source.kind == "file":
            path = Path(str(source.locator)).expanduser()
            info = path.stat()
            if os.name != "nt" and stat.S_IMODE(info.st_mode) & 0o077:
                raise ConfigError(f"{label} file permissions are too broad; require mode 0600 or stricter")
            value = path.read_text(encoding="utf-8")
        elif source.kind == "inline":
            value = str(source.locator)
        elif source.kind == "prompt":
            reader = prompt or (lambda message: getpass.getpass(message))
            value = reader(f"{label} (32 hexadecimal characters): ")
        else:
            raise ConfigError(f"{label} uses an unsupported secret source")
        return _decode_secret_text(value, label)
    except ConfigError:
        raise
    except OSError as exc:
        raise ConfigError(f"cannot resolve {label} from its protected file: {type(exc).__name__}") from None
    except Exception as exc:
        raise ConfigError(f"cannot resolve {label}: {type(exc).__name__}") from None


def resolve_secure_keys(profile: SecureProfile) -> tuple[bytes, bytes]:
    return (
        resolve_secret(profile.secrets.gak, "GAK"),
        resolve_secret(profile.secrets.guek, "GUEK"),
    )


def dump_config(config: AppConfig, path: str | Path) -> None:
    try:
        import yaml
    except ModuleNotFoundError as exc:
        raise RuntimeError("PyYAML is required to save configuration files") from exc
    data = config.redacted_dict()
    if isinstance(config.profile, SecureProfile):
        def serializable_source(source: SecretSource) -> dict[str, Any]:
            if source.kind == "env":
                return {"env": source.locator}
            if source.kind == "file":
                return {"file": source.locator}
            # Never write inline key material back to disk. A subsequently
            # loaded saved configuration will ask for it with masked input.
            return {"prompt": True}

        data["profiles"][0]["secrets"] = {
            "gak": serializable_source(config.profile.secrets.gak),
            "guek": serializable_source(config.profile.secrets.guek),
        }
    Path(path).write_text(yaml.safe_dump(data, sort_keys=False), encoding="utf-8")
