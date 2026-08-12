# DLMS Smart Meter Enumeration Tool

`dlms-enum` performs authorized, read-only DLMS/COSEM discovery over direct serial HDLC. It supports either an unauthenticated public association or an HLS-GMAC Security Suite 0 association with authenticated-and-encrypted xDLMS traffic. Both profiles use logical-name referencing, read the Association LN object list, supplement it with a conservative OBIS catalogue, perform GET operations only, and write a canonical JSON report plus side-by-side JSONL traffic.

The secure profile uses Gurux DLMS 1.0.201 for HLS-GMAC and AES-GCM. It does not implement cryptography itself. No SET, arbitrary ACTION, key transfer, key rotation, password authentication, manufacturer catalogue, or fuzzing is available. The sole ACTION allowed is Association LN method 1, which is required to complete HLS authentication.

## Install and run

Python 3.11 or newer is required.

```shell
python -m venv .venv
. .venv/bin/activate
python -m pip install -e .
```

Public scan:

```shell
cp examples/public-meter.yaml meter-public.yaml
python -m dlms_enum validate-config meter-public.yaml
python -m dlms_enum scan --config meter-public.yaml
```

Secure scan:

```shell
cp examples/hls-gmac-suite0-meter.yaml meter-secure.yaml
export DLMS_GAK='hex:00000000000000000000000000000000'   # replace with provisioned GAK
export DLMS_GUEK='hex:00000000000000000000000000000000'  # replace with provisioned GUEK
python -m dlms_enum validate-config meter-secure.yaml
python -m dlms_enum scan --config meter-secure.yaml
```

Do not use the placeholder keys shown above. The client system title in the example is also a placeholder and must be replaced with the eight-byte value provisioned for that client.

Guided setup is available with `python -m dlms_enum scan`. Secure keys entered there are masked. If that configuration is saved, inline key values are replaced with masked interactive prompts rather than written to disk.

## Minimal HLS-GMAC Security Suite 0 configuration

```yaml
version: 1

transport:
  device: /dev/ttyUSB0
  baudrate: auto

profiles:
  - name: hls_gmac_suite0
    client_address: 1
    client_system_title: "hex:0011223344556677"
    secrets:
      gak:
        env: DLMS_GAK
      guek:
        env: DLMS_GUEK
```

The secure profile name fixes the following behavior:

- logical-name referencing;
- `Authentication.HIGH_GMAC`;
- `SecuritySuite.SUITE_0`;
- `Security.AUTHENTICATION_ENCRYPTION`;
- AES-GCM with 128-bit GAK and GUEK values;
- public bootstrap client SAP 16;
- invocation-counter Data object `0.0.43.1.0.255`, class 1, attribute 2;
- automatic baud and one-byte/two-byte HDLC server-address discovery;
- protected GET requests and responses after HLS succeeds.

Credential meanings:

- `client_address` is the authenticated client SAP assigned by the meter's access-control configuration.
- `client_system_title` is the exact eight-byte client identity provisioned with that SAP. It is an identifier, not a secret key.
- GAK is the 16-byte Global Authentication Key used to authenticate protected APDUs.
- GUEK is the 16-byte Global Unicast Encryption Key used to encrypt protected APDUs.

## Secret input and redaction

Each GAK/GUEK source can use one of these forms:

```yaml
secrets:
  gak: {env: DLMS_GAK}
  guek: {file: /secure/path/guek.hex}
```

```yaml
secrets:
  gak: {prompt: true}
  guek: {prompt: true}
```

Environment variables, protected files, and prompts accept 32 hexadecimal characters, optionally prefixed with `hex:`. Secret files must have mode `0600` or stricter on Unix. Inline `hex:` values are supported for isolated laboratory work, but produce a warning and are never copied to effective configuration, reports, traffic logs, saved configurations, exception messages, or dataclass repr output.

Raw wire logging contains ciphertext, protocol identifiers, system titles, and the ephemeral authentication value carried by AARQ because those bytes are part of the requested on-wire capture. Decoded challenge fields are redacted. GAK and GUEK are never transmitted and are never serialized.

## Secure connection flow

The implementation performs endpoint discovery before constructing any ciphered client:

1. Open HDLC with public client SAP 16 and establish a public association.
2. Read the public logical-device identity and invocation-counter object.
3. Release the public application association, disconnect HDLC, and close serial media.
4. Lock the persistent counter record and choose a counter strictly greater than the meter value.
5. Open a fresh HDLC link with the authenticated client SAP.
6. Send an AARQ containing `glo-initiate-request` (`21`) using HIGH_GMAC, Suite 0, and authentication plus encryption.
7. Parse AARE, authenticate/decrypt `glo-initiate-response` (`28`), and obtain the server system title.
8. Generate the Association LN authentication ACTION with Gurux; transmit `glo-action-request` (`CB`).
9. Authenticate/decrypt `glo-action-response` (`CF`) and validate it with `parseApplicationAssociationResponse`.
10. Only after HLS validation, send `glo-get-request` (`C8`) and accept authenticated/decrypted `glo-get-response` (`CC`).
11. Attempt protected `RLRQ → RLRE`, then `DISC → UA`, and close serial media.

The secure session refuses an LLC-wrapped plaintext `C0` GET before it can be sent. This prevents the regression where a structurally successful HLS exchange is followed by plaintext GETs and meter exception `D8 01 01`.

## Invocation-counter safety and recovery

Client invocation-counter reuse with the same key and system title is cryptographically unsafe. The default state file is:

```text
~/.local/state/dlms-enum/invocation-counters.json
```

State is keyed by the public meter identity, server address, authenticated client address, and client system title. The file is process-locked for the complete secure session. Updates use a same-directory temporary file, `fsync`, and atomic replacement. Gurux increments counters while generating protected APDUs; `dlms-enum` persists the resulting next unused counter before calling the serial-media send operation. A timeout, partial send, rejected APDU, retry, failed HLS exchange, protected release, or process crash after persistence therefore consumes rather than reuses counters.

On restart, the tool uses the greater safe value and never rolls state backward. If persisted state is lower than the meter-reported counter, the run is refused instead of silently repairing ambiguous state. Do not delete or copy an old state file back into place.

If the public counter read fails, the default is a hard failure. An expert who has independently established a safe next value can use the explicit advanced override:

```yaml
invocation_counter:
  unsafe_override: 2286331232
```

This bypass is deliberately named `unsafe_override`. It is not automatic recovery, and choosing a reused or stale value can compromise AES-GCM security and cause meter rejection. A public meter identity is still required unless `invocation_counter.meter_identity` is explicitly provisioned.

Advanced counter and endpoint settings are available when meter defaults differ:

```yaml
profiles:
  - name: hls_gmac_suite0
    client_address: 1
    client_system_title: "hex:0011223344556677"
    secrets:
      gak: {env: DLMS_GAK}
      guek: {env: DLMS_GUEK}
    server:
      logical_address: 0
      physical_address: 1
    hdlc:
      address_size: 1       # auto, 1, 2, or 4
    proposed_max_pdu_size: 65535
    invocation_counter:
      public_client_address: 16
      class_id: 1
      logical_name: 0.0.43.1.0.255
      attribute_id: 2
      state_file: ~/.local/state/dlms-enum/invocation-counters.json
      meter_identity: null  # optional explicit identity if public identity GET is unavailable
```

Serial framing, response timeout, inter-request delay, and session guard remain transport-level overrides; see `examples/public-meter.yaml` for their complete form.

## Outputs

Each run gets a UTC-named directory under `./runs` unless overridden:

- `report.json` contains the selected endpoint, addressing type, redacted effective configuration, association/HLS outcome, public counter bootstrap, discovered objects, decoded values, GET outcomes, cleanup warnings, and a traffic-file hash.
- `summary.md` is the compact human-readable report. It contains connection and role details followed by a table of each scanned OBIS attribute, its decoded value, hexadecimal/raw numeric representation, and result. Large structured values are shortened only in this Markdown view.
- `traffic.jsonl` contains the profile name, phase, addresses, authentication/security metadata, client/server system titles when known, raw TX/RX frames, protected command names, outgoing invocation counters, Gurux-decoded response values, result category, timing, and redaction indicators.

GET uses at most two attempts. Explicit DLMS errors such as access denied are not retried. Timeouts, transport failures, and malformed responses can receive one retry; each protected retry gets a new persisted invocation counter.

### Terminal progress and secure-status messages

During a scan, the terminal uses one Rich progress display rather than printing every request on a new line. Once the Association View is known, it shows the completed/total readable attributes and replaces the current action in place, for example `GET 1.0.1.8.0.255 class 3 attribute 2 attempt 1`.

Gurux internally labels Suite 0 security-control bit `0x20` as “Encryption is applied” and bit `0x10` as “Authentication is applied.” Together they form the configured `0x30` authentication-and-encryption policy. Those repeated low-level diagnostics are suppressed. They did not indicate two additional operations: encryption protects confidentiality, while authentication is the AES-GCM integrity/authenticity tag. A successfully decoded protected response means Gurux verified that tag; tag failure is reported as a scan error.

## Troubleshooting

- **Persisted counter below meter value:** verify that the configured client system title, authenticated SAP, meter, and state file belong together. Restore a known newer state only if its provenance is certain; otherwise reprovision keys/system title according to the meter vendor's process.
- **Public counter read fails:** confirm public client SAP 16, invocation-counter OBIS/class/attribute, and public access rights. Use `unsafe_override` only with a separately verified safe value.
- **HLS rejected:** check the authenticated client SAP, exact client system title, GAK, GUEK, and the meter's assigned Security Suite. HLS completion is mandatory; no GET is attempted after failure.
- **Authentication-tag failure:** usually indicates a wrong GAK/GUEK, wrong system title, wrong server identity, damaged frames, or counter mismatch. The tool does not fall back to plaintext.
- **Access denied after successful HLS:** the association is valid, but that authenticated role lacks read access to the requested object/attribute. The tool records the DLMS error and does not attempt SET/ACTION workarounds.
- **No endpoint found:** confirm serial permissions and wiring. Automatic discovery tries 9600 first, then configured candidates, and tests common one-byte and two-byte server addressing with public communication only.
- **Protected release rejected:** some meters do not accept a protected release in the negotiated context. The warning is recorded and HDLC DISC is still attempted; it does not hide an earlier scan error.

## Development and limitations

```shell
python -m unittest discover -s tests -v
python -m dlms_enum validate-config examples/public-meter.yaml
python -m dlms_enum validate-config examples/hls-gmac-suite0-meter.yaml
```

Protocol tests use fakes, the real Gurux request generator, and sanitized structural expectations derived from the supplied captures; they need no physical meter and embed no keys. Live validation is still required for the target meter, particularly its role provisioning, counter object access, server system title, association-view size, and protected-release behavior.

This release accepts exactly one scan profile per run: either `public` or `hls_gmac_suite0`. Running both profiles together without duplicate public discovery is deferred. Security Suites 1/2, dedicated keys, signing, key agreement, key management, and arbitrary ACTION/SET services are intentionally unsupported.
