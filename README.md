# DLMS Smart Meter Vulnerability Scanner and Fuzzer

`dlms-enum` is a DLMS/COSEM vulnerability scanner and fuzzer in active development, operating over direct serial HDLC. The completed first phase built and validated the reconnaissance and access engine: reliable serial-HDLC DLMS interaction and authenticated access through unauthenticated public associations, password-authenticated LLS associations, and HLS-GMAC Security Suite 0 associations with authenticated-and-encrypted xDLMS traffic. All profiles use logical-name referencing, read the Association LN object list, supplement it with a conservative OBIS catalogue, and write a canonical JSON report plus side-by-side JSONL traffic. Secure scans can additionally retest authenticated-only targets through the public client to identify unadvertised public access. Later phases add active vulnerability tests and protocol fuzzing on top of this engine; see [plan.md](plan.md).

Logical-name attribute 1 is not read or emitted as a separate result because it duplicates the OBIS logical name already stored on every object record.

The LLS and secure profiles use Gurux DLMS for authentication; the secure profile also uses Gurux for HLS-GMAC and AES-GCM. The tool does not implement cryptography itself. Association View access rights for SET and ACTION are reported passively. In the current enumeration phase, a run transmits only GET requests, plus the mandatory Association LN method 1 ACTION required to complete configured HLS authentication and the opt-in invocation-counter replay diagnostic. No modifying SET, arbitrary ACTION, key transfer, or key rotation is transmitted in this phase. Active vulnerability modules — transmitted SET/ACTION verification, credential-policy testing, and protocol fuzzing — are roadmap items tracked in [plan.md](plan.md).

## Install and run

Python 3.11 or newer is required.

To create a configuration with a small standalone form, open
[`tools/config-generator.html`](tools/config-generator.html) in a browser. It
runs entirely in the browser, has no dependencies, and can copy or download a
YAML file. Environment-variable credential references are selected by default;
inline credentials are intended only for controlled laboratory use.

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

LLS password scan:

```shell
cp examples/lls-meter.yaml meter-lls.yaml
export DLMS_LLS_PASSWORD='replace-with-the-provisioned-password'
python -m dlms_enum validate-config meter-lls.yaml
python -m dlms_enum scan --config meter-lls.yaml
```

The LLS password may instead be written inline as `password: {inline: "..."}`
or `password: "..."`. Prefix a binary password with `hex:`. Inline passwords
are accepted for laboratory configurations, are redacted from effective
configuration and reports, and are replaced with an environment reference if
the configuration is re-saved. The raw credential-bearing LLS AARQ is omitted
from `traffic.jsonl`; its decoded XML remains available with the authentication
value redacted.

Authentication-mechanism scan:

```shell
export DLMS_PASSWORD='replace-with-the-provisioned-password'
export DLMS_GAK='00112233445566778899AABBCCDDEEFF'
export DLMS_GUEK='FFEEDDCCBBAA99887766554433221100'
dlms-enum scan --config examples/authentication-enumeration.yaml
```

`authentication_scan` is an optional top-level final phase, not a profile. The
normal public/LLS/HLS role scans, GET enumeration, optional public cross-profile
tests, and optional invocation-counter replay diagnostic finish first. The tool
then verifies the role's known-working method first (NONE for public, LOW for
LLS, and HIGH-GMAC for secure roles), followed by the other methods in fresh
associations. The existing `transport.session_guard_ms` delay applies when each
association closes; there is no separate authentication cooldown. Between
mechanisms, the tool reopens the role's known-good association. If that check
fails, later mechanisms are not tested because their rejection would be
ambiguous. If the first check contradicts the association that just worked, the
result is explicitly marked `inconsistent_with_known_good`, not simply rejected.
The configured password is shared by the password probes; each secure role keeps
its own system title, keys, and counter state. HIGH-GMAC is reported as a
prerequisite failure for roles without
those secure credentials. Results distinguish an AARQ rejection from a completed
HLS challenge. Immediately before HIGH-GMAC, the tool refreshes that role's
public invocation-counter object. If the meter rejects the first secure AARQ,
the tool refreshes the counter again and makes one monotonic retry; an accepted
AARQ with a failed HLS challenge is not retried. HIGH-ECDSA is listed as
unsupported because this release has no
signing-key/certificate credential support. A rejected mechanism does not stop
the remaining probes while the intervening known-good connection still works.

Every intervening HIGH-GMAC health check first rereads the public invocation
counter, combines it with the crash-safe persisted client state, and leases the
next strictly monotonic counter before generating protected messages. Health
checks therefore consume counters normally and never reuse or roll back a
counter. Their results and counter-refresh evidence are included in the
authentication report.

### Standalone public connection discovery

If the serial-HDLC connection parameters are unknown, run the separate
reconnaissance discovery tool with only the device path:

```shell
dlms-autodiscover /dev/ttyUSB0
```

It can also be started directly from the source tree after installing the
project:

```shell
python scripts/dlms_autodiscover.py /dev/ttyUSB0
```

The default sweep tries common baud rates using 8N1, public client SAP 16,
one-byte server addresses and two-byte server addresses with physical values
0 through 31. It prioritizes common server forms, including logical address 1
with physical address 17 (combined server address 145). If an HDLC endpoint
answers but rejects SAP 16, the tool tries a bounded list of alternative public
client SAPs on that proven endpoint. Use `--deep` to expand physical addresses
through 127, or use `--clients`, `--logical-addresses`, `--physical-range`,
`--baud-rates`, and the serial-format options to override the bounded defaults.
Common endpoints are tried first; exhausting the complete default or deep
scope can take several minutes because every silent address must time out.

Each run writes `discovery.json`, complete `traffic.jsonl` evidence, and—after
a successful association—`suggested-public-meter.yaml` under
`./discovery-runs/<timestamp>/`. The report includes the confirmed baud rate,
serial format, client and server addresses, address encoding, negotiated DLMS
version, Association LN version, conformance, PDU and HDLC limits, logical
device name, public-readable invocation-counter candidates, and server/client
system titles when the public AARE or a readable Security Setup object exposes
them.

System-title retrieval first checks the public AARE and Association
View-advertised Security Setup objects. If no server title is found, it also
sends bounded public GETs for attribute 5 of common class-64 logical names
`0.0.43.0.0.255` through `0.0.43.0.15.255`. This can find a Security Setup
object that is addressable but omitted from the public Association View.
Explicit access denials are retained as negative evidence; two consecutive
timeouts stop the direct sweep. Use `--security-setup-range MIN-MAX` to adjust
the instances or `--no-direct-system-title-probes` to disable these extra GETs.
Any returned value must be exactly eight octets and is reported as a verified
public read—the tool does not manufacture or guess a title from the meter
serial number.

Discovery uses logical-name referencing over direct serial HDLC and transmits
only SNRM, unauthenticated AARQ, public GET, RLRQ, and DISC. It does not try
credentials, protected associations, SET, or arbitrary ACTION requests. A
secure client's SAP, system title, keys, security suite and invocation-counter
mapping are provisioned role data and cannot in general be inferred from the
public profile. IEC 62056-21 optical sign-on, WRAPPER/TCP, PLC and HDLC-over-IP
are outside this script's scope.

At startup, interactive runs list all configured roles and select all of them by default. A mandatory public preflight then discovers the working serial interface, baud rate, server address, public Association View and meter identity, reports negotiated capabilities, and validates readable invocation-counter candidates before the final READ-only plan is confirmed. The same role and scope choices can be supplied without prompts:

```shell
python -m dlms_enum scan --config meter-public.yaml --short
python -m dlms_enum scan --config meter-public.yaml --full
python -m dlms_enum scan --config meter-public.yaml --get-limit 100
python -m dlms_enum scan --config meter-profiles.yaml --roles public,client1 --get-limit 100
python -m dlms_enum scan --config meter-profiles.yaml --association-view-mode reuse
python -m dlms_enum scan --config meter-profiles.yaml --association-view-mode compare
python -m dlms_enum scan --config meter-profiles.yaml --system-title-listen-seconds 60
```

`--system-title-listen-seconds 60` adds a passive phase after the public
preflight has confirmed the baud rate and HDLC server address. During that
window the tool sends nothing. It recognizes complete HDLC AARE and
`GeneralGloCiphering` frames and records an exposed eight-byte sender system
title without trying to decrypt the protected service. HDLC source and target
addresses are used to label a title as server or client when possible. A title
that is not exactly eight octets is ignored. On a point-to-point optical link,
traffic from another client is visible only when the capture setup can observe
that traffic.

`--get-limit 100` tests exactly 100 mapped GET capabilities while retaining every other GET, SET, and ACTION capability in the report as `NOT_TESTED`. Association and authentication metadata are prioritized, and—when advertised and the budget permits—one likely event-log Profile Generic buffer is reserved within that same budget so block-transfer decoding and row rendering are exercised without selecting every potentially large profile. In a secure scan, the same limit also caps the optional cross-profile public GET test. For unattended configuration-driven runs, use `scan.get_limit: 100`; the older object-based short scope remains available as `scan.object_limit: 10`. The two limits are mutually exclusive. If neither limit nor a command-line switch is supplied and standard input is not an interactive terminal, the default remains a full scan.

When the public preflight reports the negotiated `multiple_references` conformance bit, an interactive run offers GET-with-list batching. The operator chooses a maximum from 1 through 10 attributes; the effective size is additionally reduced to fit the negotiated PDU. Scaler and unit attributes remain ahead of their value attribute. If a list request is rejected, malformed, or contains an item error, the whole list is retried as individual GETs so every attribute keeps an independent outcome. For unattended runs, set `scan.batch_size`; its safe default is `1` (disabled).

Every successful role scan exports `association-view.json`, containing object
identities, interface versions, and advertised attribute/method rights. It does
not contain read values or credentials. Interactive setup can save this view in
the local state directory, keyed separately by serial device and role. On a
later run choose `reuse` to skip the potentially long, multi-block Association
View download, `live` to read it normally, or `compare` to read it and report
added, removed, and access-changed objects. For unattended runs use
`--association-view-mode live|reuse|compare`; add `--save-association-view` to
update the reusable snapshot after a live read. A reused view is inventory
metadata, so its Association LN object-list GET is reported as `NOT_TESTED`, not
as a new meter response.

When both a public role and one or more authenticated roles are scanned, the
tool also writes `capability-comparison.json` and `capability-comparison.md`.
These files compare the advertised GET, SET, and ACTION permissions for the
same objects and members. Direct GET results from the optional public
cross-profile check are attached as separate evidence. The comparison never
sends SET or ACTION requests, so an advertised permission is not presented as
proof that a modifying operation would succeed.

Security Setup and Image Transfer objects receive a separate read-only posture
summary. It shows the values that were safely read, lists advertised
permissions, and highlights security, key, certificate, or firmware-update
controls that the public role can apparently modify. This is passive reporting:
the tool does not try those modifying operations.

Known targets that are absent from the Association View can be tested through
bounded candidate providers:

```yaml
scan:
  common_catalogue: true
  candidate_providers: [common, security, firmware]
  candidate_limit: 100
  get_limit: 500
```

`common` contains the existing standard OBIS catalogue. `security` adds a
small set of Security Setup targets and `firmware` adds the standard Image
Transfer target. Generation is deterministic, duplicate requests are removed,
and `candidate_limit` caps the total number of generated GET targets. Exact
vendor targets can be supplied without creating an unbounded address sweep:

```yaml
scan:
  candidate_providers: [common]
  candidate_limit: 40
  candidate_objects:
    - class_id: 99
      logical_name: 0.0.128.0.0.255
      attributes: [2, 3]
      description: Vendor status
```

Reports retain each candidate's provider, rule, and confidence. A definite
DLMS rejection is expected negative evidence: it does not turn an otherwise
successful run into `completed_with_errors`. Timeouts, transport failures, and
malformed responses remain inconclusive or erroneous. Generated candidates are
never described as Association View-advertised Security Setup or Image Transfer
objects, even when a direct GET verifies that one exists.

Secure scan:

```shell
cp examples/hls-gmac-suite0-meter.yaml meter-secure.yaml
export C4_GAK='hex:00000000000000000000000000000000'   # replace with provisioned GAK
export C4_GUEK='hex:00000000000000000000000000000000'  # replace with provisioned GUEK
python -m dlms_enum validate-config meter-secure.yaml
python -m dlms_enum scan --config meter-secure.yaml
```

This example configures the mandatory public preflight role plus secure role `c4` at client SAP 4. Do not use the placeholder keys shown above. The client system title in the example is also a placeholder and must be replaced with the eight-byte value provisioned for that client.

Guided setup is available with `python -m dlms_enum scan`. During initial setup,
the tool asks whether to append the authentication matrix and, when enabled, for
the password environment-variable name. The LLS setup separately asks for its
normal association password variable. Secure keys entered there are masked. If
that configuration is saved, inline key values are replaced with masked
interactive prompts rather than written to disk.

## Authentication enumeration

Every successful role scan reports two kinds of authentication evidence:

- `active_verification` records the mechanism and client SAP that actually established the current association (`none`, `low`, or `high_gmac` in this release).
- `advertised_associations` decodes attributes 3 and 6 of every readable Association LN object: associated client/server SAPs and the authentication-mechanism OID. Mechanism IDs 0 through 7 are named as none, low, high, high-MD5, high-SHA1, high-GMAC, high-SHA256, and high-ECDSA.

Association metadata GETs are prioritized early in the scan. The passive result
is intentionally marked incomplete because a meter can hide other Association LN
objects from the current client. When the final authentication scan is enabled,
the tool actively probes the selected configured client SAPs only. It does not
guess passwords or sweep unconfigured client addresses.

## Multiple roles and public preflight

Use `role` to give each configured client a unique operator-facing name. `name` continues to select the implemented protocol profile:

```yaml
version: 1

transport:
  device: /dev/ttyUSB0

profiles:
  - name: public
    role: public

  - name: lls
    role: meter_reader
    client_address: 32
    public_client_address: 16
    authentication:
      mechanism: low
      password: {env: DLMS_LLS_PASSWORD}

  - name: hls_gmac_suite0
    role: client1
    client_address: 1
    client_system_title: "hex:0011223344556677"
    secrets:
      gak: {env: CLIENT1_GAK}
      guek: {env: CLIENT1_GUEK}

  - name: hls_gmac_suite0
    role: client2
    client_address: 4
    client_system_title: "hex:1122334455667788"
    secrets:
      gak: {env: CLIENT2_GAK}
      guek: {env: CLIENT2_GUEK}
    invocation_counter:
      logical_name: 0.0.43.1.1.255
```

The public preflight always runs, even when the public role is not selected for a full scan. For every selected secure role, the operator sees its SAP and system title together with a numbered list of validated public-readable unsigned counter candidates and their decoded current values. A single prompt accepts either a displayed row number or an arbitrary six-part counter-object logical name, then asks for confirmation. An unlisted logical name is clearly marked as operator-supplied and is attempted with a direct public read before secure association. The chosen mapping affects only the runtime configuration; the source YAML is not rewritten. Immediately before the secure association, the counter is read again and combined with crash-safe local state as described below.

After confirming each secure role's counter source, an interactive run optionally offers a two-request invocation-counter reuse diagnostic (default: no). This laboratory check runs after the other scan tests and replays `0x00000000` plus the first counter actually transmitted in that secure session against a small Association LN GET. If that first counter is also zero, the second transmitted counter is used instead. After a rejected replay, the tool sends one protected GET with the next persisted safe counter on the existing association. If that recovery GET fails, it attempts a protected release, always sends HDLC DISC, resets all local HDLC state, and reconnects with a fresh Gurux client. A meter-side AARQ rejection is retried once after `invocation_counter.recovery_wait_ms` (default: 60000 ms); a meter-specific reset or administrative unlock is never attempted automatically. The persistent counter is never rolled back. Any accepted replay is reported explicitly; timeouts and protocol errors retain their individual outcomes.

With multiple selected roles, each role receives its own subdirectory and canonical report. The parent directory contains `workflow.json` and the public `preflight-traffic.jsonl`. A single selected role retains the existing flat output layout.

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
- a 60000 ms one-time recovery wait if the meter rejects the post-replay secure AARQ;
- automatic baud and one-byte/two-byte HDLC server-address discovery;
- protected GET requests and responses after HLS succeeds.

### Public cross-profile access test

Enable the additional read-only access-control check in a secure configuration:

```yaml
scan:
  union_profile_test: true
```

The bootstrap public association first supplies its Association View. After the authenticated scan is complete and its protected association is closed, the tool opens a fresh public association and directly addresses each authenticated-readable `(class_id, logical_name, attribute_id)` target that was not advertised as publicly readable. Common-catalogue guesses are excluded: candidates must come from the authenticated Association View.

A successful public GET is reported as `UNEXPECTED_PUBLIC_ACCESS`. An explicit DLMS error is `PUBLIC_ACCESS_REJECTED`; a timeout, transport failure, or malformed response is `INCONCLUSIVE`. SET and arbitrary ACTION are never attempted. These cross-profile probes have their own counts. `object_limit` applies only to the primary authenticated scan, while `get_limit` also caps the number of cross-profile probes.

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

Environment variables, protected files, and prompts accept 32 hexadecimal characters, optionally prefixed with `hex:`. Secret files must have mode `0600` or stricter on Unix. Inline `hex:` values are supported for isolated laboratory work, but produce a warning and are never copied into the effective configuration, a saved configuration, exception messages, or dataclass repr output.

Secret redaction is enabled by default. To retain credential-bearing raw frames and any readable Association secret or user values during an authorized laboratory test, set:

```yaml
output:
  redact_secrets: false
```

This unsafe mode is marked clearly in `summary.md` and every traffic record. It retains the raw LLS AARQ, decoded authentication values, readable Association LN attribute 7, and Association user data. Treat the whole run directory as sensitive. GAK and GUEK are still not serialized because they are client inputs rather than values received from the meter; they are not transmitted by DLMS. With the default `true`, decoded challenge fields are redacted, the raw LLS AARQ is omitted, and a readable Association secret is hashed while its raw response is omitted.

## Secure connection flow

The implementation performs endpoint discovery before constructing any ciphered client:

1. Open HDLC with public client SAP 16 and establish a public association.
2. When `union_profile_test` is enabled, read and retain the public Association View.
3. Read the public logical-device identity and invocation-counter object.
4. Release the public application association, disconnect HDLC, and close serial media.
5. Lock the persistent counter record and choose a counter strictly greater than the meter value.
6. Open a fresh HDLC link with the authenticated client SAP.
7. Send an AARQ containing `glo-initiate-request` (`21`) using HIGH_GMAC, Suite 0, and authentication plus encryption.
8. Parse AARE, authenticate/decrypt `glo-initiate-response` (`28`), and obtain the server system title.
9. Generate the Association LN authentication ACTION with Gurux; transmit `glo-action-request` (`CB`).
10. Authenticate/decrypt `glo-action-response` (`CF`) and validate it with `parseApplicationAssociationResponse`.
11. Only after HLS validation, send `glo-get-request` (`C8`) and accept authenticated/decrypted `glo-get-response` (`CC`).
12. Attempt protected `RLRQ → RLRE`, then `DISC → UA`, and close the secure media.
13. When enabled and additional targets exist, open a fresh public association and issue the cross-profile GET probes.
14. Release the public association, disconnect HDLC, and close serial media.

The secure session refuses an LLC-wrapped plaintext `C0` GET before it can be sent. This prevents the regression where a structurally successful HLS exchange is followed by plaintext GETs and meter exception `D8 01 01`.

## Invocation-counter safety and recovery

Client invocation-counter reuse with the same key and system title is cryptographically unsafe. The default state file is:

```text
~/.local/state/dlms-enum/invocation-counters.json
```

State is keyed by the public meter identity, server address, authenticated client address, and client system title. The file is process-locked for the complete secure session. Updates use a same-directory temporary file, `fsync`, and atomic replacement. Gurux increments counters while generating protected APDUs; `dlms-enum` persists the resulting next unused counter before calling the serial-media send operation. A timeout, partial send, rejected APDU, retry, failed HLS exchange, protected release, or process crash after persistence therefore consumes rather than reuses counters.

On restart, the tool uses the greater safe boundary and never rolls state backward. If persisted state is lower than the meter-reported counter, the tool advances to one greater than the meter value. This safely reconciles counters accepted from another authorized process using the same client identity. Do not delete or copy an old state file back into place.

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

Serial framing, validation response timeout, inter-request delay, and session guard remain transport-level overrides; see `examples/public-meter.yaml` for their complete form. `transport.response_timeout_ms` applies while establishing and validating the association, including the Association View. Once that succeeds, enumeration switches to `scan.enumeration_timeout_ms`, which defaults to 1000 ms. This allows a more tolerant connection timeout such as 3000 ms without paying that delay for every unanswered attribute.

## Outputs

Each run gets a UTC-named directory under `./runs` unless overridden:

- `report.json` contains the selected endpoint, addressing type, safely described effective configuration, active, probed, and Association-LN-advertised authentication mechanisms, structured AARQ/AARE negotiation metadata, Association LN context, selective-access selectors, Profile Generic schemas, engineering and date/time metadata, association/HLS outcome, public counter bootstrap, discovered objects, decoded values, GET outcomes, optional public cross-profile findings, a complete per-role GET/SET/ACTION capability matrix, cleanup warnings, and traffic-file hashes. Each matrix row is `SUCCESS`, a normalized failure category, or `NOT_TESTED`. Readable Association secrets and users are retained when `output.redact_secrets` is explicitly disabled.
- `summary.md` is the human-readable report. It contains connection and role details, proposed-versus-negotiated association values, Association object metadata, selective-access support, engineering metadata, complete date/time flags, Profile Generic schemas and rows, attempted decoded OBIS values with detected wire/interface/UI types, public cross-profile findings, and a compact operation matrix. Per-frame HDLC sequence/FCS, invoke, block-transfer and selector details are shown for a bounded number of frames; complete evidence remains in `traffic.jsonl`. In secure scans, security-control flags and Suites 0–2 are decoded, and general-ciphering envelope fields are shown when present. SET and ACTION are discovered passively and remain `NOT_TESTED` because no modifying request is sent.
- `profile-logs.jsonl` is written when Profile Generic rows were read. It starts each profile with a schema record containing the captured-object definitions and then writes one record per row. Each cell retains its ordered column position, source class/OBIS/attribute/data-index, available type information, decoded value, and raw value. JSONL is the canonical export because profile cells may contain nested DLMS arrays and structures.
- `association-view.json` is the portable per-role inventory snapshot. Profile
  Generic buffers that arrive across multiple DLMS blocks are reassembled before
  reporting; `summary.md` decodes 12-byte COSEM timestamps and renders numeric
  event codes in timestamp/code/description columns while `report.json` retains
  canonical decoded values.
- `capability-comparison.json` and `capability-comparison.md` compare public and
  authenticated advertised permissions when both kinds of role were scanned.
  The Markdown omits repetitive authenticated-only detail; the JSON remains
  complete.
  Each role's `report.json` and `summary.md` also include the passive Security
  Setup/Image Transfer posture and bounded candidate-generation details.
- `traffic.jsonl` contains the profile name, phase, addresses, authentication/security metadata, client/server system titles when known, raw TX/RX frames, searchable HDLC framing/FCS/sequence metadata, invoke ID and priority, service class, block-transfer fields, selective-access parameters, protected command names, security-control flags, outgoing invocation counters, general-ciphering envelope fields, separated ciphertext and authentication-tag evidence, Gurux-decoded response values, result category, timing, and redaction indicators. Each record says whether secrets were redacted. By default, the reusable LLS password is not decoded, its raw AARQ is omitted, and a readable Association LN secret is hashed while its raw response is omitted. Setting `output.redact_secrets: false` retains that raw evidence.
- When passive system-title listening is requested,
  `system-title-discovery.json` records the unique titles and every matching
  observation, while `system-title-traffic.jsonl` retains receive-only raw
  evidence for matching AARE and `GeneralGloCiphering` frames. Unrelated frames
  are not retained because they could include a credential-bearing LLS AARQ.
  These files are also linked from `workflow.json` and each role report.
- When `authentication_scan.enabled` is true, `authentication-report.json`,
  `authentication-summary.md`, and `authentication-traffic.jsonl` are written at
  the run root. The summary and terminal show one role-by-mechanism matrix.

GET uses at most two attempts. Explicit DLMS errors such as access denied are not retried. Timeouts, transport failures, and malformed responses can receive one retry; each protected retry gets a new persisted invocation counter. After two consecutive timeout responses, retries are suppressed while that timeout run continues. After four consecutive timeouts by default, a circuit breaker reads the last successfully read attribute (or the proven Association View if no smaller GET has succeeded). If the health check fails, the scanner drops the link, reconnects once, and checks again. A successful check resets the breaker and resumes scanning; another failure stops that GET phase without sending the remaining requests and reports those operations as `INCONCLUSIVE`. Configure the threshold from 3 through 10 with `scan.timeout_breaker_threshold`.

### Terminal progress and secure-status messages

During a scan, the terminal uses one Rich progress display rather than printing every request on a new line. Once the Association View is known, it shows the completed/total readable attributes and replaces the current action in place, for example `GET 1.0.1.8.0.255 class 3 attribute 2 attempt 1`.

The terminal announces every normal role and its enabled phases. Each completed
role is summarized in a highlighted status panel with endpoint, Association View
source, GET outcomes, passive SET/ACTION findings, Profile Generic row counts,
and artifact paths. The final authentication scan advances one progress line
instead of printing every attempt, then renders a colored combined matrix.

Gurux internally labels Suite 0 security-control bit `0x20` as “Encryption is applied” and bit `0x10` as “Authentication is applied.” Together they form the configured `0x30` authentication-and-encryption policy. Those repeated low-level diagnostics are suppressed. They did not indicate two additional operations: encryption protects confidentiality, while authentication is the AES-GCM integrity/authenticity tag. A successfully decoded protected response means Gurux verified that tag; tag failure is reported as a scan error.

## Troubleshooting

- **Persisted counter below meter value:** the tool advances to `meter + 1` and persists that value before transmission. If this happens unexpectedly, verify that the configured counter object, client system title, authenticated SAP, meter, and state file belong together; another authorized process may be using the same client identity.
- **Public counter read fails:** confirm public client SAP 16, invocation-counter OBIS/class/attribute, and public access rights. Use `unsafe_override` only with a separately verified safe value.
- **HLS rejected:** check the authenticated client SAP, exact client system title, GAK, GUEK, and the meter's assigned Security Suite. HLS completion is mandatory; no GET is attempted after failure.
- **LLS rejected:** check that the configured client SAP selects the intended LLS Association LN and that the environment or inline password has the exact expected byte representation. LLS passwords are case-sensitive; `hex:` values are decoded as bytes rather than sent as ASCII.
- **Authentication-tag failure:** usually indicates a wrong GAK/GUEK, wrong system title, wrong server identity, damaged frames, or counter mismatch. The tool does not fall back to plaintext.
- **Access denied after successful HLS:** the association is valid, but that authenticated role lacks read access to the requested object/attribute. The tool records the DLMS error and does not attempt SET/ACTION workarounds.
- **No endpoint found:** confirm serial permissions and wiring. Automatic discovery tries 9600 first, then configured candidates, and tests common one-byte and two-byte server addressing with public communication only.
- **Protected release rejected:** some meters do not accept a protected release in the negotiated context. The warning is recorded and HDLC DISC is still attempted; it does not hide an earlier scan error.

## Development status and roadmap

```shell
python -m unittest discover -s tests -v
python -m dlms_enum validate-config examples/public-meter.yaml
DLMS_LLS_PASSWORD=example python -m dlms_enum validate-config examples/lls-meter.yaml
python -m dlms_enum validate-config examples/hls-gmac-suite0-meter.yaml
python -m dlms_enum validate-config examples/multi-role-meter.yaml
```

Protocol tests use fakes, the real Gurux request generator, and sanitized structural expectations derived from the supplied captures; they need no physical meter and embed no keys. Live validation is still required for the target meter, particularly its role provisioning, counter object access, server system title, association-view size, and protected-release behavior.

The current phase — the enumeration and access engine — accepts multiple named `public`, `lls`, and `hls_gmac_suite0` roles and scans each selected role independently after one public planning preflight. The LLS profile currently uses unprotected xDLMS messages after password authentication. A secure role can also perform the bounded public cross-profile test described above. Negotiated GET-with-list batching is available for Association View-advertised reads, with bounded groups and individual fallback. The optional final authentication phase probes the supported password-based HLS variants and Suite 0 HLS-GMAC only on configured client SAPs.

Not yet implemented in this phase: LLS combined with APDU ciphering, Security Suites 1/2, dedicated keys, signing, key agreement, key management, unconfigured client-address sweeps, and transmitted SET/arbitrary ACTION verification. These are roadmap items rather than exclusions; see [plan.md](plan.md) for the phased vulnerability-scanning and fuzzing roadmap.
