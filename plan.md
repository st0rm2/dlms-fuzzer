# dlms-enum roadmap

Status: 2026-08-13

## Direction

`dlms-enum` remains an authorized, read-only discovery and configuration-audit tool. It should distinguish clearly between:

- capabilities advertised by an Association LN;
- operations verified by a request;
- targets inferred from a catalogue or enumeration rule;
- explicit DLMS rejections;
- transport failures and other inconclusive results.

Normal scans must not send arbitrary SET or ACTION requests, transfer firmware, rotate keys, guess credentials, or replay protected commands. Higher-risk protocol-conformance checks belong in separate, explicitly selected lab workflows.

## Completed foundation

- [x] Public Association LN discovery and read-only GET scanning.
- [x] HLS-GMAC Security Suite 0 association with authenticated and encrypted xDLMS traffic.
- [x] Crash-safe invocation-counter persistence and rollback prevention.
- [x] Passive inventory of advertised GET, SET, and ACTION capabilities.
- [x] Conservative common-OBIS catalogue probes outside the Association LN.
- [x] Secure-to-public direct GET comparison for authenticated-readable targets.
- [x] Exact GET budgets with unselected capabilities retained as `NOT_TESTED`.
- [x] Apply `get_limit` to the public cross-profile test as well as the primary scan.
- [x] Reduce the default response timeout from 3000 ms to 1000 ms.
- [x] Suppress retries after two consecutive timeouts in a scan phase.
- [x] Refresh the terminal elapsed-time display independently once per second.
- [x] Canonical JSON, Markdown summary, and side-by-side traffic evidence.

## Next: complete public-versus-secure capability comparison

This is the next feature to implement. The tool already downloads both Association Views when `union_profile_test` is enabled, but it uses the public view mainly to choose direct GET probes. The next step is to preserve and compare the complete advertised operation model for both roles.

Why this comes next:

- it directly detects common access-control configuration mistakes;
- it reuses data and parsing that already exist;
- SET and ACTION exposure can be assessed passively, without modifying the meter;
- direct GET verification already has result classification, limits, and retry controls;
- it provides the security model needed by later LLS and suite-policy work.

Planned work:

- [ ] Retain normalized public and secure rights for every `(class_id, logical_name, member_id)`.
- [ ] Compare GET, SET, and ACTION rights separately.
- [ ] Preserve Access and Access3 requirements such as authenticated, encrypted, or signed requests and responses.
- [ ] Report objects and members present in only one role.
- [ ] Flag unexpectedly broad advertised public GET, SET, or ACTION rights without claiming that passive evidence proves successful access.
- [ ] Continue direct verification for GET only.
- [ ] Keep `UNEXPECTED_PUBLIC_ACCESS`, explicit rejection, and inconclusive transport outcomes distinct.
- [ ] Apply `get_limit` only to transmitted GET probes; always produce the complete passive comparison.
- [ ] Add per-role and per-operation totals to `report.json` and `summary.md`.
- [ ] Add unit tests for Association LN versions 2 and 3, write-only attributes, method rights, missing objects, GET limits, and inconclusive responses.

Definition of done:

- Every advertised GET, SET, and ACTION capability can be compared side by side for public and secure roles.
- No SET or arbitrary ACTION is transmitted.
- Passive exposure, verified exposure, rejection, and inconclusive evidence cannot be confused in either report format.
- Existing report consumers remain compatible, or the report schema version is deliberately advanced and documented.

## Reliability gate: dead-session circuit breaker and timing evidence

This gate should be completed before significantly increasing the number of probe candidates. Retry suppression prevents a second transmission, but a silent association can still cause every remaining candidate to consume one timeout.

- [ ] Track consecutive timeout outcomes separately for each scan phase.
- [ ] After a configurable bounded threshold, stop or suspend that phase instead of timing out the entire remaining inventory.
- [ ] Optionally perform one conservative association-health check or reconnect attempt before stopping.
- [ ] Mark skipped remainder as `NOT_TESTED` with a `session_unhealthy` reason.
- [ ] Never reuse a protected invocation counter during recovery.
- [ ] Detect unusually large gaps in the monotonic host clock and report a probable suspend/process-pause warning separately from meter response time.
- [ ] Report the circuit-breaker threshold, trigger point, attempted recovery, and number of skipped requests.
- [ ] Test public and protected recovery paths, including cleanup failures.

## Bounded OBIS enumeration outside the Association LN

Replace the small fixed catalogue as the only undeclared-object source with bounded, explainable candidate generation. Do not attempt the full six-byte OBIS Cartesian space.

- [ ] Introduce candidate providers for the common catalogue, standard OBIS templates, user-supplied lists, and optional manufacturer catalogues.
- [ ] Represent a probe as `(class_id, logical_name, attribute_id)`; an OBIS value alone is not a complete logical-name GET target.
- [ ] Deduplicate candidates against the Association View and other providers.
- [ ] Support explicit class, OBIS-group, attribute, and total-request budgets.
- [ ] Use deterministic ordering so limits and repeated runs are reproducible.
- [ ] Record the provider, rule, and confidence for every inferred target.
- [ ] Treat explicit DLMS errors as negative evidence and timeouts as inconclusive.
- [ ] Apply the dead-session circuit breaker to enumeration phases.
- [ ] Keep the default candidate set conservative; broad enumeration must require explicit configuration.

## LLS profile and credential-exposure reporting

Add Low Level Security only with secret-safe configuration and traffic handling.

- [ ] Add a distinct LLS profile rather than overloading `public` or `hls_gmac_suite0`.
- [ ] Accept the password from an environment variable, protected file, or masked prompt.
- [ ] Never place the password in configuration snapshots, reports, exceptions, or decoded traffic.
- [ ] Redact or disable raw AARQ capture by default because the ACSE authentication value can contain the static password.
- [ ] Report credential length and observed transport/confidentiality properties without exposing the value.
- [ ] Do not add password guessing, default-password lists, or authentication spraying.
- [ ] Include LLS as another role in the passive capability comparison.

## Passive security and firmware-update posture

Build a read-only posture section from already accessible objects and Association LN rights.

- [ ] Summarize Security Setup policy, suite, system titles, version, and advertised method rights.
- [ ] Flag publicly advertised access to security activation, key transfer, key agreement, or certificate-management methods.
- [ ] Detect class 18 Image Transfer objects and read only advertised readable attributes.
- [ ] Report image-transfer status, block size, enablement, and advertised initiate/transfer/verify/activate rights where available.
- [ ] Avoid claiming that remote metadata proves secure-element use, key extraction, signature enforcement, or secure boot.
- [ ] Never send Image Transfer or key-management ACTION requests in a normal scan.

## Separate conformance workflow: association policy and downgrade checks

This should be a separate command with explicit authorization and attempt limits, not an automatic fallback used by `scan`.

- [ ] Require the expected policy for each client SAP.
- [ ] Test application context/protection, authentication mechanism, security suite, and security policy as separate dimensions.
- [ ] Establish a known-good baseline before testing weaker variants.
- [ ] Distinguish AARE acceptance, completed HLS, protected-service acceptance, granted rights, and a successful harmless GET.
- [ ] Bound attempts and add cooldown and lockout warnings.
- [ ] Never continue a normal scan under a weaker association after the expected secure association fails.
- [ ] Produce a matrix of proposed versus negotiated/observed properties and explain why each result is or is not a downgrade.

## Experimental lab workflow: invocation-counter replay enforcement

The normal counter allocator deliberately prevents reuse. Replay testing must therefore be isolated from normal scanning and clearly marked experimental.

- [ ] Require explicit lab-mode selection and a harmless allowlisted GET target.
- [ ] Capture one valid protected GET APDU and reframe it in a valid data-link exchange, rather than blindly replaying an old HDLC frame.
- [ ] Preserve normal counter-state safety for all newly generated protected requests.
- [ ] Distinguish link-layer rejection, stale-counter rejection, silent discard, inconclusive transport failure, and confirmed duplicate acceptance.
- [ ] Stop after the bounded test and verify that a fresh-counter request still works.
- [ ] Document possible association desynchronization and lockout risks.

## Deferred or out of scope

These items do not belong in the normal enumerator:

- Arbitrary SET automation.
- Arbitrary or irreversible ACTION automation.
- Firmware initiate, block transfer, verify, or activate operations.
- Key rotation or key-transfer execution.
- Credential guessing or password spraying.
- AES key extraction from flash, UART, JTAG, SWD, firmware, or hardware security components.
- Claims about secure boot or signature enforcement based only on passive DLMS metadata.
- OBIS remapping: COSEM provides no standard operation for redirecting one logical name to another.

A future low-priority semantic-consistency diagnostic may flag unusual class/type/scaler/unit combinations or suspiciously identical values, but it must not present correlation as proof of internal firmware aliasing.

## Release gates for every milestone

- [ ] Preserve the read-only default and document every transmitted operation.
- [ ] Keep secrets out of reports, logs, exception messages, and test fixtures.
- [ ] Use deterministic limits and make untested scope visible.
- [ ] Classify timeouts and transport failures as inconclusive, never as access denial or object absence.
- [ ] Add fake-session unit coverage and sanitized structural protocol tests.
- [ ] Validate both example configurations.
- [ ] Run the complete automated test suite and `git diff --check`.
- [ ] Perform a bounded authorized live-meter validation before calling a milestone complete.
