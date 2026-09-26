# A1–A3 implementation review and completion plan

Reviewed: 2026-09-26. Scope: the A1–A3 definitions in
[vulnerability-research.md](vulnerability-research.md), compared with the current
code and automated tests. The original review is followed by the implementation record below. No live
meter was contacted during either step.

## Implementation record

The review below records the starting point. The subsequent implementation uses
this short sequence: evidence fixes → all-role comparison → policy rules →
bounded active GET checks → tests and documentation.

Implemented in `access_policy.py`, `capability_comparison.py`, `cross_role.py`,
and the existing scanner/CLI/reporting modules:

- Public-only exposure assessment and exact, reasoned policy exceptions.
- All-role comparisons with denied, absent, unavailable, and version-mismatch
  states, preserving the legacy public comparison fields.
- Explicit `access-check` directed pairs across public/LLS/HLS roles, fresh
  inventories, shared active GET-attempt budgets, deduplication, destination
  baselines, bounded recovery, and the existing counter/session lifecycle.
- Regression coverage for compact-report findings, skipped probes, true limit
  truncation, policy, matrices, CLI integration, and secure-task cleanup.

Implementation choices: normal inventory reads remain separate from active
verification; inventory/bootstrap/association traffic is outside the active
GET-service-attempt budget and is documented in the CLI and reports. Semantic
labels are conservative (`profile_buffer`, `register_data`, or unclassified),
while all non-baseline public capabilities remain visible. Sensitive control
rules are operation/class based and exact member exceptions refine them; they
do not claim that an advertised method will work on an unknown object version.
Live-meter validation remains pending. The detailed sequence below is retained
as design context, not a claim that every optional refinement has shipped.

Implementation validation: 234 automated tests passed; all six example YAML
configurations parsed successfully; CLI help and `git diff --check` passed.

## Assessment

The enumeration and evidence infrastructure is substantially implemented. The
full A1–A3 feature set is partial: A1 lacks its general exposure assessment,
A2 is public-centered rather than an arbitrary-role matrix, and A3 implements
only the HLS-to-public subset. The roadmap's completed Phase 1 work describes
that narrower foundation correctly; “A1–A3 (mostly)” in the research document
should not be read as completion of their full definitions.

| Feature | Implemented | Missing | Assessment |
|---|---|---|---|
| A1: public over-exposure | No-auth profile defaults to SAP 16; Association View enumeration/export; direct GET results; public Security Setup and Image Transfer control warnings | General public baseline and findings for load profiles, event logs, billing registers, and other access beyond nameplate/clock; policy exceptions; standalone public exposure summary | Collection implemented; general assessment missing |
| A2: cross-role rights | Per-role views; public-versus-each-authenticated GET/SET/ACTION comparison, including LLS; Access/Access3 requirements; presence differences; JSON/Markdown/terminal output | Non-public pair comparisons, comparisons without a public snapshot, low-privilege policy, sensitive-object rules beyond existing public security/firmware posture | Public-centered subset implemented |
| A3: cross-role GET | HLS-advertised readable targets tested through a fresh public session; explicit rejection versus transport failure; retries, GET limit, circuit breaker, evidence | LLS-to-public and arbitrary directed role pairs; shared planning/deduplication; destination-role session orchestration and aggregate budgets | One directed subset implemented |

Numerical completion percentages would overstate precision: the missing policy
and cross-role orchestration are substantial features despite the large amount
of reusable code.

## Code evidence and limitations

### A1

- `config.py:PublicProfile` defaults to client address 16, and configuration
  parsing enforces no authentication for public profiles.
- `scanner.py:scan_public` inventories and reads objects for the configured
  role. `association_view.py:snapshot_from_report` exports advertised metadata.
- `security_posture.py:build_security_posture` produces passive public findings
  for class 64 and class 18 writes/actions. It does not implement a general
  public read-exposure baseline.
- `capability_comparison.py` flags `public_only` and `public_broader`. These are
  relative differences, not a public policy: sensitive GET access advertised
  identically in both roles is classified `same` and receives no exposure flag.
  Conversely, a legitimate public-only identity capability can be flagged by
  the generic difference rule.

### A2

- `scanner.py:_attribute_access_rights` and `_method_access_rights` preserve
  legacy authenticated access and Access3 request/response requirements.
- `capability_comparison.py:compare_role_capabilities` compares GET, SET, and
  ACTION separately and includes object/member presence.
- `build_workflow_comparison` always compares one public snapshot against a
  list of authenticated snapshots. `cli.py:_scan` only builds that report when
  a public snapshot and at least one authenticated snapshot are available.
- The normalization emits rows for operations allowed on at least one side;
  it is not a full matrix of explicitly denied members. A side without the
  operation retains presence flags but loses its original denied-rights data.
- There is no configured role privilege/policy model or comprehensive rule set
  for disconnect control, scripts, clock writes, or tariff controls. Existing
  posture findings only treat no-auth roles as public; LLS roles do not receive
  equivalent low-privilege findings.

### A3

- `config.py:AppConfig.for_profile` disables `union_profile_test` for non-secure
  profiles; parsing requires an `hls_gmac_suite0` profile when it is enabled.
  LLS is supported in passive comparison, but not as a source for this test.
- `scanner.py:_public_union_candidates` selects Association View-advertised
  readable attributes that are absent, unreadable, or conditional in the
  public view. It skips logical-name attribute 1 and generated catalogue
  targets. Source access is advertised; a successful source GET is not a
  prerequisite for selection.
- `_run_public_union_gets` handles direct success, explicit DLMS errors,
  transport/protocol failures, retry suppression, and bounded recovery.
  `get_limit` selects targets per role/phase; retries and recovery generate
  additional traffic. It is not a workflow-wide transmission budget.
- The secure scan closes the protected association, then opens public through
  the secure profile's configured counter-bootstrap public SAP. There is no
  arbitrary destination-role executor or workflow-wide target deduplication.
- Every successful candidate is labeled `UNEXPECTED_PUBLIC_ACCESS`. That proves
  access contrary to the candidate's advertised public view, not necessarily
  a violation of an operator-defined security policy.

### Reporting corrections to include

1. `render_comparison_markdown` omits every `authenticated_only` row, even when
   its attached public GET verification confirms unexpected access. Preserve
   compact output, but always show verified exposure and significant failures.
2. The final cross-profile matrix merge in `scan_public` assigns `tested=True`
   to every result, including circuit-breaker-skipped results with zero
   attempts. Derive this from actual attempts. It also replaces advertised
   presence with `False`, including for conditional public rights; preserve
   the candidate's advertised metadata.
3. Keep structured DLMS error detail. An explicit service/object error is
   negative evidence for that request, but does not always prove an access
   policy denial. Separate access denial, unavailable object, and other DLMS
   errors from transport-inconclusive outcomes.
4. The workflow comparison joins public probes to the selected public snapshot
   without checking that its SAP matches the bootstrap/probe SAP. Validate
   endpoint and role identities before attaching evidence.

## Implementation sequence

### 1. Repair evidence and define policy semantics

Files: `scanner.py`, `capability_comparison.py`, `config.py`, related tests.

- Fix the reporting issues above first, retaining existing report fields.
- Introduce a small normalized evidence model keyed by endpoint, role, class,
  logical name, operation, and member. Preserve raw rights, requirements,
  explicit denial, absent object/member, unavailable view, snapshot origin,
  and observed GET outcomes separately.
- Define operator-selected role policies and explicit directed probe pairs.
  Authentication strength and numeric SAP must not imply privilege order.
- Define a named, versioned public baseline: permitted identity/nameplate and
  clock reads plus necessary discovery metadata; sensitive categories and
  unknown non-baseline capabilities remain visible. Allow exact member-level
  exceptions with reasons. Clock read permission must not permit clock SET.
- Keep a neutral rights difference distinct from a baseline exposure finding
  and from a verified policy violation. Record the policy/rule identifier and
  evidence references for each finding.

Acceptance: zero-attempt results never claim testing; confirmed public access
is visible in Markdown; conditional advertised rights survive evidence merges;
unknown/missing views are never treated as explicit denial; mismatched public
SAP evidence cannot be attached to a different role.

### 2. Complete the passive A2 matrix

Files: `capability_comparison.py`, `cli.py`, `association_view.py`, `tui.py`.

- Build one canonical union of capabilities with one cell per selected role.
  Preserve explicit no-access metadata rather than dropping it during
  normalization. Failed/unavailable roles remain visible with a reason.
- Derive pairwise differences for all selected roles, including LLS/HLS,
  HLS/HLS, and runs with no public role. Passive pair comparisons send no
  requests and need no privilege ordering.
- Record snapshot freshness/origin and object versions. Flag incompatible
  identities or versions rather than silently treating them as equivalent.
- Retain the existing public comparison as a compatibility projection, or
  deliberately version the changed schema and migrate all renderers together.

Acceptance: a three-role fixture produces all three unordered comparisons;
a two-authenticated-role run works without public; Access3 differing and
incomparable requirements remain distinct; missing role/view/member states
are preserved; passive comparison adds no GET, SET, or ACTION traffic.

### 3. Complete A1 and A2 exposure rules

Suggested new module: `access_policy.py`, consuming normalized evidence.

- Evaluate A1 on a public-only scan, without requiring an authenticated role.
  Flag non-baseline advertised and successfully read attributes independently.
  Classify known load-profile, event-log, and billing objects using existing
  metadata/catalogue information; expose uncertain classifications explicitly.
- Add operation/member-aware A2 rules for class 70, class 64, class 9, clock,
  and tariff controls. Use versioned class/member mappings and exact OBIS
  overrides rather than description-string matching alone.
- Apply rules to roles explicitly designated low privilege. Keep legitimate
  role-specific exceptions and conditional protection requirements visible.
- Reuse or cross-reference existing security/firmware findings to avoid
  duplicate findings. General severity consolidation can remain in H1.

Acceptance: equal rights in both roles still trigger a sensitive-access rule;
legitimate public identity reads do not; clock GET and SET differ; LLS can be
evaluated as low privilege; passive SET/ACTION warnings never imply success.

### 4. Generalize A3 planning and execution

Suggested new module: `cross_role.py`, using existing workflow/session helpers.

- Specify a pair as `source_role -> probe_role`: use source-advertised readable
  members as candidates and transmit GETs under the probe role. Keep source
  advertisement and source GET success as separate evidence.
- Plan after role inventories are available. Include targets absent, denied,
  or conditionally readable in the probe view, plus policy-forbidden targets
  even when advertised on both sides. Skip missing/invalid inventories with
  explicit reasons; do not infer denial from failed discovery.
- Deduplicate requests by endpoint, probe-role security context, and target,
  retaining every contributing source role. Sort deterministically. Reuse
  successful same-run destination reads only with matching identity, security
  context, and request semantics; retain their original evidence links.
- Add explicit limits for selected targets per pair and for total probe GET
  transmissions, counting retries and recovery GETs. Bound association/recovery
  attempts separately and report discovery/bootstrap overhead. Preserve every
  unselected target as `NOT_TESTED` with its reason.
- Execute sequentially by destination role through the transport guard.
  Support public, LLS, and HLS-GMAC with their real configured credentials and
  SAPs. Confirm a known-good destination association and harmless GET before
  testing; failed baselines stop that destination's probes.
- Reuse crash-safe protected counter allocation, public counter bootstrap,
  cleanup, retry suppression, circuit breaker, and bounded recovery. Recovery
  must preserve destination identity and protection without weaker fallback.
- Record success, explicit access denial, other DLMS rejection, inconclusive,
  and not-tested independently of policy assessment. Only label a successful
  request a policy violation when an applicable rule prohibits it.
- Keep secrets redacted in new requests, responses, reports, and exceptions.

Acceptance: fake sessions cover LLS-to-public, HLS-to-LLS, LLS-to-HLS, and
HLS-to-HLS; repeated targets transmit once per compatible destination context;
budget exhaustion and failed health checks leave explicit untested scope;
timeouts are inconclusive; protected recovery never reuses counters; no
application SET or arbitrary ACTION is sent (required HLS authentication
exchange remains part of establishing a protected session).

### 5. Expose, document, and validate the completed workflow

Files: `cli.py`, `config.py`, `reporter.py`, `tui.py`, example configurations,
`README.md`, `plan.md`, and `vulnerability-research.md`.

- Keep passive A1/A2 assessment available with normal scans. Put expanded A3
  execution behind a separate explicit active command, proposed as
  `dlms-enum access-check`, with selected pairs, limits, and the target
  authorization record required by the roadmap's active-phase release gate.
- Preserve the current opt-in `union_profile_test` semantics as a documented
  compatibility path; it must not silently enable additional pairs.
- Report role/SAP identities, policy, advertised versus verified evidence,
  totals per role/pair/operation, skipped scope, and traffic references. Never
  hide confirmed findings when compacting the matrix.
- Add realistic three-role examples, including public+LLS without HLS and
  non-public-only comparison. Validate existing examples and schema consumers.
- Update roadmap checkboxes only as each acceptance criterion is met. Keep
  automated completion separate from authorized live validation.

Acceptance: fake-session CLI tests exercise inventory → matrix → policy →
selected probes → JSON/Markdown/terminal; legacy configuration still works;
full tests and `git diff --check` pass. A bounded authorized meter run then
checks actual rights, source/destination identity, rejection behavior, cleanup,
counter safety, and complete report evidence before declaring A1–A3 complete.

## Validation performed for this review

- `PYTHONPATH=src .venv/bin/python -m unittest discover -s tests -q`: **211 tests
  passed**. The initial invocation without `PYTHONPATH` could not import the
  source package; the corrected invocation above succeeded.
- Relevant coverage includes public/LLS CLI comparison, Access3 parsing,
  passive security posture, fresh-public-session union GETs, explicit DLMS
  rejection, retry suppression, and counter/session recovery tests.
- Strengthen the current union limit test: it has one candidate with a limit
  of one, so it does not demonstrate truncation. Add several candidates, a
  smaller limit, retries/recovery, and retained untested rows.
- No live validation was performed. Existing live-meter release gates remain
  open. A4–A7, authentication downgrade tests, fuzzing, and modifying operations
  are outside this completion plan.
