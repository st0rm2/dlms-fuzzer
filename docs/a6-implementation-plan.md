# A6: system-title-dependent Association Views

Short implementation plan:

1. Add repeatable `--system-title ROLE:HEX` inputs and a global variant cap.
   Validate selected HLS-GMAC roles, exact 8-byte titles, duplicates, and counter
   bootstrap configuration before any meter I/O.
2. Establish a fresh protected baseline using the configured title. For each
   explicit variant, preserve SAP, keys, suite, protection and endpoint; open
   one independent session, verify negotiated properties, then GET the logical
   name and Association LN object list.
3. Use the existing per-title counter identities, persistent leases, session
   guard and cleanup. Share the active GET budget with A3–A5. Bound timeout
   retries; do not reconnect or fall back to weaker authentication.
4. Retain per-title JSON/traffic evidence and compare objects, versions and
   GET/SET/ACTION rights. Separate AARE rejection, changed/unchanged views,
   unknown rights encodings, skipped checks and inconclusive failures.
5. Add focused regression coverage and document the CLI and budget scope.

Scope: HLS-GMAC Suite 0, the profile that currently configures and sends client
system titles. Public/LLS title injection and randomized title generation are
outside this feature. Differences are review findings, not automatic proof of
an access-control vulnerability. Views are observed sequentially, so unrelated
meter configuration changes can also explain differences.

Implementation complete. Validation: 258 unit/integration tests pass, CLI help
includes the new options, and `git diff --check` is clean. No live meter was
contacted. Coverage includes changed/unchanged views, baseline failure gating,
AARE rejection versus inconclusive errors, identity/protection mismatches,
shared budgets, interruption, and persistent counter isolation per title.
