# A7: selective access on restricted Profile Generic buffers

1. Add explicit `--selective-access ROLE`, per-role target limits, and optional
   timezone-qualified range bounds (maximum one hour).
2. Select class-7 attribute-2 buffers advertised denied or conditional. In one
   association, establish a harmless baseline and try a normal buffer GET.
   Only explicit DLMS read/write-access-denied (code 3) enables selector probes.
3. Request entry 1, count 1. For an optional time range, read capture-object and
   sort-object metadata and require a captured class-8 clock attribute 2,
   data index 0. Do not invent a restricting object or use an open-ended range.
4. Reuse active authorization, per-role sessions, counter leases and shared GET
   budget. Bound response continuations/bytes and stop a session after an
   inconclusive exchange. Retain no buffer contents in A7 reports or traffic.
5. Distinguish returned data after denial, empty selective responses, rejection,
   normal-read success, skipped checks and inconclusive results. Add regression
   tests and usage documentation.

Entry reads work without capture metadata because their selector addresses row
numbers. Range checks require explicit bounds to avoid guessing meter time.
Returned data after a normal-read denial is an observed access discrepancy,
not automatically a policy violation: a meter may intentionally authorize
selective access separately. No SET or ACTION is performed.

Implementation complete. Validation: 272 tests pass, including selector gating,
range descriptor validation, budget and continuation limits, malformed/empty
buffers, workflow artifacts and traffic-level buffer-content omission.
No live meter was contacted.
