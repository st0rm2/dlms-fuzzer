# DLMS Smart Meter Enumeration Tool

This first implementation milestone performs an authorized, read-only scan over direct serial HDLC. It establishes one unauthenticated logical-name association, reads the Association LN object list, supplements it with a conservative common OBIS catalogue, GETs readable attributes, decodes values through Gurux DLMS, and writes a canonical JSON report plus side-by-side JSONL traffic.

No SET, ACTION, password authentication, ciphering, additional profiles, manufacturer catalogues, or fuzzing is implemented yet. Configuration that tries to enable those features is rejected instead of being silently ignored.

## Install

Python 3.11 or newer is required.

```shell
python -m venv .venv
. .venv/bin/activate
python -m pip install -e .
```

The runtime uses `gurux-dlms` and `gurux-serial` for HDLC, xDLMS APDUs, interface classes, and DLMS data types. Confirm that their licensing is suitable for your deployment.

## Run

Copy and edit the sample configuration:

```shell
cp examples/public-meter.yaml meter-profiles.yaml
python -m dlms_enum validate-config meter-profiles.yaml
python -m dlms_enum scan --config meter-profiles.yaml
```

Or start guided setup:

```shell
python -m dlms_enum scan
```

Other commands:

```shell
python -m dlms_enum list-catalogues
python -m dlms_enum report ./runs/2026-08-10T120000Z
```

The public client and server addresses vary between meters. The sample's logical address `1` plus physical address `1` is composed into HDLC server address `129`; a meter using server address `1` generally needs logical address `0`, physical address `1`.

## Outputs

Each run gets its own UTC-named directory:

- `report.json` is the canonical result. Objects are keyed semantically by profile, class ID, logical name, version, and attribute ID. Values retain DLMS type metadata; octet strings include hexadecimal, Base64, and printable text forms.
- `traffic.jsonl` is append-only. Each line includes TX/RX raw frames, decoded protocol XML and request context, timing, outcome, and redaction indicators.

GET uses at most two attempts. Explicit DLMS errors such as access denied are not retried. Timeouts, transport failures, and malformed responses may receive the single permitted retry.

## Safety and operational notes

Use this only against equipment you are authorized to test. This milestone sends no SET or ACTION requests, but unfiltered reads of an advertised Profile Generic buffer can be large and slow. Start with a laboratory meter, verify the serial wiring and addresses, and keep `inter_request_delay_ms` nonzero unless the meter vendor documents otherwise.

Automatic baud detection accepts a rate only after both valid HDLC setup and a valid public AARE response. A valid UA alone is not enough.
For each baud rate, endpoint discovery tests the common one-byte server address and the configured two-byte logical/physical form. The report and terminal summary identify the selected combined HDLC server address and its `Server Addressing Type` (`1-byte addressing` or `2-Byte addressing`).

## Development

```shell
python -m unittest discover -s tests -v
```

Protocol-facing tests use fakes and recorded structures so they do not require a meter. Hardware validation is still required before relying on this against a new meter family.
