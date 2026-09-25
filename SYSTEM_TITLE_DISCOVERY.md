# Discovering a DLMS/COSEM System Title Without Authentication

System-title discovery is reconnaissance: a recovered title feeds the scanner's authenticated HLS testing phases, where it is needed to address a specific secure client.

There is no universally guaranteed unauthenticated query for a meter's system title. Whether it can be retrieved depends on the communication profile and on the information exposed by the meter's public association.

A DLMS/COSEM system title is eight octets long and uniquely identifies a DLMS entity. The first three octets should contain the FLAG manufacturer identifier; the remaining five octets ensure uniqueness. It is an identifier used by DLMS security, not an encryption key.

## 1. Inspect the public-association AARE

System titles can be exchanged during application-association establishment in the AARQ and AARE APDUs. Because the AARE precedes any subsequent HLS challenge, its server title can sometimes be observed without completing authentication.

A meter is not guaranteed to include the title in a plain public AARE, however. A guessed secure AARQ is also not a dependable discovery mechanism: a meter may require the correct security context and reject the request without exposing its identity.

The latest tested meter did not include a server system title in its public AARE.

## 2. Read the Security Setup object through the public client

The standard COSEM source is the Security Setup object:

- Interface class: `64`
- Attribute 4: `client_system_title`
- Attribute 5: `server_system_title`
- Common logical-name family: `0.0.43.0.x.255`

Attribute 5 can be read with a normal GET if the public association grants access. The presence and access rights of the object are meter and association specific.

For the latest tested meter:

- The public Association LN referenced `0.0.43.0.0.255` as its Security Setup.
- No class-64 object appeared in the public association view.
- Direct probes of `0.0.43.0.0.255` through `0.0.43.0.15.255` returned `undefined object`.

This most likely means that Security Setup is hidden from public client 16. It does not prove that the object is physically absent from the meter.

## 3. Passively observe protected DLMS traffic

This is often the strongest remaining unauthenticated method. A `GeneralGloCiphering` APDU normally carries the sender's eight-byte system title outside the encrypted service:

```text
DB 08 <8-byte-system-title> <ciphered-service...>
```

The title can therefore be parsed without the encryption or authentication keys. The protected application data still cannot be decrypted.

This method has limitations:

- It applies when the sender uses `GeneralGloCiphering`; service-specific `glo-*` APDUs do not necessarily carry a system title.
- Some pre-established profiles deliberately omit the title and require it to be configured in advance.
- A capture must contain protected association or push traffic from the relevant meter.

The previously supplied plaintext `DataNotification` frames start with APDU tag `0F`. They do not contain a system-title field.

Useful passive targets are:

- spontaneous protected push notifications;
- the AARQ/AARE exchange of an existing authorized client;
- other `GeneralGloCiphering` traffic emitted by the meter.

## 4. Observe media-specific registration

DLMS defines media-specific registration as another system-title exchange mechanism. For S-FSK PLC, system titles are exchanged by the CIASE registration protocol.

The tested meter's public object list includes S-FSK setup classes, including class 56, which indicates PLC-related capabilities. This does not establish that class 56 exposes the local meter's system title through the optical public association.

Retrieving the title through this route would normally require:

- an S-FSK PLC modem capable of observing registration, or
- a capture of CIASE registration/discovery traffic.

An optical HDLC connection exposed as `/dev/ttyUSB0` ordinarily does not carry the PLC registration exchange.

## 5. Extract the title from a certificate

With DLMS Security Suites 1 and 2, the certificate owner identity contains the corresponding system title. If the meter certificate is already available from provisioning files, a head-end system, a PKI, or a commissioning export, its subject can be inspected without authenticating to the meter.

Reading or exporting that certificate from the meter may itself require authenticated access to Security Setup.

## 6. Derive only a candidate from the meter identity

The first three system-title octets should match the three-letter manufacturer identifier. For the observed Logical Device Name:

```text
ISK1030784174354
```

only the following prefix can be inferred safely:

```text
49 53 4B ?? ?? ?? ?? ??
 I  S  K
```

The DLMS specification gives the manufacturing number as one possible source for the remaining five octets, but companion specifications may define a different representation. Without the applicable Iskraemeco specification, a serial-number-derived suffix is only a candidate and must not be treated as a discovered title.

## Conclusion for the tested meter

The direct public-DLMS methods were exhausted without recovering a title. The remaining unauthenticated options are, in recommended order:

1. Passively listen for AARE or `GeneralGloCiphering` frames and extract a clear-text title.
2. Capture S-FSK CIASE registration with suitable PLC hardware.
3. Obtain the meter certificate or provisioning record externally.

If none of those sources is available, there is no standards-guaranteed way to recover this meter's system title without using an association authorized to expose Security Setup.

The main scanner now provides this passive option:

```shell
dlms-enum scan --config meter.yaml --system-title-listen-seconds 60
```

After public preflight confirms the serial settings, the tool listens without
transmitting, recognizes AARE and `GeneralGloCiphering` frames, and reports any
clear-text eight-byte sender system title without attempting decryption.

## References

- [DLMS UA Green Book, Edition 12 excerpt](https://dlms.com/wp-content/uploads/2025/06/Excerpts-DLMS-Green-Book-Ed-12-v1.0.pdf) — system-title format and the standardized exchange mechanisms.
- [DLMS UA Blue Book, Edition 17 Part 2 excerpt](https://dlms.com/wp-content/uploads/2025/06/Excerpts-DLMS-Blue-Book-Ed-17-part-2-V1.0.pdf) — S-FSK terminology and CIASE-related entities.
- [Gurux Security Setup documentation](https://www.gurux.fi/index.php/Gurux.DLMS.Objects.GXDLMSSecuritySetup) — class-64 attributes, including client and server system titles.
- [Gurux public-key cryptography documentation](https://www.gurux.fi/PublicKeyCryptography) — obtaining system titles from certificate subjects.
- [Gurux pre-established connection documentation](https://www.gurux.fi/pre-established) — profiles in which system-title information may be omitted.
- [Gurux protected-push example](https://gurux.fi/forum/15923) — an example of a system title carried by `GeneralGloCiphering`.
