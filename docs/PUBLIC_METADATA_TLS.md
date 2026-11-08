# Public metadata HTTPS trust

This bundle is exclusively for the allowlisted public display-metadata hosts.
It does not replace or extend the existing Google Drive WE2/WR2 bundle, disable
TLS checks, change DNS, or prove PS5 connectivity.

## Authenticated CA sources

Retrieved over normally verified HTTPS from the CA operators on
2026-10-05 around 04:10 UTC. The PEM certificates and independently fetched DER
files have the same DER SHA-256 fingerprints.

| Anchor | Official PEM / DER | DER SHA-256 |
| --- | --- | --- |
| ISRG Root X1 | [PEM](https://letsencrypt.org/certs/isrgrootx1.pem), [DER](https://letsencrypt.org/certs/isrgrootx1.der) | `96bcec06264976f37460779acf28c5a7cfe8a3c0aae11a8ffcee05c0bddf08c6` |
| GTS Root R4 | [PEM](https://pki.goog/repo/certs/gtsr4.pem), [DER](https://pki.goog/repo/certs/gtsr4.der) | `349dfa4058c5e263123b398ae795573c4e1313c83fe68f93556cd5e8031b3c7d` |
| Root YR | [PEM](https://letsencrypt.org/certs/gen-y/root-yr.pem), [DER](https://letsencrypt.org/certs/gen-y/root-yr.der) | `e57b7e6f150c419102e8d5c055729ff967b9d1a829bf00cec89ca604ebf4a86f` |

The ISRG fingerprint also matches the CA operator's
[WebTrust disclosure](https://letsencrypt.org/audits/ISRG-2018-WebTrust-for-CAs-Report.pdf).
The GTS fingerprint matches its
[published certificate details](https://pki.goog/repo/cps/5.12/GTS-CPS.html);
this is the self-signed GTS Root R4 variant with digitalSignature usage, not
the older self-signed or cross-signed variant.

Root YR was retrieved and independently verified from those authenticated
operator URLs later on 2026-10-05. Its PEM/DER fingerprint, self-signature,
critical CA:TRUE constraints and Certificate Sign/CRL Sign usage all passed.
Subject and issuer are `C=US, O=ISRG, CN=Root YR`; its certificate validity is
2025-09-03 00:00:00 UTC to 2045-09-02 23:59:59 UTC. This is not an intermediate
or an endpoint certificate accepted as a substitute for a trust anchor.

Offline OpenSSL checks on the first two retrieved certificates:

| Check | ISRG Root X1 | GTS Root R4 |
| --- | --- | --- |
| Subject equals issuer | `C=US, O=Internet Security Research Group, CN=ISRG Root X1` | `C=US, O=Google Trust Services LLC, CN=GTS Root R4` |
| Basic constraints | Critical, CA:TRUE | Critical, CA:TRUE |
| Key usage | Critical, Certificate Sign / CRL Sign | Critical, Digital Signature / Certificate Sign / CRL Sign |
| Certificate validity | 2015-06-04 11:04:38 UTC to 2035-06-04 11:04:38 UTC | 2016-06-22 00:00:00 UTC to 2036-06-22 00:00:00 UTC |
| Self-signature verification | PASS, `openssl verify -check_ss_sig` | PASS, `openssl verify -check_ss_sig` |

These are certificate validity dates, not a guarantee that every root program
will trust the anchors until those dates. The bundle includes exactly three
self-signed roots; no endpoint leaf, intermediate, private key, or unrelated
trust anchor is included.

The CA operator notes that Root YR is not yet in major public root-program
stores. Here it is an explicitly approved private trust anchor only for the
existing allowlisted public metadata URLs, not a change to Drive or the PS5
system certificate store. It does not disable hostname, chain or TLS checks.

## Public Mac observation, not PS5 evidence

On 2026-10-05 around 04:08 UTC, public SNI handshakes from the Mac presented:

| Host | Server-presented chain | Verified Mac trust endpoint |
| --- | --- | --- |
| raw.githubusercontent.com | leaf `*.github.io` → Let's Encrypt YR1 → Root YR cross-signed by ISRG Root X1 | ISRG Root X1 |
| prosperopatches.com | leaf `prosperopatches.com` → Google WE1 → GTS Root R4 cross-signed by GlobalSign Root CA | GTS Root R4 |
| cdn.prosperopatches.com | Same leaf and chain as prosperopatches.com | GTS Root R4 |

The GitHub leaf's SAN includes `*.githubusercontent.com`; the Prospero leaf
includes `*.prosperopatches.com`. The Mac reported certificate verification
code 0 for each connection. LibreSSL then emitted `poll error` on stdin EOF;
that post-handshake process exit is not a measured HTTP response or PS5 result.

Offline `openssl verify` against only `certs/public-metadata-roots.pem`, using
each captured leaf and its server-presented intermediates, passed for all
three chains. This establishes that the saved anchors cover these captured
public chains on the Mac, not that PS5's loader behaves identically.

The [Let's Encrypt chain documentation](https://letsencrypt.org/certificates/)
describes YR1 → Root YR → ISRG Root X1. The
[Google CA documentation](https://pki.goog/repo/cp-cps-tls/6.7/GTS-CP-CPS-TLS.html)
identifies WE1 under GTS Root R4. Endpoint chains may rotate or vary by TLS
negotiation and network location; these observations are not certificate pins.

Observed intermediary DER fingerprints, retained only as provenance:

- YR1: `13949634d99cd6fd6aa80bc034fefacceb1969feef986586713ecdbb05758d3f`.
- Root YR cross-signed by X1: `072639d0b140d5bffae16ad9c3f6cc6086040621f51ee61a6d46a8915c07cf76`.
- WE1 signed by GTS Root R4: `1dfc1605fbad358d8bc844f76d15203fac9ca5c1a79fd4857ffaf2864fbebf96`.
- GTS Root R4 cross-signed by GlobalSign: `76b27b80a58027dc3cf1da68dac17010ed93997d0b603e2fadbe85012493b5a7`.

## Existing loader and diagnostic limits

The packaged `certs/google-we2-wr2.pem` contains Google WE2 and WR2
intermediates, not the two anchors above. The existing production loader also
tries optional Google PEM paths and `cacert.pem`; this audit did not inspect
what is installed on the console or its system trust store. A successful CA
load count is not proof that a particular public host's chain validates.

The open-source
[Vita SDK header](https://github.com/vitasdk/vita-headers/blob/master/include/psp2/net/http.h)
names SSL detail bit `0x20` as `SCE_HTTPS_ERROR_SSL_UNKNOWN_CA`.
This is primary implementation documentation for Vita, **not** a demonstrated
PS5 firmware 13.60 contract. The project-pinned PS5 payload headers did not
provide that enum. On PS5, preserve the native error/detail unchanged; unknown
CA is a supported hypothesis, not a decoder result established by this audit.

No PS5, account, token, save, or certificate-store access occurred here.
Whether these roots are accepted by PS5's loader and whether a subsequent
bounded public metadata request succeeds still requires authorized physical
validation. The bundle alone does not establish the cause of the earlier
failure or authorize clearing its backoff/cache.

## Direct Root YR chain, host proof only

The public Mac handshake on 2026-10-05 still presented `*.github.io` → YR1 →
Root YR cross-signed by ISRG Root X1 for `raw.githubusercontent.com`. The leaf
SAN includes `*.githubusercontent.com`. The self-signed Root YR and its
cross-signed server variant have the same public-key fingerprint
`7e4e8838a8add6295de7ae3b047d3aba3488ab95db0a0aa56d897a00d8618bcf`
(SHA-256 of DER SubjectPublicKeyInfo).

OpenSSL 3.6.3 verified that captured leaf and YR1, with **only** the official
self-signed Root YR in CAfile, no CApath/CAstore, hostname
`raw.githubusercontent.com` and `sslserver` purpose. The resulting chain
terminated directly at Root YR: leaf → YR1 → Root YR. Thus the additional
anchor provides a demonstrably shorter valid chain without changing the
catalog URL or trusting the leaf/intermediate.

`tests/check_public_cert_release.py` retains the official YR1 certificate as
an offline test fixture (DER fingerprint above) and verifies the YR1 → Root
YR chain against only that root. The fixture is not production trust.

Whether chain length/path building explains PS5's preserved native error
detail `0x20` is **unknown**. Neither this host verification nor the direct
anchor demonstrates PS5 13.60's certificate-loader ABI or a physical fix;
only an authorized native request can establish success. No API/Pages mirror
or alternate hostname was added.

The public context now supplies all three approved PEM roots in **one**
`sceHttpsLoadCert` call, using the existing count-and-pointer-list declaration.
This avoids depending on whether repeated native calls append to or replace
that context's trust store. The offline stub verifies every list entry, order,
count, isolated owner and fail-closed handling of native errors. It does not
prove PS5 13.60's internal store semantics; sequential replacement is a
possible explanation for the previous GitHub-only failure, not a demonstrated
root cause. The existing Drive loader is unchanged.

## Reproduce certificate checks

Split each PEM block only in disposable host test storage, then run:

```sh
openssl x509 -in root.pem -noout -subject -issuer -dates -fingerprint -sha256 -text
openssl verify -check_ss_sig -CAfile root.pem root.pem
openssl x509 -in root.pem -outform DER | openssl dgst -sha256
```

Compare with the pinned DER fingerprints above and the independent official DER
files. Do not obtain replacement roots from a failed endpoint handshake or
automatically trust a server-provided leaf/intermediate.

## Redistribution review (.272)

Issuer grants and the provenance boundary are documented in
[CERTIFICATE-TERMS.md](CERTIFICATE-TERMS.md). This resolves the earlier missing
license evidence; it does not invent the original WE2 retrieval event.
