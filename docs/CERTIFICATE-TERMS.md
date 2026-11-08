# Embedded HTTPS certificates: provenance and redistribution

The files in `certs/` are project-selected certificate sets. They were not
extracted from a documented Mozilla/NSS bundle; no MPL license is inferred.
Each certificate is distributed complete and unchanged, under its issuer's
certificate redistribution grant. No private key is included.

| Embedded certificates | Official evidence and grant |
| --- | --- |
| Google WE2, WR2 and GTS Root R4 | [Google Trust Services TLS CP/CPS v6.7](https://pki.goog/repo/cp-cps-tls/6.7/GTS-CP-CPS-TLS.html), certificate tables and section 9.5: royalty-free reproduction/distribution of complete certificates; no unapproved derivatives. |
| ISRG Root X1 and Root YR | [ISRG CP/CPS v6.0](https://letsencrypt.org/documents/isrg-cp-cps-v6.0/), root table and section 9.5: complete-certificate reproduction/distribution permission. |
| Sectigo Public Server Authentication Root E46 | [Sectigo TLS CP/CPS v6.2.7](https://www.sectigo.com/uploads/legal/TLS-Combined-CP-CPS-v6.2.7.pdf), section 9.17.3 (PDF page 91 / printed page 89): complete-certificate reproduction/distribution permission. Section 9.5 alone is not the grant. |

Reviewed November 6, 2026. Current official fingerprints match the embedded
DER bytes. The initial WE2/WR2 download event was not recorded: present identity
is established by the issuer's published fingerprints, not an invented history.
WE2 and WR2 are intermediates; this document does not call them roots.
Issuer document copyright and certificate redistribution terms are distinct.

Transport roles and the exact fingerprint inventory remain in
[Google Drive certificates](GOOGLE_DRIVE_CERTIFICATES.md),
[public metadata TLS](PUBLIC_METADATA_TLS.md) and
[signed release TLS](RELEASE_UPDATES_TLS.md). No certificate changed in .272.
