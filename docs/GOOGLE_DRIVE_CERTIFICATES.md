# Google Drive certificates

## Normal setup

No certificate setup is required. TostónSync v0.5.106 and newer includes the
working Google WE2 + WR2 bundle in the ELF. On first run, the daemon copies it to
`/data/tostonsync/cacert.pem` only if that file does not already exist.

The Google Drive card shows:

- certificate state: Working, Needs repair, or Missing;
- bundle composition: WE2 + WR2;
- the last successful Google TLS matrix verification.

If repair is needed, open **Settings → Google Drive → Advanced diagnostics**,
press **Repair Google certificates**, and confirm. TostónSync replaces the file,
rebuilds its Google HTTP context, and runs the host matrix. It reports success
only when all required hosts return their expected TLS/HTTP results.

Do not use `roots.pem` alone. A large general root bundle is not a substitute
for the WE2 + WR2 pair verified on PS5 hardware.

## Manual recovery — macOS or Linux

Use this only when the UI repair action is unavailable. Extract the release ZIP,
open a terminal in that folder, replace the documentation address `192.0.2.10`
with your PS5 address, and paste:

```bash
PS5=192.0.2.10; curl --fail --ftp-create-dirs -T certs/google-we2-wr2.pem "ftp://$PS5:2121/data/tostonsync/cacert.pem"
```

Then restart TostónSync and run **Google host TLS matrix**.

## Manual recovery — Windows PowerShell

Extract the release ZIP, open PowerShell in that folder, replace the
documentation address `192.0.2.10` with your PS5 address, and paste:

```powershell
$PS5="192.0.2.10"; curl.exe --fail --ftp-create-dirs -T "certs\google-we2-wr2.pem" "ftp://${PS5}:2121/data/tostonsync/cacert.pem"
```

Then restart TostónSync and run **Google host TLS matrix**.

The release also contains the same clean two-certificate file at
`certs/google-we2-wr2.pem` for inspection and recovery.

## Redistribution review (.272)

Issuer grants and the provenance boundary are documented in
[CERTIFICATE-TERMS.md](CERTIFICATE-TERMS.md). This resolves the earlier missing
license evidence; it does not invent the original WE2 retrieval event.
