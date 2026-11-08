# Signed release HTTPS transport

`http_get_release_limited()` and `http_get_release_to_fd()` use a fresh native
libSceHttp context with the two roots in `certs/release-roots.pem`. The generated
`release_cert_bundle.h` contains public certificates only. This trust does not
read or modify Drive's on-disk CA files, shared context, diagnostic switches, or
public display-metadata trust. A missing certificate loader, failed root load,
or uncertain native cleanup rejects the operation. Cleanup uncertainty blocks
subsequent release requests until daemon restart.

## Trust-anchor provenance

Retrieved on 2026-10-18 over HTTPS with hostname and chain verification using
the installed Homebrew OpenSSL CAfile. The DER hashes are checked by
`tests/check_release_http.py` independently of PEM comments and formatting.

| Root | Authenticated source | DER SHA-256 |
| --- | --- | --- |
| Sectigo Public Server Authentication Root E46 | [Sectigo's root inventory](https://www.sectigo.com/knowledge-base/detail/Sectigo-Public-Intermediates-and-Roots), linking to [certificate 4256644603](https://crt.sh/?d=4256644603) | `c90f26f0fb1b4018b22227519b5ca2b53e2ca5b3be5cf18efe1bef47380c5383` |
| ISRG Root X1 | [Let's Encrypt PEM](https://letsencrypt.org/certs/isrgrootx1.pem) | `96bcec06264976f37460779acf28c5a7cfe8a3c0aae11a8ffcee05c0bddf08c6` |

Both certificates are self-signed roots with CA:TRUE and Certificate Sign key
usage. Separate `openssl verify -check_ss_sig`, with only each supplied root
and no default CApath/CAstore, passed. No server leaf, intermediate, private key,
or unrelated root was added. The direct HTTPS endpoint
`crt.sectigo.com/SectigoPublicServerAuthenticationRootE46.crt` failed its TLS
handshake; the authenticated crt.sh link published by Sectigo was used instead.
No insecure retry was made.

Fresh verified Mac handshakes observed `api.github.com` and `github.com`
chaining through Sectigo DV E36 to E46. `release-assets.githubusercontent.com`
and `objects.githubusercontent.com` chained through Let's Encrypt YR1 and a
cross-signed Root YR to ISRG X1. These observations explain the chosen roots;
endpoint chains can change, and these are not leaf pins. The older public
metadata bundle did not validate the API or github.com chains.

## Request and ownership contract

Initial URLs must use HTTPS, default port 443 or explicit `:443`, and exactly:

- `api.github.com/repos/galdo320/TostonSync/releases/latest`;
- `github.com/galdo320/TostonSync/releases/download/vN.N.N/<encoded-asset>`.

The asset is one URL path component, at most 255 decoded bytes. Userinfo,
fragments, unescaped whitespace/control bytes, encoded controls/backslashes,
invalid percent encoding, path separators inside an asset, and other ports or
hosts are rejected. The caller's signed-release parser can impose stricter
initial URL, asset-name and version constraints.

Automatic native redirects are disabled and their configuration must succeed.
At most three redirects are followed manually; every destination must be an
absolute HTTPS URL on exactly `release-assets.githubusercontent.com` or
`objects.githubusercontent.com`. No bearer, client certificate, proxy
configuration, cookie jar, or authorization callback is supplied. Requests use
GET, an ASCII versioned User-Agent, and `Accept-Encoding: identity`. There is no
application retry; redirects are separate bounded request hops. GitHub's
[asset API](https://docs.github.com/en/rest/releases/assets) documents both
streamed `200` responses and `302` redirects; its
[network-domain reference](https://docs.github.com/en/actions/reference/runners/self-hosted-runners)
lists the release-assets host.

The total URL and Location limit is 4,096 bytes; response headers are limited to
8,192 bytes. Duplicate or empty Location, duplicate/invalid Content-Length,
unsupported content encodings, malformed headers and ambiguous
Transfer-Encoding plus Content-Length are rejected without truncation. Native
DNS/connect/send/receive timeout configuration must succeed (10 seconds each),
and a monotonic 60-second request budget is checked between operations. A
blocking native call can extend that budget by its configured per-call timeout.

Only a final `200` succeeds. Buffered bodies are capped at 512 KiB. The fd
variant requires an empty regular file positioned at zero and a signed expected
size from 1 byte through 16 MiB. It writes no bytes before the final `200`,
checks any declared Content-Length, rejects excess bytes before writing that
chunk, and requires exact EOF size. It handles short writes and EINTR. The fd
stays open on success and failure; partial bytes remain caller-owned. The
caller must discard a failed staging object and performs signed ELF hashing, embedded-marker validation, fsync and publication
separately. From .266 the release download is the ELF itself; historical schema-1/2
ZIP handling is not admitted by the .266 production client. The transport never opens,
renames or unlinks an output path.

## Native verification and test boundary

The isolated context retains the native certificate-verification defaults and
loads its own approved roots. No verification-disabling function, permissive
certificate callback, or diagnostic bypass is used. Enabling a Drive diagnostic
flag cannot affect this context. The existing minimum-TLS setter remains best
effort: preserved hardware evidence shows that it can return an error while a
verified request succeeds. This change does not invent a PS5 SSL-option ABI
from different-platform headers.

`tests/check_release_http.py` compiles the production transport and substitutes
an offline SDK object/response model. It exercises URL policy, redirect limits,
TLS-error propagation, fail-closed loading and cleanup, header/body bounds,
short/truncated responses, partial writes and fd ownership. These checks prove
control flow and validation, not a Sony TLS handshake. The unchanged Drive
and metadata suites retain their existing assertions; the context-lifetime
extractor stops at the separately tested release section.

No PS5, loader, installed certificate store or live console file was accessed.
Native certificate-chain, hostname/expiry enforcement, root-loader semantics,
firmware TLS compatibility and physical update acceptance still require a
separately authorized hardware round. Host TLS fixtures cannot establish those
native properties.

## Redistribution review (.272)

Issuer grants and the provenance boundary are documented in
[CERTIFICATE-TERMS.md](CERTIFICATE-TERMS.md). This resolves the earlier missing
license evidence; it does not invent the original WE2 retrieval event.
