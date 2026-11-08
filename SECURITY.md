# Security

## Report a vulnerability privately

Use GitHub's **Security → Report a vulnerability** for this repository:
[private vulnerability report](https://github.com/galdo320/TostonSync/security/advisories/new).
Do not put an exploitable issue, save data, access codes, OAuth credentials or
private keys in a public issue. Include the version, affected route/action,
expected and observed behavior, and a minimal synthetic reproduction.

## Supported boundary

TostónSync is a privileged payload on a jailbroken console, intended for a
trusted home LAN. It is not a sandbox for hostile consoles, local processes,
physical devices or other administrators. Keep the console and its ports off
the public internet. There is no remote telemetry or central service account.

The interface is HTTP, not HTTPS. Its optional access code is off by default;
loopback clients intentionally bypass it. Enable protection for external devices,
use an isolated trusted network, and assume an on-path device can read or alter
HTTP traffic. Do not reuse an important password. Browser Drive credentials are
stored in that browser's local storage; a compromised browser/profile is outside
the daemon's protection. Clear/disconnect the browser session when appropriate.

## HTTP and settings controls

- Host must be a literal IP, localhost or the configured hostname, with the
  server's web port. Duplicate critical headers, malformed request framing and
  oversized request targets are rejected. Forwarded headers do not grant trust.
- A present Origin must match Host. An absent Origin remains supported for
  launchers and native clients. State-changing actions require POST and their
  existing JSON/binary content types; GET observations do not authorize actions.
- Frames are denied with X-Frame-Options DENY and CSP frame-ancestors 'none'.
  CSP still allows the existing inline application scripts/styles. It is not
  an assertion that arbitrary same-origin script execution is safe.
- Session material uses operating-system randomness and expires on the server.
  Logout and access-code changes revoke existing cookies. Cookies are HttpOnly
  and SameSite; Secure cannot protect a plaintext HTTP deployment. Failed-login
  throttling has per-client and global limits.
- INI-bound HTTP fields reject control characters, embedded NUL, malformed JSON,
  ambiguous duplicate keys, invalid types and overlong values before mutation.
  Valid Unicode labels and bracket/symbol characters remain supported.
- Drive error messages are bounded known diagnostic codes, not raw OAuth
  responses. Logs/support copies filter credential material. Support bundles
  use a fresh private directory and explicit member list, excluding stale files.

## Updates, files and remaining limits

Signed updates require the embedded Ed25519 key, signed manifest, exact ELF size
and hash, supported minimum version and no downgrade. A GitHub account compromise
alone cannot forge an update. Signing-key compromise, console compromise or a
malicious build environment requires a separate recovery procedure. Do not send
private keys in a report.

Restore, backup and rollback safeguards are defense in depth, not a guarantee
against hardware faults, power loss or incompatible games. Keep independent
copies. Stop after an uncertain write; do not repeat it or erase its evidence.
A host/browser test is distinct from physical validation on a console.

No reverse proxy, DNS deployment, hostile-LAN isolation or encrypted UI transport
is claimed. Public-source publication requires a separately reviewed clean tree,
corresponding-source availability and enabled private vulnerability reporting.
