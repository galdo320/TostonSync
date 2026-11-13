# TostónSync™ for PS5

TostónSync backs up PS5 saves to your own USB drive or Google Drive and provides
a browser interface for reviewing backups and restoring compatible saves.
It runs as a payload on a jailbroken PS5. It does not use PSN or a shared cloud
account. English and Spanish are available in the interface.

**This is experimental software that writes save data.** Keep an independent
backup before restoring. A passing host test does not establish compatibility
with every game, console firmware or jailbreak. RAW recovery is for compatible
same-console saves; Portable transfers have additional target and format checks.
See [save compatibility](docs/SAVE_COMPATIBILITY.md).

## Requirements

- A jailbroken PS5 with a working ELF loader and the required save-access services.
- A trusted local network and a recent browser on a phone or computer.
- A usable USB data volume, or your own Google Drive OAuth application/session.
- Free internal space for staging and rollback copies before Restore.

The build pins ps5-payload-sdk v0.43. Firmware dispatch support in that SDK is
not a claim that every loader or firmware was physically tested. FTP backup
support was removed in .269; old FTP settings are ignored without being erased.

## Install or update from a file

1. Download the three matching assets from a signed Release:
   `TostonSync-v<VERSION>.elf`, `update-manifest.json`, `update-manifest.sig`.
   Keep their names. Do not use an ELF from an unrelated build directory.
2. If TostónSync is already running, open `http://<ps5-ip>:1993/` and use
   **Settings → Updates → Update from a file**. Saving an update changes the installed
   file; the current process keeps running.
3. Check the saved version, then choose **Restart** separately to load it from
   disk. Never interrupt an update or repeat a request whose result is unknown.

For a stopped daemon, the signed Mac launcher is in this source repository:

```sh
./tools/start-tostonsync.command /path/to/folder-with-the-three-release-assets
```

It verifies the manifest, signature, byte count and SHA-256 with the embedded
public keys. It asks for the PS5 address and web port (1993 by default). A ready
daemon is reused; only a refused connection permits one loader send. An uncertain
response stops without retrying. The jailbreak and loader must already be active.
The root `Start TostónSync.command` is the shared compatibility implementation.
See [Mac setup](QUICKSTART_MAC.md) and [building from source](BUILD.md).

Signed updates use a direct ELF, schema-3 manifest and detached Ed25519 signature.
The signed manifest also binds the release-notes hash. Checking is separate from
installing; installation and Restart require explicit actions. A private or
unreachable repository reports unavailable updates without asking for a GitHub
token. Versions .263–.265 need a file update to reach the direct-ELF client.

## Use backups and Restore safely

Choose a backup mode in **Settings → Automatic backups**. **Manual only** disables automatic backups;
a manual backup is still possible from a game's menu. USB and Google Drive are
separate destinations. A completed transfer without a confirmed receipt is not
a verified backup. Protected backups are excluded from retention and Cleanup.

After a Restart the in-memory backup catalog is empty. Opening a tab does not
scan destinations or prepare a Restore. Choose **Scan backups** explicitly,
then select the exact game, profile and backup. A failed or incomplete Scan is
not evidence that your backups disappeared. Older USB folders without identity
markers can be listed but cannot authorize Cleanup.

Restore from a backup follows **Verify → review → final confirmation**. Unknown
method, verification or protection blocks the final action. Keep the game fully
closed. Complete RAW Restore preserves the current set, publishes the original
backup bytes and reads them back against their original member hashes. A mounted
metadata inspection uses a disposable copy, never a source that will be published.
Portable and selected Restore use their own format, selection and target checks;
these are not promises that every mode or game has been physically validated.

**Restore previous save** is a distinct operation using the retained rollback.
Its mandatory confirmation reports what is known; it does not claim a fresh
backup verification. It exchanges the current set with the retained set rather
than silently deleting the displaced saves. Do not use it as a substitute for
investigating an uncertain Restore result.

Do not open a game after an uncertain Restore. Preserve the log and backups and
seek help before retrying or deleting anything. Review every deletion separately.

## Local-network security and privacy

The web interface uses plaintext HTTP. Keep it on a trusted LAN, never expose
port 1993 to the internet, and do not place an unreviewed proxy in front of it.
Enable an access code for external devices. Access protection is optional and
off by default; PS5 loopback access bypasses it. A device able to inspect local
HTTP traffic can observe that traffic; the access code is not TLS.

Requests accept literal IP addresses, `localhost`, or the explicitly configured
`general.http_hostname` with the actual web port. A present Origin must match;
clients without Origin remain supported. Do not add an arbitrary DNS name just
to bypass a rejected request. Frames are denied. See [SECURITY.md](SECURITY.md)
for the exact threat boundary and private vulnerability reporting.

Save archives and support bundles can identify games, profile labels, timestamps
and paths. Review them before sharing. Support output excludes Drive tokens,
client secrets and private keys; it is not a promise of anonymous diagnostics.
No save data is included in this repository or its release assets.

## Build and source

```sh
gmake sdk-setup  # explicit, checksum-verified SDK setup
gmake           # build the daemon; does not contact a PS5
```

See [BUILD.md](BUILD.md) for LLVM 18, the pinned SDK source/archive checksums and
build inputs. Release assets contain only the ELF, manifest and signature.
GitHub's generated source archives are separate. Source must correspond to the
distributed binary; never treat a different revision as its source.

## Help and credits

For ordinary problems, use the repository's issue tracker after reviewing any
attached diagnostics. For security issues use the private channel in
[SECURITY.md](SECURITY.md), not a public issue. [Support guidance](docs/SUPPORT.md),
[credits](CREDITS.md) and [third-party notices](THIRD_PARTY_NOTICES.md) provide more
detail. Donations through [Ko-fi](https://ko-fi.com/galdo) are optional.

## License

TostónSync is free software under the GNU General Public License, version 3 or
(at your option) any later version. See the complete [LICENSE](LICENSE) and
[THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md) for dependency terms.

## Name and logo

The GPL covers the code; it does not grant rights to the TostónSync name or
logo. Forks must use a different name and logo.

PlayStation is a trademark of Sony Interactive Entertainment. TostónSync is not
affiliated with or endorsed by Sony Interactive Entertainment.
