# Building TostónSync

This document is the build reference. For the shortest Mac-only path, use
[QUICKSTART_MAC.md](QUICKSTART_MAC.md).

The delivered daemon, `bin/TostonSync v<VERSION>.elf`, is a PS5 payload. It does not run on
your computer; your computer only builds it.

## Supported Build Hosts

- macOS with Homebrew, LLVM 18 and GNU Make (`gmake`)
- Linux with Clang/LLVM 18 and GNU Make
- Windows through WSL2/Ubuntu

Native Windows builds are not supported because the PS5 payload SDK expects a
Unix-like shell environment.

## 1. macOS Toolchain

```bash
brew install llvm@18 make git curl unzip
```

Apple Silicon:

```bash
export LLVM_CONFIG=/opt/homebrew/opt/llvm@18/bin/llvm-config
```

Intel:

```bash
export LLVM_CONFIG=/usr/local/opt/llvm@18/bin/llvm-config
```

Persist the matching line in `~/.zshrc`.

Verify:

```bash
"$LLVM_CONFIG" --version
gmake --version
```

On macOS, always use `gmake`. Apple's `/usr/bin/make` is BSD make and can fail on
GNU Make syntax.

## 2. Linux / WSL Toolchain

Debian/Ubuntu/WSL:

```bash
sudo apt update
sudo apt install -y bash clang-18 lld-18 make git curl unzip
```

Fedora:

```bash
sudo dnf install -y bash clang lld llvm-devel make git curl unzip
```

If your distro does not package LLVM 18, install it from the official LLVM
packages for that distro.

## 3. PS5 Payload SDK

Pinned binary release (SDK v0.43, including firmware 13.60 support):

```bash
gmake sdk-setup
gmake
```

Run from the TostónSync source folder after installing the host tools. This
explicit setup downloads the official archive, verifies its published SHA-256
and installs under `build/sdk-v0.43/ps5-payload-sdk`, without changing `/opt`.
Normal builds and tests do not download anything. The project SDK takes
precedence over an old shell export; an explicit make command-line
`PS5_PAYLOAD_SDK=/path` override must contain the same verified CRT.

An older CRT can reject firmware 13.60 before `main()`, which means no logs,
startup notification or Web UI. Do not reuse another firmware's offsets.
The build now fails clearly rather than shipping that unsupported runtime.

macOS quarantine fix:

```bash
xattr -dr com.apple.quarantine build/sdk-v0.43/ps5-payload-sdk
```

The pinned archive and CRT checksums are in `tools/payload_sdk.py`. Updating
them requires an intentional SDK compatibility review. Firmware dispatch proof
is offline only; loader and jailbreak compatibility still need a console test.

## 4. Source Tree

In this workspace:

```bash
cd ~/Documents/Codex/TostónSync
```

If you are cloning fresh:

```bash
git clone https://github.com/<you>/TostónSync.git
cd TostónSync
```

The local folder name does not matter; the build output and PS5 paths are
TostónSync.

## 5. Included QR Generator

The reviewed `src/third_party/qrcodegen.c` and header are included. Build these
shipped bytes; do not replace them from an upstream branch. If either file is
missing or altered, restore it from the same TostónSync source tag before building.
The MIT notice remains
in both source files and in `CREDITS.md`.

## 6. Build Targets

macOS:

```bash
gmake            # daemon only
gmake app        # optional menu launcher
gmake dashboard-files
gmake all        # daemon + launcher
```

Linux/WSL:

```bash
make
make app
make all
```

Outputs:

```text
bin/tostonsync.elf
app/eboot.elf
build/dashboard/TostonSyncLauncher.bin
build/dashboard/install_dashboard.elf
```

Optional fake PKG hook:

```bash
make app-pkg      # or gmake app-pkg on macOS
```

`app-pkg` only works if you provide a compatible fake-PKG tool named
`prospero-pkg` on `PATH`. The open SDK does not ship that tool.

## 6.1 Dashboard Icon Without PKG

For macOS, the practical no-PKG path is:

```bash
make dashboard-files
make dashboard-install
```

The target uses the `ps5-payload-sdk` `install_app` approach: copy the app files
over FTP, then run a tiny installer payload through elfldr. Example connection:

```text
PS5_HOST=192.0.2.50   # example; use the PS5's current LAN IP
PS5_PORT=9021
PS5_FTP_PORT=2121
```

If your PS5 IP changes:

```bash
make dashboard-install PS5_HOST=<ps5-ip>
```

For multiple local PS5s, keep profiles in `.tostonsync-targets.json` and choose
one explicitly: `make targets`, then `make daemon-run TARGET=og` or
`make daemon-run TARGET=pro`. The profile IP is only the current address.

`build/dashboard/TostonSyncLauncher.bin` is uploaded to the PS5 as
`/system_ex/app/TOST10001/eboot.bin`; the dashboard expects the installed
executable to be named `eboot.bin`.

The native dashboard app checks the local daemon and starts the installed
`/data/tostonsync/tostonsync.elf` through loopback elfldr on port `9021` only if
positively stopped. It waits for a valid readiness response before opening the
UI and reuses a detected running daemon. Unknown markers or process inventories
block a new send. Do not deploy externally while the launcher is starting;
those tools do not share its lock. Autoload is optional, not
required for this click-to-start path; the jailbreak and elfldr are required.
Installation sends files and a registration payload but does not run the daemon.
Native execution/permissions must still be tested on the user's actual firmware.

## 7. PS5 Install

Permanent install target:

```text
/data/tostonsync/tostonsync.elf
```

Fresh installs do not need a pre-made `config.ini`; TostónSync creates:

```text
/data/tostonsync/config.ini
/data/tostonsync/imports/
/data/tostonsync/staging/
/data/tostonsync/sync.log
/data/tostonsync/.port
```

Browser imports use `imports/` on internal storage by default. If the safe
restore reserve does not fit, TostónSync falls back to a writable USB drive.
The resumable session is stored in `/data/tostonsync/import.session`.

Autoload order:

```text
/data/kstuff.elf
/data/tostonsync/tostonsync.elf
```

`kstuff` must run first because the watcher needs kernel access to read saves.

## 8. UI Endpoints

```text
http://127.0.0.1:1993/      PS5 browser, no PIN/password
http://<ps5-ip>:1993/       external LAN devices
```

The menu App opens the first URL. External devices are only gated if
`ui_auth_enabled = true` and an access code is set.

## 9. Runtime Configuration

Main config:

```text
/data/tostonsync/config.ini
```

Important defaults:

```ini
[general]
http_port = 1993
ui_auth_enabled = false
open_browser = true

[triggers]
modes = on_game_close, on_shutdown

[crypto]
use_kernel_resign = false
```

Backups are grouped by the stable PS5 user UID and title. Friendly aliases are
display-only, so renaming a user never creates a second backup identity:

```text
TostónSync/<stable_user_uid>/<TITLE_ID>/<backup>.zip
```

## 10. Troubleshooting

**`PS5_PAYLOAD_SDK is wrong or unset`**

`export PS5_PAYLOAD_SDK=/opt/ps5-payload-sdk` and verify
`$PS5_PAYLOAD_SDK/bin/prospero-clang` exists.

**macOS says the compiler cannot be opened**

Run:

```bash
sudo xattr -dr com.apple.quarantine /opt/ps5-payload-sdk
```

**`make` fails on macOS**

Use `gmake`.

**No toast appears on PS5**

Confirm `/data/tostonsync/tostonsync.elf` exists, the autoload path is exact,
and `kstuff` is loaded before TostónSync. Then read:

```text
/data/tostonsync/sync.log
```

**The UI is locked even though you do not want auth**

Set this in `/data/tostonsync/config.ini`:

```ini
ui_auth_enabled = false
```

Or create:

```text
/data/tostonsync/reset_auth
```

Then relaunch the daemon.

**The PS5 browser asks for a code**

Use `http://127.0.0.1:1993/`. If that still asks, you are not running the current
build.

## 11. Shipping A Release

Signed Releases contain exactly:

```text
TostonSync-v<VERSION>.elf
update-manifest.json
update-manifest.sig
```

The signature binds the ELF filename, size, SHA-256, version and release notes.
The Mac launcher script and documentation are source-repository files, not extra
Release assets. `gmake test-public` runs the self-contained public checks; the
full private qualification workflow additionally runs host/browser, sanitizer,
privacy, exact-source and independent artifact gates. The public subset is not
represented as that complete private workflow.

Never ship:

```text
/data/tostonsync/tokens.json
a real /data/tostonsync/config.ini from your console
```

Because the daemon links against `ps5-payload-sdk`, distributing the ELF requires
making the corresponding GPL source available.

## Corresponding SDK source

The exact v0.43 source used to identify the linked runtime is
[commit d9c9519](https://github.com/ps5-payload-dev/sdk/tree/d9c9519116944a7f1c22d262012c53b80b3520b7).
Its [complete source archive](https://codeload.github.com/ps5-payload-dev/sdk/tar.gz/d9c9519116944a7f1c22d262012c53b80b3520b7)
has SHA-256 `44b541e77eef201afb4fbb6b32af9b97a4cdf893fc2d944d228ff46a8235fd10`.
The pinned binary SDK archive has SHA-256
`a9cc9929f21b2b2c5d5b309f3bab4997067c45281c0622cf4838b1aecba66fcb`.
See [SDK-SOURCES.json](docs/SDK-SOURCES.json) and the full
[runtime notices](docs/SDK-LICENSES.md). Obtain sources explicitly; a build or
verification never downloads or contacts a console implicitly.
A distributor must retain the corresponding source and build inputs for its
binary, rather than relying on a mutable upstream branch or a binary-only SDK.

The project preserves this source in the public
[SDK fork](https://github.com/galdo320/TostonSync-sdk), with the annotated
[`tostonsync-sdk-v0.43` tag](https://github.com/galdo320/TostonSync-sdk/tree/tostonsync-sdk-v0.43)
at the [exact pinned commit](https://github.com/galdo320/TostonSync-sdk/tree/d9c9519116944a7f1c22d262012c53b80b3520b7).
The SDK source is hosted separately, not as a TostónSync release asset.
