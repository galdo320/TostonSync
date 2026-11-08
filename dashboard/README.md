# TostónSync native dashboard app (no PKG required)

Click the TostónSync icon to open the app. Its native executable checks the
local daemon first. If positively stopped, it sends the installed
`/data/tostonsync/tostonsync.elf` to local elfldr on `127.0.0.1:9021`, waits for
a valid TostónSync readiness response, then opens the loopback Web UI. A
positively detected running daemon is reused. Unknown, stalled or
foreign listeners do not grant permission to launch another daemon.

The jailbreak and elfldr must already be active. kstuff is still needed for
saves. This icon cannot start the jailbreak or loader, and cannot make an
unsupported firmware compatible. It does not perform a restore or change
settings/credentials.

When the daemon starts, it shows its detected LAN Web UI address even at the
default Important only notification level, unless notifications are disabled.
Use that address from a phone or computer. The console browser opens the
separate loopback address; `127.0.0.1` is not the PS5 address on other devices.
If LAN is unavailable, the notice says it is running locally and waiting for
LAN. Installing the app files does not itself start the daemon.

If nothing opens, first check only whether the static Web UI is reachable:

```bash
curl --silent --show-error --connect-timeout 3 --max-time 5 \
  --output /dev/null --write-out 'HTTP %{http_code}\n' \
  http://192.0.2.50:1993/
```

Replace the example IP with the console's current address and use its configured
Web UI port if different. This does not execute browser scripts or fetch private
status/logs. HTTP 200 proves page reachability, not daemon version, successful
native launch or restore compatibility. Preserve the launcher message/install
output if it fails; do not redeploy, clear markers or restore a save blindly.

An unreadable/malformed port or PID marker, incomplete process inventory, or an
active daemon with a custom state directory blocks a new loader send. The local
launcher lock coordinates clicks, not external deployments: the final check
and another tool's launch are not one atomic operation. Do not run another
installer or `daemon-run` concurrently.

## Build locally (no console access)

```bash
gmake app
gmake dashboard-files
gmake test-public
```

Outputs include:

```text
app/eboot.elf                         native ELF, not a loader payload
build/dashboard/TostonSyncLauncher.bin
build/dashboard/TOST10001/eboot.bin    same fake SELF, canonical install name
build/dashboard/TOST10001/sce_sys/param.json
build/dashboard/TOST10001/sce_sys/param.json.system
build/dashboard/TOST10001/sce_sys/icon0.png
build/dashboard/install_dashboard.elf registration payload, not the app
bin/tostonsync.elf                    daemon payload
```

Delivery names include the app name and version:
`bin/TostonSync v<VERSION>.elf`, `bin/TostonSync Launcher v<VERSION>.elf`
and `build/dashboard/TostonSync Installer v<VERSION>.elf`.
Signed Releases contain exactly the daemon ELF, `update-manifest.json` and
`update-manifest.sig`. Build the optional native launcher and installer locally.
Internal build/install names above stay fixed; do not rename the installed daemon
or native `eboot.bin`. The public `test-public` target covers the self-contained
source checks, not the complete private release qualification suite.
The clean public source contains the app source,
metadata, icon, Makefile and executable offline checks, not development builds.
There is no fabricated `.pkg`; the optional `app-pkg` target requires external
compatible tooling and reports an error if none is installed.

## Install only after authorization

Confirm the selected console's identity and current address. Keep the game
closed; do not install while a backup/restore or another install is active.
FTP must permit writes to `/data`, `/user/app` and `/system_ex/app` and support
`MTRW` for the writable system mount. elfldr must accept the registration payload.

From the source workspace, replacing the example with the current address:

```bash
gmake dashboard-install PS5_HOST=192.0.2.50
```

Or choose one explicit local target profile: `gmake dashboard-install TARGET=pro`.
This command writes to the selected console. It stages the daemon via a
temporary FTP file and rename, installs the native app/icon/metadata and sends
the registration payload. It stops if a required write/rename/send fails and
does not run or replace the daemon. A failed install may leave staged app files;
it is not an atomic rollback of the shell's app database. Transport success
alone does not prove that registration completed: confirm the icon on the PS5.

## Controlled hardware acceptance

Local tests cover the launcher state machine and install commands with mocks.
Native app execution, module availability, notification/browser launch and
firmware permissions are not proven until tested on a specifically authorized
console. No real consoles, accounts or saves are required for the local checks.

1. With the jailbreak/loader active and daemon positively stopped, click the
   installed icon. Confirm a TostónSync response and its reported version.
2. Close only the browser and click the icon again. Confirm the same daemon
   run/PID, with no replacement log. No saves need to be opened or changed.
3. Check the configured HTTP port, loader-unavailable diagnostic and browser
   opening behavior only when separately authorized; do not kill active jobs.
4. If any phase fails, preserve the logs and stop. Do not retry installation or
   terminate processes blindly. No game restore test is implied by app startup.
