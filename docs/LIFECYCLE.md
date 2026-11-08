# Local lifecycle helpers

## v0.5.219 operational delivery

The build defaults `TOSTONSYNC_STARTUP_VALIDATION_ONLY` to zero and reuses the
unchanged .216 operational path below, including normal root/assets and PIN,
cookie/nonce authentication. Host tests still compile the historical temporary
path explicitly; it is not an operational INI option or a releasable hold.
The .218/.178 artifacts and physical evidence remain historical, not replaced.

Operational startup is not read-only. After the cooperative lock, existing
initialization can migrate local state, save config defaults/migrations, create
or rotate logs/CA files, trim history and consume configured auth-reset markers.
It can rename `restore.busy` to `restore.interrupted`, write PID/port markers and
open the browser according to the existing INI. No new housekeeping is added.

Before the HTTP bind, `import_session_init()` can normalize and persist the
checkpoint, revalidate selected ZIP linkage and retain interrupted selected
claims as uncertain. READY is not age-expired, but FAILED or stale RECEIVING
sessions can be released under existing policy. An interrupted recovering
candidate can be removed. Unprotected `.part`/`.inspect` staging older than 24
hours can be removed from state imports and attached USB `.imports`; preserved
and uncertain-state guards remain. Neither checkpoint nor staging is promised
byte-for-byte unchanged merely because triggers are manual-only.

The existing watcher/idle workers, local watchdog and metadata scans resume.
Manual-only retains suppression of automatic backup retry/job replay and enqueue;
explicit manual/Selected RAW operations remain available. Manual/local Drive
initialization remains lazy, without token reads, refresh/account calls or folder
creation until an explicit Drive action. Save recovery barriers still block
uncertain operations. No save engine, cleanup policy or RAW receipt permission is
changed by .219; no physical operation is authorized by building it.

A physical validation must separately accept these existing startup effects and
avoid loading .219 beside a live .218. No remote STOP or retirement mechanism is
added. Platform power cycling is not a demonstrated graceful daemon shutdown.
The first validation stops after normal authenticated UI/config/metadata checks;
backup/import/preflight/publication remain separate authorizations.

## v0.5.217 temporary startup validation delivery

The temporary build marker `TOSTONSYNC_STARTUP_VALIDATION_ONLY` is compiled into
this delivery only. It is not an INI option, BOOT_HELD/lifecycle state, a safe
mode, or an automatically releasable startup subsystem. The operational .216
delivery and its evidence remain archived. A later operational transition needs
separate implementation/authorization; timeout, restart or a GET never enables it.

Acquire the unchanged cooperative `instance.lock` first. Require an existing,
stable literal manual-only INI and load it without creation/default migration or
persistence. Observe `import.session` with bounded stable reads using the existing
parser, preserving actual states (READY does not expire by age). An invalid,
changing or unavailable checkpoint remains UNKNOWN/BLOCKED, not invented IDLE.
Historical receipt fields do not confer any operational authority or claim.
Checkpoint/source ZIP integrity is not established merely by parsed metadata.

Emit `startup_import_observation` through the existing transport output. There
is no new import/report HTTP endpoint. Do not start the watcher, workers, replay,
retry evaluation, destinations, Drive, auth reset, browser or status watchdog.
No INI change disables the browser: its configured value remains untouched.
Only GET `/api/config` and GET `/api/inspect-save-metadata` are admitted, with
the existing access-protection checks. All other routes (including GET imports,
downloads and OAuth) and methods return `startup_validation_only` in backend
before body admission/handler execution. This delivery cannot perform Backup or
Restore. It uses the same metadata collector and save gate without starting a
watcher; metadata UNKNOWN is still UNKNOWN and is not a permission to mutate.

The file lock survives all HTTP activity and is released only after HTTP
teardown. No lifecycle IPC/helper/remote STOP, cleanup, process takeover or signal
is introduced. Ordinary .216 startup stays in source but is not admitted by this
temporary delivery. Host tests are not physical PS5 startup/exclusion proof.

## v0.5.216 cooperative operational startup

Normal startup now acquires `flock(LOCK_EX | LOCK_NB)` on the canonical regular
file `/data/tostonsync/instance.lock`, independent of configurable state directory
or HTTP port. Only return zero admits startup. The existing canonical state
parent must already be a safe directory; the file must be regular, owned by the
effective UID, private and singly linked. Descriptor/path device and inode must
agree after acquisition. No PID/content reading, truncation or stale cleanup is
used. The descriptor remains open through HTTP restarts and closes only after
operational teardown and zero admitted operations. The file is never unlinked.

This prevents accidental duplicates only among cooperating versions using that
same inode. It does not prove kernel/payload identity, exclude an uninstrumented
legacy daemon, or resist deliberate namespace replacement by privileged software.
Process death releases the kernel lock; a persistent file or stale PIDfile grants
no authority. A failed or unexpected lock result blocks before operational work.
SDK declarations/imports and earlier TostónSync use justify the offline change;
host tests do not prove physical PS5 filesystem locking behavior.

AF_UNIX lifecycle IPC is not started or required on this operational path. Its
existing implementation and historical evidence remain preserved. Internal
operation admission, save gate, recovery/checkpoint and manual-only guards remain
active independently. No remote STOP or VERIFY can be approved using the file
lock, PIDfile, version or HTTP. Helpers remain BLOCKED/UNKNOWN without their
original authenticated identity and supported kernel evidence. There is no
fallback IPC, service manager, takeover or new shutdown endpoint.

The bind/ENOTSUP investigation is closed; v0.5.215 stays diagnostic-only historical
evidence, not the operational alias. No new physical execution is recorded here.

## Historical lifecycle IPC

This is an instance-specific observation/stop barrier, not an HTTP API, UI,
service manager, restore tool or daemon replacement. Compilation and host tests
do not prove PS5 runtime behavior. No physical execution was performed for this
change; the commands below are usage instructions, not recorded runs.

`gmake lifecycle-helpers` compiles three separate payloads:

| Internal build | Versioned release role |
| --- | --- |
| `bin/lifecycle-inspect.elf` | `TostonSync Lifecycle Inspect v0.5.212.elf` |
| `bin/lifecycle-stop.elf` | `TostonSync Lifecycle Stop v0.5.212.elf` |
| `bin/lifecycle-verify.elf` | `TostonSync Lifecycle Verify v0.5.212.elf` |

## v0.5.212 operational delivery

### v0.5.215 diagnostic-only delivery

The .215 daemon alias is intentionally not operational and must not be installed
for autoload. It observes the unchanged single AF_UNIX pathname bind and always
returns before configuration, imports, HTTP or watcher/workers. Provider metadata
is bounded module information from the current callable, not binary attestation;
no addresses are reported. Filesystem metadata uses the pinned SDK statfs
contract and rejects an unrecognized structure version. Its raw syscall wrapper
does not update errno, so that errno stays UNKNOWN rather than reusing an older
error. Bind/socket errors are captured immediately. A successful bind only uses
the existing own-device/inode reservation release; uncertainty never permits
removing a preexisting/replacement socket. No fallback or operational startup.

The unchanged .214 operational artifacts and .212 physical bind error remain
preserved. Neither host tests nor the diagnostic ELF establish a corrected PS5
bind or an operational server.

Normal operational startup resumes after the diagnostic-only .211 release.
The platform ancestor `/data` must be a literal directory owned by the effective
UID with an exactly matching canonical path. Group/other write bits there do
not reject admission. TostónSync does not change `/data` permissions or owner.
The owned state directory must still reject group/other writes, and the private
lifecycle directory must still reject all group/other permissions.

This is a cooperative single-instance contract: modern instances do not rename
or replace the namespace. A hostile payload with equivalent privilege that
replaces `/data` or its children is out of scope. Private permissions alone do
not make a writable ancestor immune to replacement. No directory lock, bindat,
process inventory, takeover or automatic residue cleanup is added.

The canonical socket bind remains the exclusive reservation, not identity or
STOP authority. Build and host test success do not establish PS5 runtime or
game acceptance. The .211 diagnostic artifacts remain historical evidence;
the current ELF is not diagnostic-only.

## Historical socket instance reservation (v0.5.210–v0.5.215)

From v0.5.210 the daemon reserves the fixed protected lifecycle socket atomically
before operational startup. Reservation is exclusivity, not kernel identity or
STOP authority. It does not require a global process inventory, an HTTP port or
a PIDfile. Authenticated lifecycle identity and credentials retain their existing
fail-closed checks independently; incompatible kernel identity stays UNKNOWN.

The canonical `/data/tostonsync` parent must already exist safely. A missing or
unsafe parent blocks rather than creating a new base and bypassing legacy state
migration. Only the private lifecycle directory/socket infrastructure is created.
A preexisting pathname blocks with `reservation_path_present`, ownership UNKNOWN;
it does not confirm another live instance. No stale cleanup or fallback is allowed.

The reservation survives HTTP restarts and lifecycle service quiescence. Release
occurs only after operational teardown, with no admitted detached operations, and
unlinks only the owned socket with the same device/inode. A replacement is never
removed; a crash or incomplete close can leave a residual pathname that blocks
the next startup. Automatic residue recovery is deliberately not implemented.
This contract covers cooperating modern instances, not uninstrumented legacy
payloads or another privileged payload that removes the protected namespace.

INSPECT reports the daemon's complete identity and a read-only snapshot. The
helper binds PID/start time to kernel observations and authenticates the local
socket peer; it does not infer identity from a process name or PID file. Version,
build, module and nonce identify that reported instance. They are not proof that
its bytes match a local ELF hash.

The pinned SDK does not provide supported proof that the payload owns a dedicated
process rather than a hijacked carrier. Native identity therefore reports
`process_model=0` (UNKNOWN), and native STOP remains **BLOCKED**. Never edit this
to DEDICATED to make a request pass. A legacy instance without this authenticated
protocol is also BLOCKED; there is no PID-file fallback, takeover or forced kill.
VERIFY also remains UNKNOWN for carrier/unknown ownership: observing that the
carrier still exists or has exited does not by itself prove this payload exited.

## Explicit identity input

Keep the exact successful INSPECT JSON. The offline serializer validates every
required field and emits exactly one 760-byte protocol-1 frame from the
project-owned `src/lifecycle_ipc.h` layout. This is not a guessed native kernel
ABI. Strings are preserved without truncation or normalization; UNKNOWN is not
converted into PASS. A serialized snapshot does not approve a stop: the daemon
must reserve admission and observe fresh CLEAR checks with no queued/active work.

```sh
python3 tools/lifecycle_identity.py stop inspect.json > stop-identity.bin
python3 tools/lifecycle_identity.py verify inspect.json > verify-identity.bin
```

The serializer reads a local file/stdin and writes binary stdout only. It makes
no network, process or PS5 calls. STOP and VERIFY are distinct commands; neither
helper accepts an omitted, incomplete or mismatched original identity.

The existing SDK transport is `prospero-deploy`; `-i` carries stdin to the helper.
After separate authorization for physical execution, an already configured host
can supply the frames using the existing transport:

```sh
SDK=build/sdk-v0.43/ps5-payload-sdk
"$SDK/bin/prospero-deploy" -h "$PS5_HOST" -p "$PS5_PORT" bin/lifecycle-inspect.elf
"$SDK/bin/prospero-deploy" -h "$PS5_HOST" -p "$PS5_PORT" -i bin/lifecycle-stop.elf < stop-identity.bin
"$SDK/bin/prospero-deploy" -h "$PS5_HOST" -p "$PS5_PORT" -i bin/lifecycle-verify.elf < verify-identity.bin
```

Save only the helper's complete INSPECT JSON as `inspect.json`; transport logs
are not identity input. The native helper uses the protected same-device local
socket, not an HTTP route. A preexisting/stale socket is never automatically
deleted, so an unsafe or unavailable endpoint stays BLOCKED.

## Blocked INSPECT diagnostics

INSPECT v0.5.206 reports the first failed check as `outcome=BLOCKED` with a
specific `reason` and diagnostic `stage`, `operation`, `result`, `errno`,
`errno_name`, `expected` and `observed`. Available literal `lstat` metadata is
reported as path/type/mode/UID/GID; no file content is read. An absent IPC is not
called unsafe. Metadata that cannot be observed is `ipc_metadata_unverified`,
not evidence that IPC is present. A semantic mismatch has no fabricated syscall
errno; unavailable/non-applicable values and unmapped errno names are `null`
(UNKNOWN where the check needs that information).

Stages cover parent/socket metadata and path resolution, connection, kernel
peer credentials, protocol handshake and instance identity. No diagnostic
failure becomes approval. The helper never follows a socket symlink, repairs
permissions, creates IPC paths, removes stale sockets, tries another path or
uses HTTP/TCP as an IPC fallback. Failure diagnostics do not publish a nonce or
complete kernel credential record. A reported helper version is not a daemon
version. Successful INSPECT retains the original protocol-1 JSON schema.
`IPC_SOCKET_CREATE` and `IPC_SOCKET_TIMEOUT` describe the existing client socket
and timeout setup; they do not create an IPC filesystem node.

These diagnostics have only been validated offline. The observed v0.5.205
physical result `local_socket_unavailable_or_unsafe` does not establish which
check failed; identifying its actual cause requires separately authorizing one
new INSPECT execution. STOP/VERIFY and the native process-model limitation are
unchanged.

## Results and bounded verification

An accepted STOP sends one SIGTERM to the authenticated instance itself. Acceptance
is not exit proof. STOP waits up to 30 seconds using kernel PID/start-time checks;
VERIFY performs the same bounded checks without sending a signal.

- `INSTANCE EXITED`: the original PID is absent.
- `PID REUSED`: the PID belongs to a different kernel start identity; the original
  instance is gone, and the new process is never signalled.
- `PROCESS STILL RUNNING`: the original kernel PID/start identity is still present.
- `UNKNOWN`: kernel identity, timing or protocol proof was unavailable.

The `verification` field uses those four results. If the original process remains
present at the 30-second deadline, `verification=PROCESS STILL RUNNING` and the
separate `outcome=STOP TIMEOUT`; neither field is exit proof.

There is no resend, SIGKILL escalation or automatic thaw after signal failure.
If the STOP reply is lost, do not resend STOP: use VERIFY with the original
identity. A timeout or UNKNOWN result is not permission to deploy another daemon.
