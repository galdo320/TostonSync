# Save compatibility

TostónSync backs up saves and chooses a supported restore method automatically.
It does not bypass incompatible encryption or promise that any game can read
any other platform's save. A successful PFS mount alone is not that proof.

| Input | Supported path | Required checks |
| --- | --- | --- |
| Encrypted PS5 RAW | Exact restore to compatible local slots | Existing local user, game closed, slot names, database rows and matching sealed keys |
| Manual selected-container RAW | Dedicated exact-selected preflight/commit; generic full-title Restore/recovery blocked | Explicit literal selection, declared service companions, stable encrypted images and complete checksums |
| TostónSync checksummed portable PS5 backup | Restore into destination-created PS5 slots | Unique local user, all target slots/metadata, every payload checksum, retained rollback and installed-content verification |
| Legacy/decrypted third-party archive | Inspection; unsupported formats remain blocked | Never bypass missing integrity or target identity checks |
| PS4 ↔ PS5 ↔ PC game payload | Not implemented as a general converter | A separate, validated converter for that game, region, version and direction |

## Manual selected RAW download (v0.5.201)

In **Saves**, open **Selected RAW** to review the existing metadata-only
inventory. Select active names literally, review the separate service companions
and confirm that the game is fully closed. SystemSaveData remains an active
container with global-data implications, not an independently playable slot;
roles are UNKNOWN if metadata cannot identify them. This does not mount or read
decrypted save contents. Busy/running/pending recovery and uncertain selected
images or service existence block the export. Unknown registration does not
pretend to be PASS and is not required for encrypted byte copying.

`POST /api/download/raw-selected`, for example:

```json
{"target_uid":"00000001","title_id":"PPSA00001","selected_slots":["ExactSlotName"],"service_slots":"ExactSlotName","game_closed_confirmed":true}
```

`service_slots` declares exactly the selected names whose `sdimg_sce_bu_`
companions were observed; use an empty string for none, or newline-separated
literal names for several. Absence is not UNKNOWN, a wildcard, or permission to
invent/include another service. Selection is mandatory and limited to 32 active
names / 64 images. Only selected active images and declared companions enter
the ZIP. Missing selection never falls back to the full-title download.

Every artifact is marked **partial** in its manifest and filename, even when
all active containers were explicitly selected. It is not a full recovery
source, a portable export, or a newly supported selective RAW Restore format.
The normal inspector verifies its exact scope, CRC and checksums but blocks
full-title Restore/recovery. Original full backups remain separate.

Source metadata and SHA-256 are compared before, during ZIP streaming and after;
fresh UID, observed running state, recovery and inventories are checked again.
`X-TostonSync-Zip-SHA256` is computed over the closed ZIP bytes, **not** the
content fingerprint. Verify the downloaded file locally against that header.
The gate serializes TostónSync only: game/system writers are not locked and these
observations cannot prove a globally atomic filesystem snapshot. There is no
retry, automatic destination, history/dedupe update, retention or configuration
change. Failed new ZIPs remain evidence; successful temporaries are released
after delivery. A lost/interrupted HTTP response is not a verified local backup.

## Selective portable restore API (v0.5.188)

An existing normal, checksummed portable import can be checked and restored
for an explicit subset of its literal slot names. No derived ZIP or new import
is necessary. This release exposes selection through the API, not a new UI
picker. An API check does not perform restore.

`POST /api/import/compatibility` example:

```json
{"id":"existing-import-id","phase":"check","target_uid":"00000001","selected_slots":["ExactSlotName"]}
```

The response separates `available_slots`, `selected_slots`, `ready_slots` and
`written_slots`; `total_slots` is the selected scope. A successful six-slot
import / one-slot check returns available=6, selected=1, ready=1, total=1,
written=0, `ready=true`, one individual ready report and a `selection_receipt`.
Source archive hashes and every checksum remain validated, while destination
checks/mounts are restricted to selected slots. Unknown identity, missing
native containers, SQLite errors or unmount uncertainty still block approval.

Restore requires a separately authorized `POST /api/import/commit` with the
same `id`, `target_uid`, `selected_slots` and server-issued
`selection_receipt`. The server repeats target compatibility and compares its
durable approval before enqueuing; the worker verifies it again before save
access. The receipt binds import hashes, title, fresh destination UID, available
inventory count and selected set. Reordering a set is harmless; changing,
adding or removing a member requires a new explicit check. Slot bytes are
never case-folded, Unicode-normalized or inferred from menu positions.

Omitting `selected_slots` retains historical restore-all behavior only for an
import session that has never requested explicit selection. Once it has,
omission and generic upload restores are blocked; restart or a missing/corrupt
receipt cannot turn one-slot approval into restore-all. A failed checkpoint
write cannot authorize restore; a valid session with invalidated approval needs
a fresh successful explicit check, not a client-created token. A present
unreadable, invalid or incomplete checkpoint is retained and blocks import
replacement, cleanup and local legacy restore until explicit inspection.
If the entire checkpoint was removed or lost externally, previous session
history cannot be reconstructed; no approval or automatic restore replay is
inferred from orphan files. Independently chosen legacy files keep their
normal all-slots contract. This is not deletion-proof checkpoint storage.
Legacy restore endpoints reject selection/receipt fields instead of ignoring
them. Referring to the same session-owned ZIP as an absolute USB path (or a
filesystem alias) does not bypass the selection requirement; uncertain file
identity is blocked conservatively.

Normal selected writeback preserves destination-native container keys,
ACCOUNT_ID, USER_ID, local HMAC, title and literal directory. Existing
full-title snapshot/rollback may copy unselected images **for recovery**;
successful normal writeback does not. Status exposes
`last_restore_{available,selected,written}_slots` and `last_restore_selective`.
Written counts record completed, postverified writes before any later failure;
rollback may undo them. Always interpret them with the terminal restore and
recovery result. A failed physical write/postverification may have modified an
image without incrementing the count; zero is not proof of zero mutations in a
failed restore. There is no new automatic creator or database mutation.

Offline tests exercise production selection/session/HTTP/core and real
snapshot/recovery file operations with synthetic saves. PFS/native APIs are
mocked; preserving a local HMAC is not cryptographic HMAC verification or proof
that a game accepts the transferred progress.

## Native per-path modes in portable Restore (v0.5.199)

Before recreating a selected destination tree, Restore observes modes directly
inside a verified private copy of that destination's PFS. Root, directories
and regular files are matched by **literal relative path and type** to the
portable tree. ZIP/extracted-file modes are not permission authority. No
title-specific values or blanket 0777 policy are applied. An absent/unreadable
reference, unsupported type or incomplete inventory blocks before the wipe.
The existing AppleDouble exclusions remain unchanged.

After the unchanged payload copy and SFO identity transformation, Restore
reapplies each captured mode, children before parents, and reads it back in
PFS. A cleanly unmounted candidate is then acquired and checked through a new
private mount before the existing closed-image publication primitive runs.
Complete payload hashes, keystone and destination SFO/identity checks remain.
After publication, a hash-bound private copy verifies all modes and the same
content/identity checks again. The live image is never mounted by this new
writer/verification path. The encrypted size and final hash must match the
validated closed candidate.

Any mode/content failure or uncertain unmount stops remaining slots, retains
encrypted candidates, validation trees, per-path evidence and the encrypted
title snapshot/checkpoints, and blocks further save I/O after restart. There
is no automatic rollback/retry/cleanup of this uncertain portable operation.
Publication can have happened before a postverification failure: a failed job
or zero completed-write count is not evidence that the destination is unchanged.

The reused collector is bounded to 1024 entries and fails closed when exceeded.
Modes are the destination's **currently observed** values, not reconstructed
historical values or proof that a damaged destination has correct permissions.
ACLs, xattrs, ownership, timestamps and other metadata are not newly restored
by this correction. Native close behavior still requires physical validation;
offline synthetic mounts and prior one-slot acceptance do not establish
permissions as the sole cause, cryptographic HMAC validity or universal game
acceptance. Private evidence is retained on success as well as failure.

## Move a save between PS5 consoles

1. Preserve the original RAW backup. Close the game on both consoles.
2. On the source PS5, open **Backups & Restore → Move a save to another PS5**,
   select the game and download the portable backup. This requires access to
   the source console; an encrypted ZIP by itself is not a decrypted export.
3. On the destination, create the needed save slots in the game first, then
   close it. Preserve a RAW backup of that destination too.
4. Import the portable ZIP on the destination. Restore performs compatibility
   checks automatically. A source UID or console name is not used as permission
   to overwrite another local user's save. Multiple possible owners require
   resolution rather than guessing.
5. Wait for the final result. Keep the original ZIP and retained previous save
   until you have loaded the game, saved to a new slot and loaded that slot again.

Cross-console capability is still experimental until this last hardware test
passes for the actual game/build. Missing target slots, unknown identity,
checksum failures or encrypted-key mismatch must not be overridden.

### Registered expansion recovery foundation (v0.5.184)

Missing native containers still block normal portable restore. This release
does **not** create them automatically and does not reactivate the old PPR
helper. A future creator must independently prove native registration, keys,
owner, HMAC and metadata before this recovery foundation can be activated.

Its low-level held API snapshots all original active/service images and arms a
scoped journal before any publication. The caller must already own the shared
exclusive save gate and durable restore marker, with a freshly resolved local
UID and closed game. Approved image bytes and rows are evidence supplied by
that future creator, not generated or authorized by the journal.

On explicit recovery, only journal-attributed new files/rows may be removed.
All captured original images and typed rows must verify; other titles remain
untouched. A permanent expansion sentinel keeps missing/corrupt journals from
downgrading to ordinary image-only rollback. Uncertainty, unknown files/rows,
unsupported schema or failed durability preserves evidence and blocks further
work. Recovery does not overwrite the complete database or its global sequence.

ARMED, COMMITTED and RECOVERING remain recovery-pending in this foundation.
COMMITTED records publication, not native or game acceptance. Only verified
recovery reaches RECOVERED; retained evidence is not silently deleted or used
as an expansion redo. Host tests model crash/restart and real SQLite behavior;
they do not prove coordinated native PFS writes, save-service caches, game
acceptance or power-loss behavior on PS5 storage. A surviving unregistered
copy temporary requires explicit review, not automatic cleanup.

### Native-creator contract audit (v0.5.185)

**Not approved for activation.** Offline evidence does not yet establish a
native creator for missing `SAVESERVICE-LINE-0-11Slot` and `12Slot`. Keep the
six source slots unchanged; the four current active slots and any service
images are rollback evidence, not a reduced recovery target.

The pinned SDK's `libSceFsInternalForVsh.so` is an import stub with empty
`.text`. It supplies function names, including PPR/transaction exports, but
no savedata option definitions or prototypes in its headers. The existing
local declarations and Garlic's observed five-argument PPR call are not a
documented native-create ABI. Do not guess transaction signatures or sizes.
Garlic's worker formats a private PPR result; the supplied SaveMgr registers
with manual SQL, whose AUTOINCREMENT INSERT omits `id`/`rowid`. Neither proves
detached game-native creation, exact preallocated rowids, local owner/HMAC
acceptance, or coordinated native save-service registration.

Before the existing journal may arm, a separately validated creator must
provide all of the following under the exclusive gate and durable barrier:

- Fresh unambiguous destination UID, closed game, complete current image/row
  inventory and verified four-slot rollback including existing service images.
- Private **final** new images, not provisional empty containers: known native
  ABI and lifetime, destination key lineage, exact SFO title/directory/owner,
  native destination HMAC provenance, complete portable payload checksums,
  clean unmount and private remount verification. A nonzero HMAC or mount alone
  does not establish authenticity or game acceptance.
- Exact typed new rows and destination `rowid`, with the same live schema.
  A detached database's AUTOINCREMENT value or `MAX(rowid)+1` prediction is not
  allocation proof. Allocation must be reserved by a proven coordinated native
  protocol before publication; otherwise this arm API is not a suitable fit.
  Do not publish first and retroactively label observed rows as preapproved.

The journal fixes added-image SHA-256 and typed rows/rowids when armed. Later
payload writes/resealing or native row changes are not automatically approved:
commit **and rollback** fail closed on unknown postimages. Existing portable
restore also opens its own snapshot, which rejects an expansion already
pending. Do not nest that entry point, clear its marker to get past it, or
reactivate the old fresh-PPR helper. Reuse held low-level verification/copy
logic only after an audited composition contract is established.

**Successful finalization is a design requirement, not a new implementation.**
COMMITTED must retain the barrier. A future success checkpoint must bind the
exact final six-slot inventory, local identity, approved typed rows/rowids,
key/HMAC lineage, payload hashes and clean native lifecycle to the retained
original rollback. If the images evolve after arm, each allowed postimage must
be attributed durably *before* publishing it; the current immutable plan
cannot be silently rewritten after a crash. Only after final verification and
durable receipt write, close/reopen/readback may a separately implemented
terminal-success transition authorize clearing local pending markers and then
the shared restore marker last, with parent-directory durability. Retain RAW,
portable, journal and rollback. Interrupted retirement remains blocked and
must be explicitly revalidated; RECOVERED means exact old-state recovery,
not successful six-slot creation. No success state is recognized today.
Historical successful completion must be separate from a later explicit
rollback's live attribution checks: normal game writes cannot be required to
match a historical full-image hash forever, nor authorize deletion of unknown
new bytes. Even RECOVERED currently becomes pending if its exact old live
state changes. Journal retirement needs its own tested lifecycle; do not
remove the sentinel to work around that condition.

Physical validation is staged: first authorize read-only destination evidence
and verified private copies, excluding tokens and unrelated saves; then, only
after the ABI/private-allocation prerequisites are proven, authorize a single
disposable private creator experiment. Live publication, restore, resign,
deployment, retries or cleanup are **not** included. A creator experiment must
not run if it can register live rows or touch original images before arming.
Stop on changed UID/game state, occupied gate, recovery pending, insufficient
space, unsupported schema/allocation, failed key/SFO/HMAC/checksum validation,
uncertain unmount or changed originals. Preserve evidence on uncertainty.

Host regression checks exercise actual journal code and SQLite, including
rowid-only drift and changed approved staging. Their synthetic key seam is not
PS5 PFS crypto, HMAC authentication, native registration or game acceptance.
Native creation and finalization remain INCONCLUSIVE; do not authorize them
merely because these offline tests pass.

### Controlled Pro → OG acceptance test (not yet executed)

This is a game-acceptance test, not a PFS-mount test. Code checks, ZIP
checksums, local ownership and a successful remount can establish filesystem
integrity; only the actual game can establish that it accepts and can write
the transferred progress. There is no universal restore guarantee.

Before any console access, obtain explicit authorization naming the source
console, destination console, their current addresses, game/title ID and the
destination's **local** user. IP addresses and source manifest labels are not
identity or overwrite authority. Request these facts, not Google credentials,
sealed keys, console secrets or account passwords:

- Firmware and active payload/mount environment on each console; exact game
  region/title ID, installed version and relevant DLC on both.
- Whether both game profiles belong to the same account, without publishing an
  Account ID. Different accounts or versions can add game-specific constraints
  that TostónSync does not automatically rewrite.
- A known-good source slot and recognizable progress, confirmed by loading it
  in the game; a known-good destination save confirmed before the transfer.
- Destination-created containers for **every** source slot and an unambiguous
  local owner. Keep both games closed during export, preflight and restore.
- Independent RAW backups of both original saves, copied outside the working
  import/rollback directory, with recorded ZIP SHA-256 and integrity checks.
  Protect them from retention and do not overwrite or delete them. An encrypted
  source RAW backup is not authorization or input for cross-console restore.
- A newly exported formal portable ZIP, its SHA-256, complete slot/payload
  inventory, manifest and per-file checksum result. A legacy export or a ZIP
  with missing slots/checksums is a stop condition, not a bypass request.

Authorize in two stages: (1) read-only console checks and creation/download of
these safety exports; (2) after reviewing their evidence, one portable restore
to the named destination user/title. Do not combine an ambiguous read-only
approval with permission to overwrite live saves. No deployment, credential
change, database repair, game-specific conversion or automatic rollback is
included without separate authorization.

Once preflight is green and the second approval is explicit:

1. Import the portable ZIP once. Confirm its persisted session and exact SHA-256;
   reopen its review after switching tabs/reloading without uploading it again.
2. Confirm the resolved **destination-local** owner and full slot list. Any
   ambiguity, missing target slot, changed file, game-running state or recovery
   warning stops the test before restore. Preserve the original staged ZIP.
3. Execute that single reviewed restore. Keep the game closed until the final
   filesystem/metadata verification and clean unmount complete. Record the
   full job result, slot counts and retained rollback status. Do not call this
   game-compatible yet.
4. The user opens the destination game and loads the identified transferred
   slot. Confirm the expected chapter/progress/inventory and absence of errors.
5. Save from the game into an unused slot; never overwrite the only original
   source or destination reference. Wait for the game's own save operation.
6. Close the game completely, reopen it and load that newly saved slot. Record
   whether the expected progress remains and whether another save is allowed.
7. Only all three results — load, new save, reload — justify a pass for this
   exact title/version/profile pair. Back up the accepted destination state to
   a separate artifact; keep the original RAWs, portable ZIP and rollback.

On a load/save/reload failure, stop and close the game. Preserve logs, reviewed
inventory, import ZIP and recovery images; do not retry, delete images or edit
`savedata.db` blindly. Restoring the previous destination save requires its
own approval and unchanged target identity/keys. A failed rollback remains a
recovery condition, never a successful transfer.

Record a small evidence table: source/destination labels, firmware/game versions,
local-owner selection, all backup hashes, expected/verified slot counts, restore
terminal result, and separate **load / save to new slot / reload** outcomes.
Screenshots should omit account/email/console secrets; technical logs can be
exported through the existing sanitized support bundle. Until this table is
complete, Pro → OG game acceptance is **not demonstrated**.

## Import once, then review or retry

A verified import stays on the destination PS5 until you explicitly remove it.
Return to **Backups & Restore → Continue review** after changing tabs or
reloading the page. If target preparation fails, the backup remains available;
follow the explanation, then retry Restore without uploading it again.

An interrupted browser upload needs the same file to resume. Cancel removes
that import's temporary data, not the console's current save. A verified ZIP
is not yet a verified destination: Restore checks local compatibility before
writing. Queued or in-progress status does not mean the save is restored.

## Recover an imported encrypted RAW for a different local user

In **Backups & Restore**, import the original RAW once, review its detected
title/slots, and choose **Prepare recovery copy**. This is preparation, not
restore: TostónSync retains the original ZIP and SHA-256, extracts disposable
active images into private `/data` storage, and attempts the existing sealed-key
unwrap/PFS mount path. It does not mount or modify the uploaded original or a
live save, change its UID, use a zero-key fallback, or create target containers.
The mount API is not a native read-only kernel mount; disposable copies are
mandatory for this reason.

Each active slot must have authentic matching title/directory metadata and a
PS5 keystone. The entire decrypted tree (including empty files/directories) is
compared with SHA-256. Only then can the existing portable manifest, per-file
checksums and recipient-style ZIP verification publish a persistent recovery
sidecar. Source labels/UID/date are provenance, never destination authority;
unknown source-console labels remain unknown. Service images stay in the
original RAW and are not substituted for active slots. The UI retains the
review across tabs/restarts; no second upload is required after successful
preparation.

If analysis fails before an inventory is available, the UI shows **Slot inventory
unavailable**, not zero slots. Staging/ZIP filesystem errors are distinct from
malformed ZIP, checksum and extraction-limit failures. Keep the original and
copy the specific error from Technical details; do not bypass validation or
repeatedly upload the same completed file to diagnose an extraction failure.
Successful host extraction does not prove the console's filesystem calls work.

**Keys are the boundary.** This only works if the current mount environment can
actually decrypt these RAW images. A changed user, matching title, successful
ZIP upload or Garlic's available mount calls does not prove that. If keys cannot
unwrap/mount, preparation is blocked and the original is retained. Obtain a
verified portable export on a console that can still decrypt the original; if
no such environment exists, TostónSync cannot promise recovery.

The separate **Restore** action still requires an unambiguous destination-local
owner and game-created valid containers for every active slot, a closed game,
full checksums and retained rollback. It rechecks the original and sidecar
hashes without trusting the UI. No arbitrary UID rewrite, incompatible RAW
copy, database repair or universal conversion is allowed.

After an interrupted/uncertain kernel mount, `raw-recovery.pending` and any
private mount evidence remain. Save I/O and scratch cleanup stop until an
authorized reboot/inspection establishes clean mount state. Do not manually
delete these guards just to bypass a warning. Known clean failures can discard
disposable plaintext staging; the original RAW remains until explicit removal.

Offline tests prove control flow, inventories, checksums, publication and error
handling only. Physical validation requires separate authorization first for
copy-only RAW decryption (without target save writes), then for destination
preflight/rollback and one explicit restore. Only an actual game load → save
to a new slot → close/reopen → reload proves acceptance for that exact game,
version and account pair. Preserve independent original backups throughout.

## Interrupted restore

### Dedicated exact RAW-selected publication (v0.5.207)

Generic Restore still rejects partial RAW archives. The separate
`/api/import/raw-selected/preflight` and `/api/import/raw-selected/commit`
contracts require `restore_mode=raw_selected_exact`, the canonical RAW import
ID/ZIP hash, UID/title, explicit literal active and service arrays, and a
finalized server-held selection receipt. A READY preflight is not a lease.
There is no UI or restore-all fallback for this path.

Commit consumes the receipt permanently, claims the RAW work session durably
and uses its own controller/thread. It revalidates the archive, fresh UID,
closed game, exact rows, destination hash/stat and private native observations.
Only selected preimages enter the independent transaction checkpoint. Only
unmounted canonical encrypted source images can be published; diagnostic
mounts operate on different private copies and can never become publication
sources. A selected active plus its service means two authorized images, not
one writeback.

Each publication is checked by encrypted SHA and a newly acquired private
copy, including complete SFO identity, own key evidence, geometry and confirmed
unmount. Complete encrypted-image equality preserves all source bytes; this
is not a cryptographic HMAC validation or a game-acceptance guarantee. Use
`/api/import/raw-selected/status?id=...&selection_receipt=...` to observe only
that operation; QUEUED is not completion. A spent claim, corrupt checkpoint,
possible rename or missing finalization proof cannot authorize replay.

On failure, evidence and the required barrier remain. Automatic destructive
RAW recovery, title-wide rollback, pruning and absent-container creation stay
disabled. Do not invoke the portable/full-RAW recovery path for this scope.
Manual-only suppresses startup automatic-backup replay; it is not a global
read-only boot mode and does not cancel work already admitted. In manual-only,
Drive initialization is deferred until an explicit Drive operation; local RAW
work does not open token files or initialize an account/folder.

The daemon preserves a durable recovery marker. New backups and restore writes
remain blocked so a partially written save cannot replace a good backup.
Keep the game closed and use **Restore previous save** for the affected title.
If a snapshot/rollback directory rotation itself was interrupted, the app stops
and preserves all recovery copies for review; do not delete them to dismiss
the warning. Normal retained undo checks that current slot keys still match.

## PS4, PS5 and PC conversion: what evidence says

[Garlic SaveMgr v1.7](https://github.com/earthonion/garlic-savemgr/releases/tag/v1.7)
documents PS5 save decryption, encryption, browsing and editing. The separate
[HTOS-web / garlicsaves project](https://github.com/earthonion/HTOS-web) lists
specific game conversions. They are not a universal save format.
[PS5Upload](https://github.com/phantomptr/ps5upload) documents saves and package
tools; package/FPKG conversion is not save conversion. The supplied v5.37.2
release URL was not independently verified during this audit.

[REE Save Editor](https://github.com/kvasszn/ree-save-editor#ps5---pc) documents
Requiem PC/PS5 operations, with [MandarinJuice](https://github.com/mi5hmash/MandarinJuice)
handling supported game encryption/identity. A
[reported PS5 workflow](https://github.com/kvasszn/ree-save-editor/issues/41)
uses a particular region/build, destination-created slots and changes to game
metadata; it also reports a write-locked slot requiring a new in-game save.
That report is evidence of a possible per-game workflow, not a compatibility
guarantee. Never copy another region's hash/version constants into a save.

TostónSync does not upload saves to these services, invoke their APIs, download
executables or incorporate their source automatically. Original save archives
remain unchanged. A future converter must have a clear license, known-good
source/target fixtures, exact version/region guards and a proven
load → save → reload result before it can be enabled.

## Selected paired capture

v0.5.213 adds a backend-only manual `POST /api/download/container-selected`.
It requires an explicit literal active selection, the exact confirmed service
selection, target UID/title and `game_closed_confirmed=true`. Unknown service
existence blocks; an empty service declaration is valid only for confirmed
absence. There is no fallback to a whole-title backup and no new UI.

The producer acquires verified canonical encrypted copies of the entire selected
set before any PFS mount. It constructs RAW from those copies and Portable only
from disposable clones. The Portable ZIP retains its existing layout, with the
single fixed related child `TITLE/.capture/raw.zip` and `capture.json`. The
descriptor binds source image names/sizes/hashes, UID/title/capture provenance,
the closed RAW ZIP hash and full Portable trees (root, directories, empty files
and empty directories included). The inspector validates this fixed child only;
it does not accept arbitrary nested archives or treat `.capture` as a save slot.

`atomic_snapshot=false`: stable file observations and a checked set are not a
global atomic PS5 snapshot. The final closed ZIP SHA-256 is distinct from content
fingerprints. `PAIRED_VERIFIED` establishes the paired archive contract, not
universal game/destination compatibility or an approved Restore. `RAW_ONLY`
retains only a verified encrypted archive and is not migration-ready.
`FAILED_UNSTABLE` retains provisional evidence. `BLOCKED_UNMOUNT_UNCERTAIN`
retains evidence and the existing safety barrier; no next mount or retry follows.

This cut does not change Restore, native mode policy, SFO, keys, receipts,
publication or recovery. Missing native destination path references, zero target
ACCOUNT_ID handling, capacity and game-private identity remain governed by the
existing Portable validation. Related RAW remains partial, not complete recovery;
legacy generic Restore does not gain RAW-partial authority. Physical startup,
mounts, pairing and game acceptance have not been validated for this release.

## Privacy

Console labels, local UIDs and creation dates are not login credentials, but
can identify or correlate shared archives. A decrypted game payload may contain
additional game/account identifiers. Export only copies you intend to share;
do not upload raw support logs, OAuth credentials or private account metadata.
