// TostónSync — protected (favorite) backups.
//
// A backup the owner marks as protected must NEVER be deleted by AUTOMATIC
// retention (per-title keep-N, manual prune, browser-Drive prune). Explicit
// single deletes still work — protection only guards the auto/bulk paths.
//
// Backups carry the SAME filename across every destination (USB/FTP/Drive), so
// the protected set is keyed by the bare filename (basename). Persisted one per
// line in <state_dir>/protected.lst. Legacy `_SAFETY_` archives and new names
// whose exact trigger is Safety are protected automatically from bulk cleanup.

#ifndef TOSTONSYNC_PROTECT_H
#define TOSTONSYNC_PROTECT_H

#include <stdbool.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

// True if the backup with this filename (basename taken if a path is passed)
// is marked protected, or the persisted protection list cannot be verified.
bool protect_is(const char* filename);

// Mark/unmark a backup filename as protected. Persists. Basename only.
bool protect_set(const char* filename, bool on);

// Emit the complete protected set as JSON. Unknown/malformed/too-large lists
// return false and empty output; callers must not treat uncertainty as [].
bool protect_to_json(char* out, size_t out_sz);

#ifdef __cplusplus
}
#endif
#endif // TOSTONSYNC_PROTECT_H
