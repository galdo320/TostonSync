// TostónSync — title metadata cache (names + icons).
//
// PS5 save folders are encrypted, so a game's friendly name and icon are only
// readable while the title is installed/mounted. Names are refreshed whenever
// metadata is available, so a save whose title is later removed still shows its name and
// icon instead of a bare TITLE_ID. Cache lives under <state_dir>:
//   <state_dir>/title_cache.jsonl              (one {"title_id","name"} per line)
//   <state_dir>/metadata/<TITLE_ID>/icon0.png  (copied icon)

#ifndef TOSTONSYNC_METACACHE_H
#define TOSTONSYNC_METACACHE_H

#include <stdbool.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

// Remember a real game name for a TITLE_ID (ignored if empty or == title_id).
void metacache_note_name(const char* title_id, const char* name);

// Cached name for a TITLE_ID into `out` ("" when none).
void metacache_get_name(const char* title_id, char* out, size_t out_sz);

// Automatic name: current-language metadata, cache, fallback, public cache, ID.
// Reads an already verified public cache only; never performs a network request.
// Does not read/write manual aliases. Returns true for a real name, not the ID.
bool metacache_resolve_name(const char* title_id, const char* fallback,
                            char* out, size_t out_sz);

// Same name precedence, but never creates or refreshes the on-disk cache.
bool metacache_resolve_name_readonly(const char* title_id, const char* fallback,
                                     char* out, size_t out_sz);

// Absolute path where this title's cached icon lives (built, not checked).
void metacache_icon_path(const char* title_id, char* out, size_t out_sz);

// True if a cached icon file exists for this title.
bool metacache_has_icon(const char* title_id);

// Copy `src_path` into the cache as this title's icon, unless one already
// exists. Best-effort and silent on failure.
void metacache_cache_icon(const char* title_id, const char* src_path);

#ifdef __cplusplus
}
#endif
#endif // TOSTONSYNC_METACACHE_H
