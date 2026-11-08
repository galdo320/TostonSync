// TostónSync — best-effort human game name for a TITLE_ID.
//
// PS5 saves on disk are encrypted, so the friendly name ("Resident Evil
// Requiem") isn't readable from the save folder. Installed-game metadata
// usually lives under appmeta/app sce_sys directories, and running games
// are also mounted under /mnt/sandbox/<TITLEID>_xxx/app0. Their
// param.json (newer) or param.sfo (older) carries the title name. We read
// it from there so the UI and history can show a recognizable name
// instead of just "PPSA00001". Falls back to the TITLE_ID when the name
// can't be found.

#ifndef TOSTONSYNC_TITLENAME_H
#define TOSTONSYNC_TITLENAME_H

#include <stdbool.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

// Look up the display name for title_id by reading param.json / param.sfo
// from installed metadata or the running game's sandbox. Returns true and
// fills out on success; sets out to "" and returns false otherwise. PS5 JSON
// prefers the configured app language, then English, the declared default,
// and a root-level title name. No save contents are read or changed.
bool titlename_lookup(const char* title_id, char* out, size_t out_sz);

// Copy a UTF-8 prefix without splitting a Unicode scalar. Stops at invalid
// UTF-8 or the capacity boundary, NUL-terminates when out_sz > 0, and returns
// bytes written (excluding NUL). Also supports copying a buffer to itself.
size_t titlename_copy_utf8(char* out, size_t out_sz, const char* name);

// Locate an asset inside the same sce_sys metadata dirs (for example
// "icon0.png" or "pic0.png"). Returns the absolute path on success.
bool titlename_find_asset(const char* title_id, const char* asset_name,
                          char* out, size_t out_sz);

#ifdef __cplusplus
}
#endif
#endif // TOSTONSYNC_TITLENAME_H
