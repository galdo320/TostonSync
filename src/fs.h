// TostónSync — filesystem helpers and sandbox escape.
//
// The escape uses kernel_set_proc_rootdir() / kernel_get_root_vnode()
// from the ps5-payload-sdk. After it succeeds we can open() any path
// on the console, including /user/home/<user>/savedata_prospero/.
//
// fs_get_running_title() reads the currently-foregrounded title's ID
// from the system process list — used by the "on_game_close" trigger.

#ifndef TOSTONSYNC_FS_H
#define TOSTONSYNC_FS_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    char name[64];     // basename (e.g., "CUSA00000")
    char path[256];    // absolute path
    char user_uid[16]; // for save-title entries: the parent PS5 user UID
                       // (the directory name under /user/home/). For
                       // entries from fs_list_users() this is the UID
                       // itself (== name).
} fs_dir_t;

bool   fs_escape_sandbox(void);
bool   fs_mkdir_p(const char* path);

// Walk /user/home/<UID>/savedata_prospero/* and fill `out` with one
// fs_dir_t per title across all users. Returns count written.
size_t fs_list_save_titles(const char* root, fs_dir_t* out, size_t max_out);

// Walk /user/home/<UID>/* (one entry per console user). Returns no users
// on an incomplete/unreadable/oversized inventory; never returns a prefix.
size_t fs_list_users(const char* root, fs_dir_t* out, size_t max_out);

// Best-effort: write the currently foregrounded title ID
// (e.g. "CUSA00000") into `out`. Empty string when at the menu.
void fs_get_running_title(char* out, size_t out_sz);

// True while the game's /mnt/sandbox/<title_id>_* dir exists (i.e. the title
// is running), false once it is gone. Existence-based, no mtime gate — a game
// idling in a cutscene/menu is still reported as running, so the on_game_close
// trigger only fires when the game ACTUALLY closes.
bool fs_title_is_running(const char* title_id);

// Export/restore safety: false also when game state cannot be read completely.
// Best-effort !fs_title_is_running() is not permission to write a save.
bool fs_title_is_closed(const char* title_id);

// Newest mtime (unix) among regular files directly inside `dir`. Used to
// detect in-place save writes (sdimg_*) that kqueue NOTE_WRITE misses.
int64_t fs_dir_newest_mtime(const char* dir);

// Total size in bytes of all regular files under `path` (recursive).
// Returns 0 if the path is missing or unreadable. Used to show how much
// each save weighs in the UI.
uint64_t fs_dir_size(const char* path);

// Read-only, bounded metadata estimate for a Full RAW backup. This is a
// point-in-time display observation, never permission to write or a reservation.
typedef struct {
    uint64_t source_bytes;
    uint64_t estimated_bytes;
    size_t files;
    const char* reason;
    int error;
} fs_backup_estimate_t;
bool fs_backup_size_estimate(const char* path, fs_backup_estimate_t* out);

#ifdef __cplusplus
}
#endif
#endif
