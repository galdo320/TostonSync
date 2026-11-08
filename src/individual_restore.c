#include "individual_restore.h"
#include "usb.h"
#include "gdrive.h"
#include "fs.h"
#include "sha256.h"
#include "log.h"
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static bool individual_restore_error(char* out, size_t cap, const char* text) {
    if (out && cap) snprintf(out, cap, "%s", text);
    return false;
}

bool individual_restore_source_current(const individual_backup_t* item) {
    if (!item || strlen(item->checksum) != 64) return false;
    if (!strcmp(item->source, "usb")) return usb_individual_revalidate(item);
    if (!strcmp(item->source, "drive")) return gdrive_individual_revalidate(item);
    return false;
}

bool individual_restore_review(const import_session_info_t* info,
    const individual_backup_t* item, migration_report_t* report,
    char container[64], char* error, size_t error_cap) {
    memset(report, 0, sizeof(*report));
    container[0] = '\0';
    if (!info || !item || info->state != IMPORT_READY || info->error[0] ||
        info->portable_path[0] || !import_session_owns_ready_path(info->path) ||
        !import_session_validate_selected(info) ||
        (item->checksum[0] && strcmp(info->sha256, item->checksum)))
        return individual_restore_error(error, error_cap, "The owned import copy or its checksum changed.");
    // Formal ZIP identity, never the filename or a hint, selects the destination.
    if (!migration_inspect_zip(info->path, NULL, report) || !report->valid ||
        report->format != MIGRATION_FORMAT_TOSTON_DECRYPTED || !report->has_checksums ||
        !report->needs_kernel || !report->strategy_ready ||
        strcmp(report->restore_strategy, "portable") || report->save_dir_count != 1 ||
        strcmp(report->title_id, item->title_id) ||
        strcmp(report->source_user_uid, item->user))
        return individual_restore_error(error, error_cap,
            report->reason[0] ? report->reason : "Not a checksummed, single-save Portable backup for this user and game.");
    restore_selection_t selected = {0};
    selected.specified = true;
    selected.count = 1;
    memcpy(selected.slots[0], report->save_dirs[0], sizeof(selected.slots[0]));
    if (!restore_selection_resolve(&selected, report->save_dirs, 1, error, error_cap)) return false;
    snprintf(container, 64, "%s", selected.slots[0]);
    return true;
}

bool individual_restore_target_exists(const config_t* cfg,
    const individual_backup_t* item, const char* container,
    char* error, size_t error_cap) {
    char uid[32], title[16];
    if (!cfg || !item || !backup_folder_code(item->user, false, uid, sizeof(uid)) ||
        strcmp(uid, item->user) || strlen(uid) >= 16 ||
        !backup_folder_code(item->title_id, true, title, sizeof(title)) ||
        strcmp(title, item->title_id) || !container || !container[0] || strlen(container) >= 64 ||
        strchr(container, '/') || strchr(container, '\\') || strstr(container, "..") ||
        strcspn(container, "\r\n") != strlen(container))
        return individual_restore_error(error, error_cap, "Invalid individual destination identity.");
    if (!fs_title_is_closed(title))
        return individual_restore_error(error, error_cap, "game_not_closed");
    char path[512];
    int n = snprintf(path, sizeof(path), "%s/%s/savedata_prospero/%s/sdimg_%s",
                     cfg->paths.saves_root, uid, title, container);
    struct stat st;
    if (n < 0 || (size_t)n >= sizeof(path))
        return individual_restore_error(error, error_cap, "Invalid individual destination path.");
    if (lstat(path, &st))
        return individual_restore_error(error, error_cap,
            errno == ENOENT ? "individual_missing_target" : "Target save is unavailable.");
    if (!S_ISREG(st.st_mode) || st.st_size < 1)
        return individual_restore_error(error, error_cap, "Target save is unavailable.");
    return true;
}

bool individual_restore_prepare(const config_t* cfg, individual_backup_t* item,
    uint64_t reserve_bytes, import_session_info_t* info,
    migration_report_t* report, char container[64], char* error, size_t error_cap) {
    import_session_info_t current;
    memset(info, 0, sizeof(*info));
    if (import_session_current(&current) && current.state != IMPORT_IDLE)
        return individual_restore_error(error, error_cap, "import_busy");
    if (!item || (!individual_catalog_item_valid(item, "usb") &&
        !individual_catalog_item_valid(item, "drive")))
        return individual_restore_error(error, error_cap, "Invalid individual reference.");
    if (!fs_title_is_closed(item->title_id))
        return individual_restore_error(error, error_cap, "game_not_closed");
    if (UINT64_MAX - reserve_bytes < item->size_bytes)
        return individual_restore_error(error, error_cap, "Not enough staging space.");
    if (!import_session_start(cfg, item->name, item->size_bytes,
        reserve_bytes + item->size_bytes, item->title_id, item->user, "browser", "", info))
        return individual_restore_error(error, error_cap, info->error[0] ? info->error : "import_busy_or_no_space");
    if (!import_session_individual_mark(info->id, info))
        return individual_restore_error(error, error_cap, "Individual checkpoint could not be made durable.");
    char download[512];
    int n = snprintf(download, sizeof(download), "%s.individual-download", info->path);
    if (n < 0 || (size_t)n >= sizeof(download))
        return individual_restore_error(error, error_cap, "Individual download path is too long.");
    bool fetched = !strcmp(item->source, "usb") ? usb_individual_download_bounded(item, download, error, error_cap)
        : gdrive_individual_download_bounded(item, download, error, error_cap);
    if (!fetched) return false;
    char sha[65];
    if (!sha256_file_hex(download, sha) || (item->checksum[0] && strcmp(item->checksum, sha)))
        return individual_restore_error(error, error_cap, "Downloaded copy failed checksum verification.");
    snprintf(item->checksum, sizeof(item->checksum), "%s", sha);
    if (!individual_restore_source_current(item))
        return individual_restore_error(error, error_cap, "source_changed");
    int fd = open(download, O_RDONLY | O_NOFOLLOW | O_NONBLOCK);
    struct stat st;
    bool copied = fd >= 0 && !fstat(fd, &st) && S_ISREG(st.st_mode) &&
        (uint64_t)st.st_size == item->size_bytes;
    unsigned char block[64 * 1024];
    uint64_t offset = 0;
    while (copied && offset < item->size_bytes) {
        size_t want = (size_t)(item->size_bytes - offset);
        if (want > sizeof(block)) want = sizeof(block);
        ssize_t got = read(fd, block, want);
        if (got < 0 && errno == EINTR) continue;
        copied = got > 0 && import_session_write(info->id, offset, block, (size_t)got, info);
        if (copied) offset += (size_t)got;
    }
    unsigned char extra;
    copied = copied && read(fd, &extra, 1) == 0;
    if (fd >= 0 && close(fd)) copied = false;
    if (!copied || offset != item->size_bytes)
        return individual_restore_error(error, error_cap, "Individual download is truncated or changed.");
    if (!import_session_individual_checkpoint(info->id, info) ||
        !import_session_finish(info->id, sha, info) ||
        !import_session_individual_checkpoint(info->id, info))
        return individual_restore_error(error, error_cap, "Owned import verification or checkpoint failed.");
    // Only a newly created transfer scratch is removed; the destination is never owned here.
    if (unlink(download))
        return individual_restore_error(error, error_cap, "Could not release individual transfer scratch.");
    if (!individual_restore_review(info, item, report, container, error, error_cap) ||
        !individual_restore_target_exists(cfg, item, container, error, error_cap) ||
        !import_session_individual_bind(info->id, item, container, info)) return false;
    log_info("individual-restore: reviewed title=%s canonical_sha256=%s selected_slots=1 save_writes=0",
             item->title_id, sha);
    return true;
}
