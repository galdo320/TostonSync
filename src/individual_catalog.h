// Individual Library rows are provider evidence, never Restore/cleanup authority.
#ifndef TOSTONSYNC_INDIVIDUAL_CATALOG_H
#define TOSTONSYNC_INDIVIDUAL_CATALOG_H
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdio.h>
#include "catalog_scan.h"
#include "backup_names.h"

#define INDIVIDUAL_CATALOG_MAX 512
#define INDIVIDUAL_MAX_BYTES (8ULL * 1024ULL * 1024ULL * 1024ULL)
typedef struct {
    char user[32], title_id[16], source[8], name[384], ref[768];
    uint64_t size_bytes;
    int64_t created_unix; // Filename presentation, not an incarnation proof.
    char container[256]; // Display label; ZIP inventory owns actual identity.
    char destination_identity[65], file_stamp[65], checksum[65];
    char parent_ref[768];
    char volume_id[65], mount[64];
    uint64_t generation;
} individual_backup_t;

static inline bool individual_catalog_name_safe(const char* name) {
    if (!name || !name[0] || strlen(name) >= 384) return false;
    const unsigned char* p = (const unsigned char*)name;
    while (*p) {
        unsigned char c = *p++;
        if (c < 32 || c == 127 || c == '/' || c == '\\') return false;
        if (c < 128) continue;
        unsigned count; uint32_t point;
        if (c >= 0xc2 && c <= 0xdf) { count = 1; point = c & 31; }
        else if (c >= 0xe0 && c <= 0xef) { count = 2; point = c & 15; }
        else if (c >= 0xf0 && c <= 0xf4) { count = 3; point = c & 7; }
        else return false;
        unsigned bytes = count;
        while (count--) {
            if ((*p & 0xc0) != 0x80) return false;
            point = (point << 6) | (*p++ & 63);
        }
        if ((bytes == 2 && point < 0x800) || (bytes == 3 && point < 0x10000) ||
            point > 0x10ffff || (point >= 0xd800 && point <= 0xdfff)) return false;
    }
    return true;
}

static inline bool individual_catalog_label(const char* user, const char* title,
        const char* source, const char* name, individual_backup_t* out) {
    backup_save_filename_info_t label;
    char uid[32], tid[16];
    if (!out || !source || strlen(source) >= sizeof(out->source) ||
        !individual_catalog_name_safe(name) || !backup_folder_code(user, false, uid, sizeof(uid)) ||
        !backup_folder_code(title, true, tid, sizeof(tid))) return false;
    memset(out, 0, sizeof(*out));
    snprintf(out->user, sizeof(out->user), "%s", uid);
    snprintf(out->title_id, sizeof(out->title_id), "%s", tid);
    snprintf(out->source, sizeof(out->source), "%s", source);
    snprintf(out->name, sizeof(out->name), "%s", name);
    if (backup_save_filename_parse(name, &label)) {
        snprintf(out->container, sizeof(out->container), "%s", label.container);
        out->created_unix = label.created_unix;
    }
    return true;
}

static inline bool individual_catalog_item_valid(const individual_backup_t* item,
                                                 const char* source) {
    return item && memchr(item->source, 0, sizeof(item->source)) &&
        !strcmp(item->source, source) && memchr(item->user, 0, sizeof(item->user)) &&
        memchr(item->title_id, 0, sizeof(item->title_id)) &&
        memchr(item->name, 0, sizeof(item->name)) &&
        memchr(item->ref, 0, sizeof(item->ref)) && item->ref[0] &&
        memchr(item->parent_ref, 0, sizeof(item->parent_ref)) && item->parent_ref[0] &&
        memchr(item->destination_identity, 0, sizeof(item->destination_identity)) &&
        strlen(item->destination_identity) == 64 &&
        strspn(item->destination_identity, "0123456789abcdef") == 64 &&
        memchr(item->file_stamp, 0, sizeof(item->file_stamp)) && strlen(item->file_stamp) == 64 &&
        strspn(item->file_stamp, "0123456789abcdef") == 64 &&
        memchr(item->checksum, 0, sizeof(item->checksum)) &&
        (!item->checksum[0] || (strlen(item->checksum) == 64 &&
         strspn(item->checksum, "0123456789abcdef") == 64)) &&
        item->size_bytes >= 22 && item->size_bytes <= INDIVIDUAL_MAX_BYTES;
}

static inline bool individual_catalog_same(const individual_backup_t* a,
                                          const individual_backup_t* b) {
    return a->size_bytes == b->size_bytes && a->generation == b->generation &&
        !strcmp(a->ref, b->ref) && !strcmp(a->parent_ref, b->parent_ref) &&
        !strcmp(a->name, b->name) && !strcmp(a->user, b->user) &&
        !strcmp(a->title_id, b->title_id) &&
        !strcmp(a->destination_identity, b->destination_identity) &&
        !strcmp(a->file_stamp, b->file_stamp);
}
#endif
