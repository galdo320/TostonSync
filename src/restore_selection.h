// Literal restore scope shared by diagnostic, admission and destination writer.
#ifndef TOSTONSYNC_RESTORE_SELECTION_H
#define TOSTONSYNC_RESTORE_SELECTION_H

#include <stdbool.h>
#include <stddef.h>

#define RESTORE_SELECTION_MAX 32
#define RESTORE_MODE_PORTABLE_SELECTED "portable_selected"
typedef struct {
    bool specified;
    size_t count;
    char slots[RESTORE_SELECTION_MAX][64];
} restore_selection_t;

// The same strict traversal extracts authority; legacy substring getters must
// not rescan unrelated string values for an id, UID or receipt.
typedef struct {
    restore_selection_t selection;
    char id[48];
    char phase[32];
    char target_uid[64];
    char user[64];
    char selection_receipt[65];
    char restore_mode[24];
} restore_selection_request_t;

typedef struct {
    restore_selection_t selection;
    char restore_mode[24];
    char import_id[48];
    char title_id[16];
    char target_uid[16];
    char source_sha256[65];
    char portable_sha256[65];
    char target_state_sha256[65];
    char receipt[65];
    size_t available_slots;
} restore_scope_t;

// Strict complete request parsing. Absent selection is legacy; empty is invalid.
bool restore_selection_parse(const char* body, restore_selection_t* out,
                             char* error, size_t error_sz);
bool restore_selection_request_parse(const char* body,
                                     restore_selection_request_t* out,
                                     char* error, size_t error_sz);
// Legacy routes cannot silently ignore selective fields, including nested
// batch fields. Complete bounded JSON traversal, never substring matching.
bool restore_selection_legacy_request(const char* body);
// Flat identity envelopes distinguish an absent UID from a malformed explicit selector.
bool restore_uid_valid(const char* uid);
bool restore_request_uid(const char* body, char uid[16], bool* explicit_uid);
// Bulk envelopes cannot hide or substitute item identity. Validate before iterating.
bool restore_batch_request(const char* body, const char** items);
bool restore_batch_item(const char** cursor, char object[1024]);
bool restore_all_request(const char* body, char source[16]);
// Import preparation may bind archive provenance without approving a local target.
bool import_request_uid(const char* body, char uid[16], bool* explicit_uid, bool* source_uid);
// Omission selects the complete inventory; explicit selections stay literal.
bool restore_selection_resolve(restore_selection_t* selection,
                               const char available[][64], size_t available_count,
                               char* error, size_t error_sz);
bool restore_selection_contains(const restore_selection_t* selection,
                                const char* slot);
bool restore_selection_equal(const restore_selection_t* a,
                             const restore_selection_t* b);
// Digest binds the server-held scope, not a client-provided permission grant.
bool restore_scope_digest(const restore_scope_t* scope, char out[65]);
bool restore_scope_valid(const restore_scope_t* scope);
bool restore_scope_equal(const restore_scope_t* a, const restore_scope_t* b);

#endif
