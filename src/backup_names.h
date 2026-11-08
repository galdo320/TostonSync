// TostónSync — one naming contract for destination folders and full backups.
#ifndef TOSTONSYNC_BACKUP_NAMES_H
#define TOSTONSYNC_BACKUP_NAMES_H

#include <stdbool.h>
#include <stddef.h>
#include <time.h>

typedef struct {
    char user_folder[128];
    char title_folder[128];
    char filename[128];
    char game[96];
    // Effective zone, never a claim that an unresolved IANA zone was applied.
    char timezone[64];
    // Existing configured alias, not a change in automatic metadata.
    bool title_rename_requested;
} backup_names_t;

typedef struct {
    bool recognized, safety, legacy;
    char type[16], scope[16], trigger[24], game[96], title_id[16];
    time_t created_unix;
} backup_filename_info_t;

bool backup_names_build(const char* console_name, const char* console_type,
                        const char* user_alias, const char* uid,
                        const char* title, const char* game,
                        const char* trigger, const char* timezone,
                        time_t now, backup_names_t* out);
// Config snapshot + existing local metadata resolver; no network activation.
bool backup_names_current(const char* uid, const char* title,
                          const char* fallback, const char* trigger,
                          time_t now, backup_names_t* out);
// Aggregate byte budget for user/title/file components. Only readable prefixes
// may shrink; codes and the complete Full/trigger/date/offset suffix survive.
// Invalid/too-short budgets return false without changing the supplied names.
bool backup_names_limit(backup_names_t* names, size_t component_budget);
// Identity is an exact bare code or the final literal " - CODE" suffix.
// UID: eight hexadecimal digits. Title: PPSA/CUSA/PCSA/NPXS + alphanumerics.
bool backup_folder_code(const char* name, bool title, char* out, size_t cap);
// New Full names identify scope, not a new archive format: type remains RAW.
// Legacy names remain readable; the ZIP inspector remains format authority.
bool backup_filename_parse(const char* name, backup_filename_info_t* out);
bool backup_filename_safety(const char* name);

// Individual names are labels only; the archive remains identity authority.
// They never enter the Full parser or the Full folder/file budget limiter.
typedef struct {
    bool recognized;
    char game[96], title_id[16], container[128], trigger[24];
    time_t created_unix;
} backup_save_filename_info_t;

bool backup_save_names_build(const char* console_name, const char* console_type,
                            const char* user_alias, const char* uid,
                            const char* title, const char* game,
                            const char* container, const char* timezone,
                            time_t now, backup_names_t* out);
bool backup_save_names_current(const char* uid, const char* title,
                              const char* fallback, const char* container,
                              time_t now, backup_names_t* out);
bool backup_save_filename_parse(const char* name, backup_save_filename_info_t* out);

#endif
