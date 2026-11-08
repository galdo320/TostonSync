// Selection-scoped transaction around the existing Portable/native engine.
// No candidate generation, SFO transformation, mount, replay or recovery writer.
#ifndef TOSTONSYNC_PORTABLE_TRANSACTION_H
#define TOSTONSYNC_PORTABLE_TRANSACTION_H

#include "restore_selection.h"
#include <stdbool.h>
#include <stddef.h>

typedef struct portable_transaction portable_transaction_t;
typedef struct {
    char result[32], workspace[512], detail[256], plan_sha256[65];
    size_t authorized_images, attempted_images, written_images, verified_images;
    bool publication_uncertain, recovery_required, barrier_retained;
} portable_transaction_report_t;

// Exact selected active images only; stable literal no-follow full hashes/stat.
// This is observational. The returned digest is bound by server-held approval.
bool portable_transaction_target_digest(const restore_scope_t* scope,
    const char* target_root, char out[65], char* err, size_t err_sz);

// Caller holds gate + durable barrier and a one-shot durable import claim.
// Workspace MUST NOT exist; no existing checkpoint/artifact is overwritten.
portable_transaction_t* portable_transaction_begin(const restore_scope_t* scope,
    const char* target_root, const char* new_workspace, char* err, size_t err_sz);
bool portable_transaction_slot_workspace(const portable_transaction_t* tx,
    const char* slot, char* out, size_t out_sz);
// Runtime-only worker authority: revalidates its durable claim and canonical
// import/hash against the server-held scope. Never serialized or reinstated
// by inspect/restart. Missing checker blocks publication.
bool portable_transaction_set_authority(portable_transaction_t* tx,
    bool (*check)(void* context), void* context);

// Exact callback used at the existing native engine's publication point.
// Persists intent before calling the unchanged .smnew/rename publisher.
bool portable_transaction_publish(portable_transaction_t* tx,
    const char* candidate, const char* target, const char* closed_sha256,
    const char* expected_pre_sha256, bool* rename_attempted);
// Called only AFTER existing complete private post-image/native-mode checks.
bool portable_transaction_verified(portable_transaction_t* tx,
    const char* target, const char* final_sha256);
bool portable_transaction_finish(portable_transaction_t* tx,
    char* err, size_t err_sz);
// Record an engine failure in the in-memory report; does not clean or recover.
void portable_transaction_failed(portable_transaction_t* tx,
    const char* detail, bool publication_uncertain);
void portable_transaction_report(const portable_transaction_t* tx,
    portable_transaction_report_t* report);
// Free memory only. Never clean artifacts, rollback, prune or clear barriers.
void portable_transaction_free(portable_transaction_t* tx);

// Observational restart path. An unfinished/unknown plan never grants replay,
// writeback, title-wide rollback, pruning, unlink or destructive recovery.
bool portable_transaction_inspect(const char* workspace,
    const restore_scope_t* expected_scope, portable_transaction_report_t* report);

#ifdef PORTABLE_TRANSACTION_TESTING
void portable_transaction_test_fault(const char* point, size_t entry);
#endif
#endif
