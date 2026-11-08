// One-shot publication of ONE already-closed, physically verified experiment.
#ifndef TOSTONSYNC_PFS_CANDIDATE_PUBLISH_H
#define TOSTONSYNC_PFS_CANDIDATE_PUBLISH_H
#include "pfs_mode_trial.h"
#include "sdimg_restore.h"

// ponytail: deliberately pinned to this evidence, not a general restore API.
#define PFS_CANDIDATE_RELEASE "0.5.198"
#define PFS_CANDIDATE_WORK "/data/tostonsync/forensics/pfs-mode-trial.x4aRD8"
#define PFS_CANDIDATE_IMAGE PFS_CANDIDATE_WORK "/CANDIDATE.img"
#define PFS_CANDIDATE_CONTROL PFS_CANDIDATE_WORK "/CONTROL.img"
#define PFS_CANDIDATE_RECEIPT PFS_CANDIDATE_WORK "/response.json"
#define PFS_CANDIDATE_SHA "937190c5ee36934f422b98db533604c23452463132cc749c5a530b7be14a679a"
#define PFS_CANDIDATE_CONTROL_SHA "136142ce77392790b374bd0f8f9ac8a07b8e47bf18741c21701a0dc039e8cc59"
#define PFS_CANDIDATE_RECEIPT_SHA "a00260939cb4792bbebba9ca837226202659582b046eb19f0aa2f8727b3e9c8c"
#define PFS_CANDIDATE_ATTEMPT PFS_CANDIDATE_WORK "/candidate-publication.attempt"

typedef struct {
    pfs_mode_trial_report_t trial; // Shared collector/hash/metadata observations.
    sdimg_target_slot_report_t registry;
    uint64_t account_id;
    uint32_t user_id;
    bool identity_resolved, attempt_durable, rename_attempted, published;
    bool pre_verified, post_verified, final_hash_verified, retained_unchanged;
    unsigned live_writebacks;
    char final_sha256[65];
} pfs_candidate_publication_t;

// Caller holds the exclusive gate/barrier. Revalidation never mounts, writes
// DB or acquires the gate recursively. All artifacts survive every outcome.
void pfs_candidate_publish_run(pfs_candidate_publication_t* report,
                               bool (*revalidate)(pfs_candidate_publication_t*));
#endif
