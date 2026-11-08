// Fixed forensic mode-only experiment. Never publishes or repairs a save.
#ifndef TOSTONSYNC_PFS_MODE_TRIAL_H
#define TOSTONSYNC_PFS_MODE_TRIAL_H
#include "pfs_attributes.h"

#define PFS_MODE_TRIAL_EXPECTED_SHA "c35445b2e661ee092c320bd6215c5b79d30a32597bd972f0094ba169c069b799"

typedef struct {
    pfs_attribute_image_t attrs;
    char (*file_sha256)[65]; // Indexed exactly like attrs.entries; directories are empty.
    size_t regular_file_count;
    bool hashes_complete;
} pfs_mode_observation_t;

typedef struct {
    const char* name;
    char image[256], verification_copy[256];
    char closed_sha256[65], sealed_key_sha256[65], plain_key_sha256[65];
    bool first_unmounted, verify_unmounted;
    bool content_unchanged, attributes_preserved, closed_observation_matches;
    pfs_mode_observation_t before, after, closed;
} pfs_mode_arm_t;

typedef struct {
    const char* result;
    char work[256], detail[256], phase[64], evidence_path[320];
    bool recovery_required, evidence_durable, source_available, source_stable, source_unchanged;
    struct stat source_before, source_after;
    char source_sha256[65];
    pfs_mode_arm_t arms[2]; // CONTROL, CANDIDATE.
    bool content_equal, metadata_equal, modes_expected;
    bool inventory_equal, content_hashes_equal, identities_equal;
    bool flags_equal, links_equal, other_modes_equal, requested_modes_observed;
    bool sealed_keys_equal, plain_keys_equal;
    bool timestamps_equal; // Observation only; excluded from equivalence.
} pfs_mode_trial_report_t;

// Caller owns the exclusive gate and existing persistent mount barrier.
// work must be a NEW private /data directory; no artifact is deleted.
void pfs_mode_trial_run(pfs_mode_trial_report_t* report);
void pfs_mode_trial_free(pfs_mode_trial_report_t* report);
#endif
