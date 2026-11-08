#ifndef TOSTONSYNC_PAIRED_CAPTURE_H
#define TOSTONSYNC_PAIRED_CAPTURE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define PAIRED_CAPTURE_MAX_ACTIVE 32
#define PAIRED_CAPTURE_MAX_IMAGES 64
#define PAIRED_CAPTURE_MAX_ENTRIES 16384
#define PAIRED_CAPTURE_JSON_MAX (16U * 1024U * 1024U)

/* Bounded observation only; UNKNOWN is never successful validation. Public
 * serialization omits literal paths, names and every hash. */
typedef enum {
    PAIR_DIAG_OPEN_TITLE, PAIR_DIAG_OPEN_CAPTURE, PAIR_DIAG_ALLOCATION,
    PAIR_DIAG_TITLE_SHAPE, PAIR_DIAG_CAPTURE_SHAPE, PAIR_DIAG_RAW_CLOSED,
    PAIR_DIAG_COLLECT_TREE, PAIR_DIAG_CREATE_EXCL, PAIR_DIAG_FDOPEN,
    PAIR_DIAG_WRITE, PAIR_DIAG_FFLUSH, PAIR_DIAG_DESCRIPTOR_STAT,
    PAIR_DIAG_FSYNC_FILE, PAIR_DIAG_FCLOSE, PAIR_DIAG_FSYNC_DIRECTORY,
    PAIR_DIAG_CLOSE_CAPTURE, PAIR_DIAG_CLOSE_TITLE,
    PAIR_DIAG_DESCRIPTOR_READ, PAIR_DIAG_DESCRIPTOR_PARSE,
    PAIR_DIAG_PORTABLE_PROVENANCE, PAIR_DIAG_TREE_COMPARE,
    PAIR_DIAG_RAW_SHAPE, PAIR_DIAG_RAW_MANIFEST, PAIR_DIAG_STAGE_COUNT
} paired_capture_stage_t;
typedef enum { PAIR_DIAG_UNKNOWN, PAIR_DIAG_PASS, PAIR_DIAG_FAIL,
               PAIR_DIAG_SKIPPED } paired_capture_stage_state_t;
typedef struct {
    paired_capture_stage_state_t state;
    char operation[32], errno_name[24], expected[96], observed[96];
    int64_t return_value, expected_value, observed_value;
    bool return_valid, errno_valid, values_valid;
    int errno_code;
    char stat_pair[40], stat_field[16], private_relative_path[260];
    uint64_t observed_mode, expected_raw_size, observed_raw_size;
    bool mode_valid, raw_size_valid;
    char expected_raw_sha256[65], observed_raw_sha256[65];
} paired_capture_stage_diagnostic_t;
typedef struct {
    paired_capture_stage_diagnostic_t stages[PAIR_DIAG_STAGE_COUNT];
    uint64_t tree_entries, tree_files, tree_directories;
    unsigned maximum_depth;
} paired_capture_diagnostic_t;

const char* paired_capture_stage_name(paired_capture_stage_t stage);
const char* paired_capture_stage_state_name(paired_capture_stage_state_t state);
void paired_capture_diagnostic_init(paired_capture_diagnostic_t* diagnostic);
/* Returns required bytes excluding NUL, including when capacity is too small. */
size_t paired_capture_diagnostic_json(const paired_capture_diagnostic_t* diagnostic,
                                     char* out, size_t capacity, bool private_detail);

typedef struct {
    char name[128];              /* Exact sdimg_ / sdimg_sce_bu_ basename. */
    uint64_t size;
    char sha256[65];
} paired_capture_image_t;

typedef struct {
    char capture_id[64], producer_version[32], title_id[16], source_uid[16];
    int64_t started_at, finished_at;
    size_t image_count;
    paired_capture_image_t images[PAIRED_CAPTURE_MAX_IMAGES];
    uint64_t raw_zip_size;
    char raw_zip_sha256[65];
    // Derived by validation, not serialized or supplied as producer authority.
    char descriptor_sha256[65];
} paired_capture_t;

/* Writes a NEW TITLE/.capture/capture.json beside an already closed raw.zip.
 * The caller owns a new private workspace/gate and stable canonical copies.
 * Records every literal regular file (including zero bytes) and directory in
 * each active sdimg_<slot> tree, including its root and sce_sys. No mounts,
 * live-save reads, permissions restoration, cleanup, or source key material.
 * Failure retains the new partial descriptor as evidence, never a valid pair.
 */
bool paired_capture_write(const char* title_root, const paired_capture_t* capture,
                          char* error, size_t error_sz);
bool paired_capture_write_diagnostic(const char* title_root, const paired_capture_t* capture,
                                    char* error, size_t error_sz,
                                    paired_capture_diagnostic_t* diagnostic);

/* Optional reserved metadata: absent is legacy; present must have exactly two
 * regular files, a strict bounded descriptor, matching full Portable trees,
 * and the declared closed raw.zip size/hash. No child ZIP extraction here.
 */
bool paired_capture_validate_title(const char* title_root, paired_capture_t* out,
                                   bool* present, char* error, size_t error_sz);
bool paired_capture_validate_title_diagnostic(const char* title_root, paired_capture_t* out,
                                             bool* present, char* error, size_t error_sz,
                                             paired_capture_diagnostic_t* diagnostic);

/* Checks the fixed child's already extracted TITLE/ flat image inventory,
 * exact image roles/names/sizes/hashes and direct RAW manifest provenance.
 * The migration inspector separately validates that child's normal checksums.
 */
bool paired_capture_validate_raw(const char* extracted_root,
                                 const paired_capture_t* capture,
                                 char* error, size_t error_sz);
bool paired_capture_validate_raw_diagnostic(const char* extracted_root,
                                           const paired_capture_t* capture,
                                           char* error, size_t error_sz,
                                           paired_capture_diagnostic_t* diagnostic);

/* Compile this same .c with PAIRED_CAPTURE_READONLY_PROBE to omit all write,
 * flush, fsync and descriptor-production code. The record is caller-owned. */
bool paired_capture_probe_readonly(const char* title_root, const paired_capture_t* capture,
                                  paired_capture_diagnostic_t* diagnostic);

#endif
