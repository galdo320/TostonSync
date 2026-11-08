// TostónSync — ZIP compression / extraction.
//
// Implements the subset of the ZIP format needed for back-up zips:
//   - Store (compression method 0) or Deflate (method 8)
//   - Local file headers + central directory + EOCD
//   - CRC32 per entry
//
// On compression we additionally return the CRC32 of the *concatenated*
// uncompressed contents so the watcher can use it as a fingerprint.

#ifndef TOSTONSYNC_ZIP_H
#define TOSTONSYNC_ZIP_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

// Compress every file under `src_dir` into a ZIP at `out_path`.
// `out_crc` receives a 32-bit fingerprint of the directory contents
// (NOT the CRC of the zip itself — it's the running CRC of every
// file's raw bytes, so identical save folders yield identical values
// across runs). `out_size` receives the final on-disk size of the zip.
bool zip_compress_directory(const char* src_dir,
                            const char* out_path,
                            bool        deflate,
                            uint32_t*   out_crc,
                            uint64_t*   out_size);

// Recovery-only complete tree archive, including empty directories. Existing
// RAW backup writers and their fingerprints keep their original behavior.
bool zip_compress_directory_complete(const char* src_dir, const char* out_path,
                                     uint32_t* out_crc, uint64_t* out_size);

// Same as zip_compress_directory, but every entry is stored under a
// `top_folder/` prefix (e.g. the title ID) so the archive's top level is a
// single folder — the exact shape PS5 Payload Manager produces and expects
// ("top-level folder matches the title ID"). Pass NULL/"" for flat behaviour.
// The content fingerprint in out_crc is unaffected by the prefix, so
// dedup-by-hash stays stable across the change.
bool zip_compress_directory_top(const char* src_dir,
                                const char* top_folder,
                                const char* out_path,
                                bool        deflate,
                                uint32_t*   out_crc,
                                uint64_t*   out_size);

// Same as zip_compress_directory_top, but also stores `manifest_json` as a
// top_folder/manifest.json entry. The manifest is NOT included in out_crc, so
// the content fingerprint stays stable for dedup. Pass NULL to skip it.
bool zip_compress_directory_top_manifest(const char* src_dir,
                                         const char* top_folder,
                                         const char* out_path, bool deflate,
                                         uint32_t* out_crc, uint64_t* out_size,
                                         const char* manifest_json);

// Watcher variant: also returns an order-independent SHA-256 fingerprint of
// entry names, sizes, and uncompressed contents. The manifest is excluded.
bool zip_compress_directory_top_manifest_sha256(
    const char* src_dir, const char* top_folder, const char* out_path,
    bool deflate, uint32_t* out_crc, uint64_t* out_size,
    const char* manifest_json, char out_sha256[65]);

// Partial RAW export only: exact flat sdimg_ basenames, no directory walk or
// fallback. Regular files only, no symlinks; creates a NEW archive (O_EXCL).
// Includes the normal per-file checksums and a mandatory manifest. The returned
// SHA is the content fingerprint, not SHA-256 of the finished ZIP bytes.
// Optional expected hashes bind each streamed file to names[i]; any mismatch
// fails and retains the NEW incomplete archive as evidence, never a download.
bool zip_compress_files_top_manifest_sha256(
    const char* src_dir, const char* top_folder, const char* out_path,
    const char* const* names, size_t count, bool deflate,
    uint32_t* out_crc, uint64_t* out_size, const char* manifest_json,
    char out_sha256[65], const char (*expected_sha256)[65]);

// Post-backup sanity check: returns the archive's entry count (>=0) or -1 if
// the file isn't a readable ZIP. Cheap (reads the EOCD only, no extraction).
int zip_entry_count(const char* zip_path);

// Extract into an existing private staging directory. Never overwrite files;
// duplicate entries, symlinks and special files are rejected. The caller must
// discard the staging directory if extraction fails.
bool zip_extract_to_directory(const char* zip_path, const char* dest_dir);
// Same strict extraction, with an actionable failure detail. I/O errors are
// distinguished from malformed/unsafe archives; no weaker fallback is used.
bool zip_extract_to_directory_checked(const char* zip_path, const char* dest_dir,
                                      char* detail, size_t detail_sz);

#ifdef __cplusplus
}
#endif
#endif
