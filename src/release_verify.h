// Signed release protocol. No network, mutation, installation or logging.
#ifndef TOSTONSYNC_RELEASE_VERIFY_H
#define TOSTONSYNC_RELEASE_VERIFY_H
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#define RELEASE_API_URL "https://api.github.com/repos/galdo320/TostonSync/releases/latest"
#define RELEASE_MANIFEST_NAME "update-manifest.json"
#define RELEASE_SIGNATURE_NAME "update-manifest.sig"
#define RELEASE_MANIFEST_V2_NAME "update-manifest-v2.json"
#define RELEASE_SIGNATURE_V2_NAME "update-manifest-v2.sig"
#define RELEASE_MANIFEST_MAX 4096
#define RELEASE_LISTING_MAX (128u * 1024u)
#define RELEASE_NOTES_MAX 4096
#define RELEASE_ASSETS_MAX 32
#define RELEASE_URL_MAX 1024
#define RELEASE_BYTES_MAX (16u * 1024u * 1024u)
typedef struct { char name[128]; uint64_t size; } release_asset_t;
typedef struct {
    char version[32], tag[40], notes[RELEASE_NOTES_MAX + 1];
    release_asset_t assets[RELEASE_ASSETS_MAX]; size_t count;
    char manifest_name[32], signature_name[32], notes_sha256[65];
} release_listing_t;
typedef struct {
    char version[32], build[64], min_version[32];
    char asset[128], asset_sha256[65], elf[128], sha256[65];
    uint64_t asset_size, size;
    char candidate_id[65], notes_sha256[65];
    bool notes_verified;
} release_manifest_t;
// The production definition contains public keys only. Host tests link test keys.
extern const uint8_t release_public_keys[2][32];
bool release_parse_listing(const void* bytes, size_t length, release_listing_t* out,
                           char* error, size_t capacity);
bool release_verify_manifest(const void* bytes, size_t length, const void* signature,
                             size_t signature_length, const char* running_version,
                             const release_listing_t* listing, release_manifest_t* out,
                             char* error, size_t capacity);
// Returns -1/0/1 on valid three-component versions; 2 means invalid input.
int release_version_compare(const char* left, const char* right);
bool release_asset_url(const char* tag, const char* asset, char* out, size_t capacity);
// Verifies the signed raw ELF size/hash (legacy ZIP fixtures remain supported). The caller
// additionally binds the embedded ELF marker using update_inspect_bytes before B1.
// Reads only the held fd. Allocates *elf on success; caller frees it.
bool release_extract_elf(int fd, const release_manifest_t* manifest,
                         void** elf, size_t* length, char* error, size_t capacity);
#endif
