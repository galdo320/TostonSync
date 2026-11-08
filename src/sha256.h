// TostónSync - small streaming SHA-256 helper for import verification.

#ifndef TOSTONSYNC_SHA256_H
#define TOSTONSYNC_SHA256_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef struct {
    uint32_t state[8];
    uint64_t total;
    uint8_t  block[64];
    size_t   used;
} sha256_ctx_t;

void sha256_init(sha256_ctx_t* ctx);
void sha256_update(sha256_ctx_t* ctx, const void* data, size_t len);
void sha256_final(sha256_ctx_t* ctx, uint8_t out[32]);
bool sha256_file_hex(const char* path, char out[65]);

#endif
