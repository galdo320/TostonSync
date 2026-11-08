#include "sha256.h"

#include <stdio.h>
#include <string.h>

int main(void) {
    static const char expected[] =
        "ba7816bf8f01cfea414140de5dae2223"
        "b00361a396177a9cb410ff61f20015ad";
    sha256_ctx_t ctx;
    unsigned char digest[32];
    char actual[65];
    sha256_init(&ctx);
    sha256_update(&ctx, "abc", 3);
    sha256_final(&ctx, digest);
    for (size_t i = 0; i < sizeof(digest); i++)
        snprintf(actual + i * 2, sizeof(actual) - i * 2, "%02x", digest[i]);
    actual[64] = '\0';
    if (strcmp(actual, expected) != 0) {
        fprintf(stderr, "SHA-256 mismatch: %s\n", actual);
        return 1;
    }
    puts("SHA-256 OK: known vector matches");
    return 0;
}
