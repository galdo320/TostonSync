#ifndef TOSTONSYNC_PEM_H
#define TOSTONSYNC_PEM_H

#include <stddef.h>
#include <string.h>

static inline const char* pem_next_cert(const char** cursor, const char* end,
                                        size_t* out_len) {
    static const char BEGIN[] = "-----BEGIN CERTIFICATE-----";
    static const char END[] = "-----END CERTIFICATE-----";
    const char* b = strstr(*cursor, BEGIN);
    if (!b || b >= end) return NULL;
    const char* e = strstr(b, END);
    if (!e || e >= end) return NULL;
    e += sizeof(END) - 1;
    if (e < end && *e == '\r') e++;
    if (e < end && *e == '\n') e++;
    *out_len = (size_t)(e - b);
    *cursor = e;
    return b;
}

#endif
