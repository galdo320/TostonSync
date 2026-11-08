// TostónSync — bounded Library scan evidence. Not a restore authority.
#ifndef TOSTONSYNC_CATALOG_SCAN_H
#define TOSTONSYNC_CATALOG_SCAN_H
#include <stdbool.h>

typedef enum {
    CATALOG_COMPLETE, CATALOG_EMPTY, CATALOG_PARTIAL, CATALOG_UNAVAILABLE
} catalog_state_t;

typedef struct {
    catalog_state_t state;
    const char* reason; // static diagnostic code; never credentials
    bool configured;   // absent configuration is not an empty successful scan
} catalog_scan_t;

#endif
