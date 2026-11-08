// TostónSync — tiny JSON read helpers.
//
// Not a real parser. Just enough to extract specific fields by key
// from Google's JSON responses. Returns the *first* match; nested
// structures are walked naively. Sufficient for our well-known
// response shapes — we never have to parse arbitrary user JSON.

#ifndef TOSTONSYNC_JSON_H
#define TOSTONSYNC_JSON_H

#include <stdbool.h>
#include <stddef.h>

#include "gdrive.h"

#ifdef __cplusplus
extern "C" {
#endif

bool   json_get_string(const char* json, const char* key,
                       char* out, size_t out_sz);
double json_get_number(const char* json, const char* key);

// Find the first array under `key` and within its first object, pull
// the named field as a string. Used for Drive folder-search results.
bool json_get_first_array_string(const char* json, const char* arr_key,
                                 const char* field, char* out, size_t out_sz);

// Parse a Drive files.list response into gdrive_version_t. Returns
// number of entries written.
size_t json_parse_versions(const char* json,
                           gdrive_version_t* out, size_t max_out);

#ifdef __cplusplus
}
#endif
#endif
