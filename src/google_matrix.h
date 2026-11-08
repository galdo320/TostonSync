#ifndef TOSTONSYNC_GOOGLE_MATRIX_H
#define TOSTONSYNC_GOOGLE_MATRIX_H

#include <stdbool.h>

static inline bool google_matrix_result_ok(int transport_rc, int ssl_error,
                                           int status, int expected_status) {
    return transport_rc == 0 && ssl_error == 0 && status == expected_status;
}

#endif
