// TostónSync — internal HTTP server.
//
// Serves the Settings UI on the configured port (default 1993) and
// exposes a small REST API the UI calls. Listens on 0.0.0.0 so the
// same UI is reachable from a phone or laptop on the LAN, and from
// the PS5 menu App at 127.0.0.1.
//
// Routes:
//   GET  /                  -> index.html (status + settings)
//   GET  /assets/app.js     -> JS bundle
//   GET  /assets/app.css    -> stylesheet
//   GET  /api/status        -> JSON: ip, oauth state, queue, retention
//   GET  /api/config        -> JSON of current config.ini
//   POST /api/config        -> partial update + persist
//   GET  /api/qr?text=...   -> SVG QR code
//   POST /api/oauth/start   -> begin device flow
//   GET  /api/oauth/poll    -> current state of device flow
//   POST /api/oauth/cancel  -> cancel device flow
//   POST /api/oauth/signout -> wipe tokens.json
//   POST /api/saves         -> local PS5 saves with title names/covers
//   POST /api/backups/catalog
//                            -> backups found across USB and Drive
//   POST /api/versions/:id  -> Drive versions for a title_id
//   GET  /api/usb/versions/:id
//                            -> USB versions for a title_id
//                            -> FTP versions for a title_id
//   GET  /api/observe/...   -> existing observations; never runs an action
//   GET  /api/download-prepared/:id -> stream a file prepared by explicit POST
// Former mutating GET routes return 405; POSTs require existing JSON/auth checks.
//   POST /api/sync          -> kick a sync_all() right now
//   POST /api/restore       -> { "title_id":"...", "file_id":"..." }
//   POST /api/restore-selected
//                            -> queue multiple explicit restore refs
//   POST /api/restore-all   -> restore latest for every backed-up title

#ifndef TOSTONSYNC_HTTPD_H
#define TOSTONSYNC_HTTPD_H

#include <stdbool.h>
#include <stddef.h>
#include "config.h"

#ifdef __cplusplus
extern "C" {
#endif

bool httpd_start(const config_t* cfg);
void httpd_stop(void);
// Called by the admitted daemon loop, never by a request.
void httpd_maintenance(void);
// Local terminal-stop teardown; unlike ordinary stop, reports incomplete joins.
bool httpd_stop_cooperatively(void);
unsigned httpd_active_connections(void);

// IP address of the primary LAN interface, formatted as "192.0.2.42".
// Empty string if not yet known. Useful for the boot toast.
const char* httpd_get_lan_ip(void);

// Detect the address now rather than returning the value cached at start.
// Used by the resume watchdog to notice network return/IP changes.
bool httpd_detect_lan_ip(char* out, size_t out_sz);

#ifdef __cplusplus
}
#endif
#endif
