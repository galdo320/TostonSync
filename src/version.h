// TostónSync — single source of truth for the build version shown in the
// UI and logs. Bump TOSTONSYNC_VERSION whenever you ship a build you want to
// recognize in screenshots; the build timestamp is filled in by the compiler
// for the translation unit that reports it (httpd.c, via /api/status).
#ifndef TOSTONSYNC_VERSION_H
#define TOSTONSYNC_VERSION_H

#define TOSTONSYNC_VERSION "0.5.273"
// Operational delivery. Host fixtures may compile the preserved temporary path.
#ifndef TOSTONSYNC_STARTUP_VALIDATION_ONLY
#define TOSTONSYNC_STARTUP_VALIDATION_ONLY 0
#endif
#define TOSTONSYNC_BUILD   (__DATE__ " " __TIME__)

#endif // TOSTONSYNC_VERSION_H
