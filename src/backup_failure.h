#ifndef TOSTONSYNC_BACKUP_FAILURE_H
#define TOSTONSYNC_BACKUP_FAILURE_H

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "gdrive.h"

// Reporting only: these causes never schedule, retry or authorize a copy.
typedef enum {
    BACKUP_DEST_OK, BACKUP_USB_DISABLED, BACKUP_USB_ABSENT, BACKUP_USB_FAILED,
    BACKUP_FTP_DISABLED, BACKUP_FTP_NO_HOST, BACKUP_FTP_FAILED,
    BACKUP_DRIVE_SIGNED_OUT, BACKUP_DRIVE_GLOBAL_CAP,
    BACKUP_DRIVE_TITLE_CAP, BACKUP_DRIVE_NOT_CONFIGURED,
    BACKUP_DRIVE_NOT_READY, BACKUP_DRIVE_FAILED,
    BACKUP_USB_IDENTITY_REQUIRED, BACKUP_USB_READ_ONLY, BACKUP_USB_NOT_USABLE,
    BACKUP_USB_UNSUPPORTED_FORMAT, BACKUP_USB_FULL, BACKUP_USB_FILE_TOO_LARGE,
    BACKUP_USB_VOLUME_CHANGED, BACKUP_USB_READ_FAILED, BACKUP_USB_WRITE_FAILED,
    BACKUP_USB_PUBLICATION_FAILED
} backup_failure_code_t;

typedef struct {
    backup_failure_code_t code;
    uint64_t used, cap, incoming;
} backup_destination_failure_t;

static inline backup_failure_code_t backup_usb_failure(const char* reason) {
    if (!reason) return BACKUP_USB_FAILED;
    static const struct { const char* reason; backup_failure_code_t code; } reasons[] = {
        {"identity_required", BACKUP_USB_IDENTITY_REQUIRED},
        {"not_connected", BACKUP_USB_ABSENT}, {"read_only", BACKUP_USB_READ_ONLY},
        {"not_usable", BACKUP_USB_NOT_USABLE}, {"locked", BACKUP_USB_NOT_USABLE},
        {"unsupported_format", BACKUP_USB_UNSUPPORTED_FORMAT},
        {"full", BACKUP_USB_FULL}, {"file_too_large", BACKUP_USB_FILE_TOO_LARGE},
        {"volume_changed", BACKUP_USB_VOLUME_CHANGED},
        {"read_failed", BACKUP_USB_READ_FAILED}, {"write_failed", BACKUP_USB_WRITE_FAILED},
        {"publication_failed", BACKUP_USB_PUBLICATION_FAILED}
    };
    for (size_t i = 0; i < sizeof(reasons) / sizeof(reasons[0]); i++)
        if (!strcmp(reason, reasons[i].reason)) return reasons[i].code;
    return BACKUP_USB_FAILED;
}

static inline backup_failure_code_t backup_drive_unavailable(gdrive_state_t state) {
    if (state == GDRIVE_STATE_NOT_CONFIGURED) return BACKUP_DRIVE_NOT_CONFIGURED;
    if (state == GDRIVE_STATE_NOT_SIGNED_IN || state == GDRIVE_STATE_DEVICE_DENIED)
        return BACKUP_DRIVE_SIGNED_OUT;
    return BACKUP_DRIVE_NOT_READY;
}

static inline void backup_readable_size(uint64_t bytes, char* out, size_t n) {
    double unit = bytes >= UINT64_C(1000000000) ? 1000000000.0 : 1000000.0;
    snprintf(out, n, "%.2f %s", (double)bytes / unit,
             bytes >= UINT64_C(1000000000) ? "GB" : "MB");
}

static inline void backup_failure_text(const backup_destination_failure_t* f,
                                       bool es, char* out, size_t n) {
    const char* text = "";
    char used[32], cap[32], incoming[32];
    backup_readable_size(f->used, used, sizeof(used));
    backup_readable_size(f->cap, cap, sizeof(cap));
    backup_readable_size(f->incoming, incoming, sizeof(incoming));
    switch (f->code) {
        case BACKUP_DEST_OK: break;
        case BACKUP_USB_DISABLED: text = es ? "USB: desactivado" : "USB: disabled"; break;
        case BACKUP_USB_ABSENT: text = es ? "USB: no conectado" : "USB: not connected"; break;
        case BACKUP_USB_FAILED: text = es ? "USB: falló la copia; no se reintentará automáticamente" : "USB: copy failed; no automatic retry"; break;
        case BACKUP_USB_IDENTITY_REQUIRED: text = es ? "USB: elige la unidad o inicia un respaldo manual para identificarla" : "USB: choose the drive or start a manual backup to identify it"; break;
        case BACKUP_USB_READ_ONLY: text = es ? "USB: la unidad es de solo lectura; no se reintentará automáticamente" : "USB: drive is read-only; no automatic retry"; break;
        case BACKUP_USB_NOT_USABLE: text = es ? "USB: la unidad no se puede usar; desbloquéala si tiene protección" : "USB: drive cannot be used; unlock it if protected"; break;
        case BACKUP_USB_UNSUPPORTED_FORMAT: text = es ? "USB: formato no compatible; usa exFAT" : "USB: unsupported format; use exFAT"; break;
        case BACKUP_USB_FULL: text = es ? "USB: no hay espacio para este respaldo" : "USB: this backup will not fit"; break;
        case BACKUP_USB_FILE_TOO_LARGE: text = es ? "USB: el respaldo supera el límite por archivo; usa exFAT" : "USB: backup exceeds the file size limit; use exFAT"; break;
        case BACKUP_USB_VOLUME_CHANGED: text = es ? "USB: la unidad cambió o se desconectó; no se reintentará automáticamente" : "USB: drive changed or disconnected; no automatic retry"; break;
        case BACKUP_USB_READ_FAILED: text = es ? "USB: falló la lectura; no se reintentará automáticamente" : "USB: read failed; no automatic retry"; break;
        case BACKUP_USB_WRITE_FAILED: text = es ? "USB: falló la escritura; no se reintentará automáticamente" : "USB: write failed; no automatic retry"; break;
        case BACKUP_USB_PUBLICATION_FAILED: text = es ? "USB: no se pudo confirmar el respaldo; no se reintentará automáticamente" : "USB: backup could not be confirmed; no automatic retry"; break;
        case BACKUP_FTP_DISABLED: text = es ? "FTP: desactivado" : "FTP: disabled"; break;
        case BACKUP_FTP_NO_HOST: text = es ? "FTP: servidor no configurado" : "FTP: host not configured"; break;
        case BACKUP_FTP_FAILED: text = es ? "FTP: falló la subida" : "FTP: upload failed"; break;
        case BACKUP_DRIVE_SIGNED_OUT: text = es ? "Google Drive: sin sesión iniciada" : "Google Drive: not signed in"; break;
        case BACKUP_DRIVE_NOT_CONFIGURED: text = es ? "Google Drive: cliente no configurado" : "Google Drive: client not configured"; break;
        case BACKUP_DRIVE_NOT_READY: text = es ? "Google Drive: conexión no disponible" : "Google Drive: connection not ready"; break;
        case BACKUP_DRIVE_FAILED: text = es ? "Google Drive: falló la subida" : "Google Drive: upload failed"; break;
        case BACKUP_DRIVE_GLOBAL_CAP:
            snprintf(out, n, es
                ? "Google Drive: límite global de respaldos alcanzado (%s de %s usados; este respaldo tiene %s). Aumenta el límite en Ajustes o elimina respaldos antiguos."
                : "Google Drive: global backup size limit reached (%s of %s used; this backup is %s). Raise the limit in Settings or delete old backups.",
                used, cap, incoming);
            return;
        case BACKUP_DRIVE_TITLE_CAP:
            snprintf(out, n, es
                ? "Google Drive: límite de respaldos por juego alcanzado (este respaldo tiene %s; el límite es %s). Aumenta el límite en Ajustes o elimina respaldos antiguos."
                : "Google Drive: per-title backup size limit reached (this backup is %s; limit is %s). Raise the limit in Settings or delete old backups.",
                incoming, cap);
            return;
    }
    snprintf(out, n, "%s", text);
}

static inline void backup_failure_summary(const backup_destination_failure_t failures[3],
                                          bool any_enabled, bool es,
                                          char* out, size_t n) {
    if (!n) return;
    out[0] = '\0';
    // Match the default destination order, without changing the copy order.
    const unsigned order[] = {1, 0, 2};
    for (unsigned i = 0; i < 3; i++) {
        char part[512];
        backup_failure_text(&failures[order[i]], es, part, sizeof(part));
        if (!part[0]) continue;
        size_t len = strlen(out);
        snprintf(out + len, n - len, "%s%s", len ? "; " : "", part);
    }
    if (!any_enabled) {
        size_t len = strlen(out);
        snprintf(out + len, n - len, "%s%s", len ? "; " : "", es
            ? "No hay destinos de respaldo habilitados. Habilita USB o Google Drive en Ajustes."
            : "No backup destinations are enabled. Enable USB or Google Drive in Settings.");
    }
}

#endif
