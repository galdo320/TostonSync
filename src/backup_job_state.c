#include "backup_job_state.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static void copy_value(char* out, size_t out_sz, const char* value) {
    if (!out || !out_sz) return;
    snprintf(out, out_sz, "%s", value ? value : "");
}

bool backup_job_state_read(const char* path, backup_job_state_t* state) {
    if (!path || !state) return false;
    FILE* f = fopen(path, "rb");
    if (!f) return false;
    memset(state, 0, sizeof(*state));
    char line[1024];
    while (fgets(line, sizeof(line), f)) {
        char* nl = strpbrk(line, "\r\n");
        if (nl) *nl = '\0';
        char* eq = strchr(line, '=');
        if (!eq) continue;
        *eq++ = '\0';
        if (strcmp(line, "job_id") == 0)
            state->job_id = strtoul(eq, NULL, 10);
        else if (strcmp(line, "started_at") == 0)
            state->started_at = strtoll(eq, NULL, 10);
        else if (strcmp(line, "completed_at") == 0)
            state->completed_at = strtoll(eq, NULL, 10);
        else if (strcmp(line, "run_id") == 0)
            copy_value(state->run_id, sizeof(state->run_id), eq);
        else if (strcmp(line, "user_uid") == 0)
            copy_value(state->user_uid, sizeof(state->user_uid), eq);
        else if (strcmp(line, "title_id") == 0)
            copy_value(state->title_id, sizeof(state->title_id), eq);
        else if (strcmp(line, "reason") == 0)
            copy_value(state->reason, sizeof(state->reason), eq);
        else if (strcmp(line, "source") == 0)
            copy_value(state->source, sizeof(state->source), eq);
        else if (strcmp(line, "destination") == 0)
            copy_value(state->destination, sizeof(state->destination), eq);
        else if (strcmp(line, "fingerprint") == 0)
            copy_value(state->fingerprint, sizeof(state->fingerprint), eq);
        else if (strcmp(line, "detail") == 0)
            copy_value(state->detail, sizeof(state->detail), eq);
        else if (strcmp(line, "status") == 0)
            copy_value(state->status, sizeof(state->status), eq);
    }
    bool ok = !ferror(f) && state->title_id[0] && state->status[0];
    fclose(f);
    return ok;
}

bool backup_job_state_write(const char* path,
                            const backup_job_state_t* state) {
    if (!path || !state) return false;
    char tmp[512];
    int n = snprintf(tmp, sizeof(tmp), "%s.tmp.%ld", path, (long)getpid());
    if (n < 0 || (size_t)n >= sizeof(tmp)) return false;
    FILE* f = fopen(tmp, "wb");
    if (!f) return false;
    chmod(tmp, 0600);
    fprintf(f,
            "job_id=%lu\nrun_id=%s\nuser_uid=%s\ntitle_id=%s\n"
            "reason=%s\nsource=%s\ndestination=%s\nstarted_at=%lld\n"
            "completed_at=%lld\nfingerprint=%s\ndetail=%s\nstatus=%s\n",
            state->job_id, state->run_id, state->user_uid, state->title_id,
            state->reason, state->source, state->destination,
            (long long)state->started_at, (long long)state->completed_at,
            state->fingerprint, state->detail, state->status);
    bool ok = !ferror(f) && fflush(f) == 0 && fsync(fileno(f)) == 0;
    if (fclose(f) != 0) ok = false;
    if (ok) ok = rename(tmp, path) == 0;
    if (!ok) unlink(tmp);
    return ok;
}
