// internal/hook/esf_glue.h
#ifndef SCDLP_ESF_GLUE_H
#define SCDLP_ESF_GLUE_H

#include <stdint.h>
#include <stdbool.h>

typedef void* scdlp_es_client_t;

typedef struct {
    uint64_t cookie;       // opaque handle to the in-flight message (scdlp_pending_t*)
    int32_t  pid;
    uint32_t flags;
    uint64_t deadline_ns;  // kernel response budget at receipt, in ns (0 if already past)
    const char* path;
    const char* exe;
} scdlp_es_event_t;

scdlp_es_client_t scdlp_es_new_client(int* err_out);
int  scdlp_es_mute_path_prefix(scdlp_es_client_t cli, const char* prefix);
int  scdlp_es_mute_self(scdlp_es_client_t cli);
void scdlp_es_release_client(scdlp_es_client_t cli);

// scdlp_es_respond delivers the agent's verdict for the message identified by
// cookie. It is idempotent and safe to race against the kernel-deadline safety
// timer: whichever fires first wins, the other becomes a no-op. Returns 1 if
// THIS call actually delivered the verdict, 0 if the message was already
// answered (e.g. the safety timer beat us).
int scdlp_es_respond(uint64_t cookie, int allow);

#endif
