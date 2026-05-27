// internal/hook/esf_glue.h
#ifndef SCDLP_ESF_GLUE_H
#define SCDLP_ESF_GLUE_H

#include <stdint.h>
#include <stdbool.h>

typedef void* scdlp_es_client_t;

typedef struct {
    uint64_t cookie;
    int32_t  pid;
    uint32_t flags;
    const char* path;
    const char* exe;
} scdlp_es_event_t;

scdlp_es_client_t scdlp_es_new_client(int* err_out);
int  scdlp_es_mute_path_prefix(scdlp_es_client_t cli, const char* prefix);
void scdlp_es_release_client(scdlp_es_client_t cli);
void scdlp_es_respond(scdlp_es_client_t cli, uint64_t cookie, int allow);

#endif
