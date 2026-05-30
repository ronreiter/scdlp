#include <EndpointSecurity/EndpointSecurity.h>
#include <bsm/libbsm.h>
#include <dispatch/dispatch.h>
#include <mach/mach.h>
#include <mach/task.h>
#include <mach/task_info.h>
#include <stdlib.h>
#include <string.h>

#include "esf_glue.h"

extern void scdlpGoOnEvent(scdlp_es_event_t ev);

// SCDLP_PATH_BUF is a per-event stack buffer size. Most macOS paths fit in
// PATH_MAX (1024). On the rare overflow we fall back to malloc.
#define SCDLP_PATH_BUF 1024

scdlp_es_client_t scdlp_es_new_client(int* err_out) {
    es_client_t* client = NULL;
    es_new_client_result_t r = es_new_client(&client, ^(es_client_t* c, const es_message_t* m) {
        if (m->event_type != ES_EVENT_TYPE_AUTH_OPEN) {
            return;
        }
        es_message_t* held = (es_message_t*)m;
        es_retain_message(held);

        scdlp_es_event_t ev;
        ev.cookie = (uint64_t)(uintptr_t)held;
        ev.pid    = audit_token_to_pid(m->process->audit_token);
        ev.flags  = m->event.open.fflag;

        // Path and exe are not NUL-terminated in es_string_token_t — copy
        // + terminate. Use stack buffers for the common case; malloc only
        // on rare overlong paths. Avoids ~2 malloc/free pairs per event.
        char pathStack[SCDLP_PATH_BUF];
        char exeStack[SCDLP_PATH_BUF];
        char* pathBuf;
        char* exeBuf;
        int pathHeap = 0, exeHeap = 0;

        size_t pathLen = m->event.open.file->path.length;
        if (pathLen < SCDLP_PATH_BUF) {
            pathBuf = pathStack;
        } else {
            pathBuf = (char*)malloc(pathLen + 1);
            pathHeap = 1;
        }
        memcpy(pathBuf, m->event.open.file->path.data, pathLen);
        pathBuf[pathLen] = '\0';
        ev.path = pathBuf;

        size_t exeLen = m->process->executable->path.length;
        if (exeLen < SCDLP_PATH_BUF) {
            exeBuf = exeStack;
        } else {
            exeBuf = (char*)malloc(exeLen + 1);
            exeHeap = 1;
        }
        memcpy(exeBuf, m->process->executable->path.data, exeLen);
        exeBuf[exeLen] = '\0';
        ev.exe = exeBuf;

        scdlpGoOnEvent(ev);

        if (pathHeap) free(pathBuf);
        if (exeHeap)  free(exeBuf);
    });
    if (r != ES_NEW_CLIENT_RESULT_SUCCESS) {
        if (err_out) *err_out = (int)r;
        return NULL;
    }

    es_event_type_t subs[] = { ES_EVENT_TYPE_AUTH_OPEN };
    if (es_subscribe(client, subs, sizeof(subs)/sizeof(subs[0])) != ES_RETURN_SUCCESS) {
        if (err_out) *err_out = -1;
        es_delete_client(client);
        return NULL;
    }
    if (err_out) *err_out = 0;
    return (scdlp_es_client_t)client;
}

int scdlp_es_mute_path_prefix(scdlp_es_client_t cli, const char* prefix) {
    es_client_t* c = (es_client_t*)cli;
    es_return_t r = es_mute_path(c, prefix, ES_MUTE_PATH_TYPE_PREFIX);
    return (r == ES_RETURN_SUCCESS) ? 0 : -1;
}

// scdlp_es_mute_self tells the kernel to never deliver events from our own
// process. Without this, reading a file inside the decision engine (e.g.
// readFirst4K for content-tier classification, or SQLite/log writes) emits
// new AUTH_OPEN events back to us — a recursive feedback loop that
// saturates the event queue and trips the 5-second response deadline.
int scdlp_es_mute_self(scdlp_es_client_t cli) {
    es_client_t* c = (es_client_t*)cli;
    audit_token_t self_token;
    mach_msg_type_number_t size = TASK_AUDIT_TOKEN_COUNT;
    kern_return_t kr = task_info(
        mach_task_self(), TASK_AUDIT_TOKEN,
        (task_info_t)&self_token, &size);
    if (kr != KERN_SUCCESS) {
        return -1;
    }
    es_return_t r = es_mute_process(c, &self_token);
    return (r == ES_RETURN_SUCCESS) ? 0 : -1;
}

void scdlp_es_release_client(scdlp_es_client_t cli) {
    if (!cli) return;
    es_client_t* c = (es_client_t*)cli;
    es_unsubscribe_all(c);
    es_delete_client(c);
}

void scdlp_es_respond(scdlp_es_client_t cli, uint64_t cookie, int allow) {
    es_client_t* c = (es_client_t*)cli;
    es_message_t* m = (es_message_t*)(uintptr_t)cookie;
    if (!c || !m) return;
    es_auth_result_t result = allow ? ES_AUTH_RESULT_ALLOW : ES_AUTH_RESULT_DENY;
    es_respond_auth_result(c, m, result, false);
    es_release_message(m);
}
