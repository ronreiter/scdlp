#include <EndpointSecurity/EndpointSecurity.h>
#include <bsm/libbsm.h>
#include <dispatch/dispatch.h>
#include <mach/mach.h>
#include <mach/mach_time.h>
#include <mach/task.h>
#include <mach/task_info.h>
#include <stdatomic.h>
#include <stdlib.h>
#include <string.h>
#include <sys/fcntl.h>

#include "esf_glue.h"

extern void scdlpGoOnEvent(scdlp_es_event_t ev);
extern void scdlpGoOnDeadlineDefault(void);
extern void scdlpGoOnRespondError(int rc);

// SCDLP_PATH_BUF is a per-event stack buffer size. Most macOS paths fit in
// PATH_MAX (1024). On the rare overflow we fall back to malloc.
#define SCDLP_PATH_BUF 1024

// When the agent has not produced a verdict by the time the safety timer fires,
// we auto-respond ALLOW. Fail-open is the deliberate choice: a slow/backlogged
// agent must never brick the machine by silently denying every open(). The
// trade-off is surfaced via the deadline-default counter so it is observable.
#define SCDLP_DEADLINE_DEFAULT_ALLOW 1

// scdlp_pending_t tracks one in-flight AUTH_OPEN message. Two parties may try
// to answer it: the Go decision path and the kernel-deadline safety timer.
// `responded` makes the es_respond + es_release_message happen exactly once;
// `refs` (one per party) frees the struct once both are done.
typedef struct {
    es_client_t*  client;
    es_message_t* msg;
    atomic_int    responded;
    atomic_int    refs;
} scdlp_pending_t;

static uint64_t mach_to_ns(uint64_t mach) {
    static mach_timebase_info_data_t tb;
    if (tb.denom == 0) {
        mach_timebase_info(&tb);
    }
    return mach * tb.numer / tb.denom;
}

static void pending_unref(scdlp_pending_t* p) {
    if (atomic_fetch_sub(&p->refs, 1) == 1) {
        free(p);
    }
}

// respond_once answers the message at most once. Returns 1 if THIS call was the
// one that responded, 0 if someone already had. Does not touch refcount.
//
// AUTH_OPEN is a *flags* event and MUST be answered with es_respond_flags_result
// — es_respond_auth_result returns ERR_EVENT_TYPE and the kernel treats the
// message as unanswered, eventually SIGKILLing the client for a missed deadline
// (this was the v1.0.x crash/freeze loop). authorized_flags = 0xFFFFFFFF
// authorizes all requested open flags (allow); 0 authorizes none (deny).
static int respond_once(scdlp_pending_t* p, int allow) {
    if (atomic_exchange(&p->responded, 1) != 0) {
        return 0;
    }
    uint32_t authorized_flags = allow ? 0xFFFFFFFF : 0;
    es_respond_result_t rr = es_respond_flags_result(p->client, p->msg, authorized_flags, false);
    if (rr != ES_RESPOND_RESULT_SUCCESS) {
        scdlpGoOnRespondError((int)rr);
    }
    es_release_message(p->msg);
    return 1;
}

int scdlp_es_respond(uint64_t cookie, int allow) {
    scdlp_pending_t* p = (scdlp_pending_t*)(uintptr_t)cookie;
    if (!p) return 0;
    int won = respond_once(p, allow);
    pending_unref(p); // the Go decision path is done with this message
    return won;
}

scdlp_es_client_t scdlp_es_new_client(int* err_out) {
    es_client_t* client = NULL;

    es_new_client_result_t r = es_new_client(&client, ^(es_client_t* c, const es_message_t* m) {
        if (m->event_type != ES_EVENT_TYPE_AUTH_OPEN) {
            return;
        }
        es_message_t* held = (es_message_t*)m;
        es_retain_message(held);

        scdlp_pending_t* p = (scdlp_pending_t*)malloc(sizeof(scdlp_pending_t));
        p->client = c;
        p->msg    = held;
        atomic_init(&p->responded, 0);
        atomic_init(&p->refs, 2); // Go decision path + safety timer

        // Response budget = how long the kernel will wait before it SIGKILLs us
        // for not answering this message. Read it from the message itself rather
        // than guessing a constant; the budget varies by OS version and load.
        uint64_t now = mach_absolute_time();
        uint64_t budget_ns = (m->deadline > now) ? mach_to_ns(m->deadline - now) : 0;

        // es_event_open_t.fflag uses kernel FFLAGS (FREAD=0x1, FWRITE=0x2), NOT
        // the open(2) O_RDONLY/O_WRONLY/O_RDWR encoding the Go engine expects.
        // Normalize to O_* access mode so the engine's read/write logic works
        // (otherwise a read open looks like O_WRONLY and is fast-allowed).
        uint32_t ff = m->event.open.fflag;
        uint32_t oflags;
        if ((ff & FWRITE) && !(ff & FREAD)) {
            oflags = O_WRONLY;
        } else if ((ff & FWRITE) && (ff & FREAD)) {
            oflags = O_RDWR;
        } else {
            oflags = O_RDONLY; // read (or neither → inspect, fail safe)
        }

        scdlp_es_event_t ev;
        ev.cookie      = (uint64_t)(uintptr_t)p;
        ev.pid         = audit_token_to_pid(m->process->audit_token);
        ev.flags       = oflags;
        ev.deadline_ns = budget_ns;

        // Path and exe are not NUL-terminated in es_string_token_t — copy
        // + terminate. Stack buffers for the common case; malloc only on rare
        // overlong paths.
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

        // Arm the safety timer BEFORE handing the event to Go. This closes the
        // window where an event sits in the Go queue (or the Go loop stalls)
        // with no deadline protection. Fire at half the budget so the agent
        // normally wins the race, but the kernel deadline is never missed.
        uint64_t fire_ns = budget_ns / 2;
        dispatch_after(
            dispatch_time(DISPATCH_TIME_NOW, (int64_t)fire_ns),
            dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0),
            ^{
                if (respond_once(p, SCDLP_DEADLINE_DEFAULT_ALLOW)) {
                    scdlpGoOnDeadlineDefault();
                }
                pending_unref(p);
            });

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
// saturates the event queue and trips the response deadline.
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
