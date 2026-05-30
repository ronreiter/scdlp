//go:build darwin

package hook

/*
#cgo CFLAGS: -fno-objc-arc
#cgo LDFLAGS: -lEndpointSecurity -lbsm

#include "esf_glue.h"
#include <stdlib.h>
*/
import "C"

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"
)

// responseDeadline is the cutoff after which we auto-Allow an event whose
// decision the agent hasn't returned yet. The kernel kills ES clients that
// don't respond within ~5 s (ES_AUTH_RESULT_TIMEOUT_DEFAULT); we leave a 2 s
// safety margin.
const responseDeadline = 3 * time.Second

type ESFHook struct {
	c      C.scdlp_es_client_t
	q      chan pendingESF
	mu     sync.Mutex
	closed bool

	// Counters exposed for status/diagnostics.
	eventsSeen        atomic.Uint64 // queued events (excludes inline-allow-on-full)
	eventsWatchdog    atomic.Uint64 // events auto-allowed by the watchdog
	eventsAgentDecided atomic.Uint64 // events decided by the agent loop
	eventsQueueFull   atomic.Uint64 // events allowed inline because queue was full
}

type pendingESF struct {
	ev     Event
	cookie C.uint64_t
}

var (
	activeMu sync.RWMutex
	active   *ESFHook
)

func NewESFHook() (*ESFHook, error) {
	activeMu.Lock()
	defer activeMu.Unlock()
	if active != nil {
		return nil, fmt.Errorf("ESF hook already initialised in this process")
	}

	var errCode C.int
	cli := C.scdlp_es_new_client(&errCode)
	if cli == nil {
		return nil, fmt.Errorf("es_new_client failed: %s", esErrString(int(errCode)))
	}

	h := &ESFHook{
		c: cli,
		q: make(chan pendingESF, 256),
	}
	active = h
	h.applyDefaultMutes()
	return h, nil
}

func (h *ESFHook) Next(ctx context.Context) (Event, DecideFunc, error) {
	select {
	case <-ctx.Done():
		return Event{}, nil, ctx.Err()
	case p := <-h.q:
		var once sync.Once
		respond := func(d Decision, fromWatchdog bool) {
			once.Do(func() {
				if fromWatchdog {
					h.eventsWatchdog.Add(1)
				} else {
					h.eventsAgentDecided.Add(1)
				}
				h.mu.Lock()
				cli := h.c
				closed := h.closed
				h.mu.Unlock()
				if closed || cli == nil {
					return
				}
				allow := C.int(0)
				if d == Allow {
					allow = 1
				}
				C.scdlp_es_respond(cli, p.cookie, allow)
			})
		}

		// Watchdog: kernel kills the client at ~5 s without a response.
		// If the agent doesn't decide in `responseDeadline`, auto-Allow.
		// sync.Once makes whichever path fires first the winner.
		go func() {
			time.Sleep(responseDeadline)
			respond(Allow, true)
		}()

		decide := func(d Decision) { respond(d, false) }
		return p.ev, decide, nil
	}
}

// Stats snapshots the per-counter values for /status reporting.
func (h *ESFHook) Stats() (seen, agent, watchdog, queueFull uint64) {
	return h.eventsSeen.Load(),
		h.eventsAgentDecided.Load(),
		h.eventsWatchdog.Load(),
		h.eventsQueueFull.Load()
}

func (h *ESFHook) Close() error {
	h.mu.Lock()
	if h.closed {
		h.mu.Unlock()
		return nil
	}
	h.closed = true
	cli := h.c
	h.c = nil
	h.mu.Unlock()

	activeMu.Lock()
	active = nil
	activeMu.Unlock()

	if cli != nil {
		C.scdlp_es_release_client(cli)
	}
	return nil
}

func (h *ESFHook) applyDefaultMutes() {
	prefixes := []string{
		"/System/",
		"/usr/share/",
		"/Library/Caches/com.apple.",
		"/private/var/folders/",
		"/dev/",
	}
	for _, p := range prefixes {
		cp := C.CString(p)
		C.scdlp_es_mute_path_prefix(h.c, cp)
		C.free(unsafe.Pointer(cp))
	}
}

func esErrString(code int) string {
	switch code {
	case 0:
		return "success"
	case 1:
		return "not entitled (need com.apple.developer.endpoint-security.client)"
	case 2:
		return "internal ES error"
	case 3:
		return "not permitted (grant Full Disk Access)"
	case 4:
		return "invalid argument"
	case 5:
		return "not privileged (run as root)"
	case 6:
		return "TCC denied"
	default:
		return fmt.Sprintf("unknown ES error %d", code)
	}
}

//export scdlpGoOnEvent
func scdlpGoOnEvent(ev C.scdlp_es_event_t) {
	activeMu.RLock()
	h := active
	activeMu.RUnlock()
	if h == nil {
		return
	}
	p := pendingESF{
		ev: Event{
			Path:  C.GoString(ev.path),
			PID:   int(ev.pid),
			Exe:   C.GoString(ev.exe),
			Flags: int(ev.flags),
		},
		cookie: ev.cookie,
	}
	select {
	case h.q <- p:
		h.eventsSeen.Add(1)
	default:
		h.eventsQueueFull.Add(1)
		C.scdlp_es_respond(h.c, ev.cookie, 1)
	}
}
