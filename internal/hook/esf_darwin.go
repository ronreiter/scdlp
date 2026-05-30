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
	"log"
	"sync"
	"sync/atomic"
	"unsafe"
)

type ESFHook struct {
	c      C.scdlp_es_client_t
	q      chan pendingESF
	mu     sync.Mutex
	closed bool

	// Counters exposed for status/diagnostics.
	eventsSeen            atomic.Uint64 // queued events (excludes inline-allow-on-full)
	eventsAgentDecided    atomic.Uint64 // events the agent loop answered
	eventsDeadlineDefault atomic.Uint64 // events auto-answered by the C deadline timer
	eventsQueueFull       atomic.Uint64 // events allowed inline because the queue was full

	// Deadline budget instrumentation (nanoseconds). lastDeadlineNs is the most
	// recent kernel response budget we observed; minDeadlineNs is the tightest.
	// These tell us how much headroom the kernel actually gives us on this OS.
	lastDeadlineNs atomic.Uint64
	minDeadlineNs  atomic.Uint64
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
		// The C layer owns the kernel-deadline guarantee (a per-message safety
		// timer armed at receipt), so the agent no longer needs its own
		// watchdog. We only have to deliver the verdict; scdlp_es_respond is
		// idempotent, so if the timer already fired this is a harmless no-op.
		var once sync.Once
		decide := func(d Decision) {
			once.Do(func() {
				allow := C.int(0)
				if d == Allow {
					allow = 1
				}
				// Only count it as agent-decided if we actually beat the
				// safety timer; otherwise the timer already defaulted it.
				if C.scdlp_es_respond(p.cookie, allow) != 0 {
					h.eventsAgentDecided.Add(1)
				}
			})
		}
		return p.ev, decide, nil
	}
}

// Stats snapshots the per-counter values for /status reporting.
func (h *ESFHook) Stats() ESFStats {
	return ESFStats{
		Seen:            h.eventsSeen.Load(),
		AgentDecided:    h.eventsAgentDecided.Load(),
		DeadlineDefault: h.eventsDeadlineDefault.Load(),
		QueueFull:       h.eventsQueueFull.Load(),
		LastDeadlineNs:  h.lastDeadlineNs.Load(),
		MinDeadlineNs:   h.minDeadlineNs.Load(),
		QueueDepth:      len(h.q),
		QueueCap:        cap(h.q),
	}
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
	// First: mute our own process. Without this, every file the engine
	// reads (SQLite WAL, extension.log, classifier readFirst4K) generates
	// AUTH_OPEN events we have to respond to, recursively.
	if rc := C.scdlp_es_mute_self(h.c); rc != 0 {
		log.Printf("WARN: scdlp_es_mute_self failed; self-event recursion will saturate the queue")
	} else {
		log.Print("muted self process")
	}

	// Second: prefix-mute high-volume directories that are never sensitive
	// secret stores. These cut event volume by an order of magnitude.
	prefixes := []string{
		"/System/",
		"/usr/",
		"/Library/Caches/",
		"/Library/Apple/",
		"/Library/Frameworks/",
		"/Library/PrivateFrameworks/",
		"/Library/Logs/",
		"/private/var/folders/",
		"/private/var/db/",
		"/private/tmp/",
		"/dev/",
		"/Applications/", // includes /Applications/*.app/Contents/...
		"/opt/homebrew/",
		"/opt/local/",
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
	h.recordDeadline(uint64(ev.deadline_ns))
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
		// Queue saturated: answer inline so we never block the ES callback
		// thread. The C safety timer for this message becomes a no-op.
		h.eventsQueueFull.Add(1)
		C.scdlp_es_respond(ev.cookie, 1)
	}
}

//export scdlpGoOnDeadlineDefault
func scdlpGoOnDeadlineDefault() {
	activeMu.RLock()
	h := active
	activeMu.RUnlock()
	if h != nil {
		h.eventsDeadlineDefault.Add(1)
	}
}

// recordDeadline tracks the last and minimum observed kernel response budgets.
func (h *ESFHook) recordDeadline(ns uint64) {
	if ns == 0 {
		return
	}
	h.lastDeadlineNs.Store(ns)
	for {
		cur := h.minDeadlineNs.Load()
		if cur != 0 && cur <= ns {
			return
		}
		if h.minDeadlineNs.CompareAndSwap(cur, ns) {
			return
		}
	}
}
