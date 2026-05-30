// Package hook abstracts the file-open event source. Real backend is the
// macOS Endpoint Security framework; tests use MockHook.
package hook

import "context"

// Decision is the synchronous answer the kernel (or simulator) is waiting for.
type Decision int

const (
	Allow Decision = iota
	Deny
)

func (d Decision) String() string {
	if d == Allow {
		return "allow"
	}
	return "deny"
}

// Event carries everything the agent needs to decide.
type Event struct {
	Path  string // resolved absolute path being opened
	PID   int    // calling process pid
	Exe   string // resolved exe path; if "" the agent will resolve from PID
	Flags int    // open flags (O_RDONLY, O_WRONLY, …)
}

// DecideFunc returns the decision back to the kernel.
type DecideFunc func(Decision)

// ESFStats is a snapshot of the ESF hook's throughput counters, used by the
// status backend and the diagnostic heartbeat log. Defined here (not under a
// build tag) so non-darwin builds can still reference it.
type ESFStats struct {
	Seen            uint64
	AgentDecided    uint64
	DeadlineDefault uint64
	QueueFull       uint64
	LastDeadlineNs  uint64
	MinDeadlineNs   uint64
	QueueDepth      int
	QueueCap        int
}

// Hook is the contract implemented by both MockHook and (later) the ESF backend.
type Hook interface {
	// Next blocks until the next event or ctx is done. Returns the event
	// and a single-shot DecideFunc the agent must call exactly once.
	Next(ctx context.Context) (Event, DecideFunc, error)
}
