package hook

import (
	"context"
	"sync"
)

// MockHook is a test/demo backend. Inject() pushes events; the consumer
// (typically the agent loop) calls Next() and then DecideFunc.
type MockHook struct {
	mu         sync.Mutex
	queue      chan pending
	lastResult Decision
	lastSet    bool
}

type pending struct {
	ev   Event
	done chan Decision
}

func NewMock() *MockHook {
	return &MockHook{queue: make(chan pending, 64)}
}

// Inject submits an event and blocks until Decide is called.
func (m *MockHook) Inject(ev Event) Decision {
	done := make(chan Decision, 1)
	m.queue <- pending{ev: ev, done: done}
	d := <-done
	m.mu.Lock()
	m.lastResult, m.lastSet = d, true
	m.mu.Unlock()
	return d
}

func (m *MockHook) Next(ctx context.Context) (Event, DecideFunc, error) {
	select {
	case <-ctx.Done():
		return Event{}, nil, ctx.Err()
	case p := <-m.queue:
		var once sync.Once
		decide := func(d Decision) {
			once.Do(func() {
				m.mu.Lock()
				m.lastResult, m.lastSet = d, true
				m.mu.Unlock()
				p.done <- d
			})
		}
		return p.ev, decide, nil
	}
}

func (m *MockHook) LastDecision() Decision {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.lastSet {
		return Decision(-1)
	}
	return m.lastResult
}
