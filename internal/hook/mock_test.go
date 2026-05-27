package hook

import (
	"context"
	"testing"
	"time"
)

func TestMockHook_AllowFlow(t *testing.T) {
	m := NewMock()
	go func() {
		_ = m.Inject(Event{Path: "/etc/hosts", PID: 1234, Exe: "/bin/cat"})
	}()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	ev, decide, err := m.Next(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if ev.Path != "/etc/hosts" {
		t.Fatalf("path mismatch: %s", ev.Path)
	}
	decide(Allow)
	if got := m.LastDecision(); got != Allow {
		t.Fatalf("decision mismatch: %v", got)
	}
}

func TestMockHook_DenyFlow(t *testing.T) {
	m := NewMock()
	go func() { _ = m.Inject(Event{Path: "/a", PID: 1, Exe: "/b"}) }()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	_, decide, err := m.Next(ctx)
	if err != nil {
		t.Fatal(err)
	}
	decide(Deny)
	if got := m.LastDecision(); got != Deny {
		t.Fatalf("decision mismatch: %v", got)
	}
}

func TestMockHook_CtxCancel(t *testing.T) {
	m := NewMock()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	if _, _, err := m.Next(ctx); err == nil {
		t.Fatal("expected ctx error, got nil")
	}
}
