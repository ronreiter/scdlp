package audit

import (
	"path/filepath"
	"testing"
	"time"
)

func openTest(t *testing.T) *Store {
	t.Helper()
	dbPath := filepath.Join(t.TempDir(), "audit.db")
	s, err := Open(dbPath)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func TestStore_LogAndTail(t *testing.T) {
	s := openTest(t)
	now := time.Now().Unix()
	for i := 0; i < 3; i++ {
		if err := s.Log(Event{
			TS: now + int64(i), FilePath: "/Users/alice/.aws/credentials",
			FileKey: "aws-credentials", FileKeyKind: "category",
			ProcessPID: 1000 + i, ProcessExe: "/usr/local/bin/aws",
			ProcessChain: "aws|zsh|Terminal", IdentityKey: "abc",
			Verdict: "deny", MatchedKind: "aws-credentials", DurationUs: 100,
		}); err != nil {
			t.Fatal(err)
		}
	}
	evts, err := s.Tail(TailFilter{Limit: 10})
	if err != nil {
		t.Fatal(err)
	}
	if len(evts) != 3 {
		t.Fatalf("expected 3 events, got %d", len(evts))
	}
	if evts[0].TS < evts[2].TS {
		t.Fatal("expected newest first")
	}
}

func TestStore_Count(t *testing.T) {
	s := openTest(t)
	for i := 0; i < 7; i++ {
		_ = s.Log(Event{TS: int64(i + 1), Verdict: "allow"})
	}
	n, err := s.Count()
	if err != nil {
		t.Fatal(err)
	}
	if n != 7 {
		t.Fatalf("expected 7, got %d", n)
	}
}

func TestStore_TailLimit(t *testing.T) {
	s := openTest(t)
	for i := 0; i < 5; i++ {
		_ = s.Log(Event{TS: int64(i + 1), Verdict: "allow"})
	}
	evts, err := s.Tail(TailFilter{Limit: 2})
	if err != nil {
		t.Fatal(err)
	}
	if len(evts) != 2 {
		t.Fatalf("expected 2 events, got %d", len(evts))
	}
}
