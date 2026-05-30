package agent

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/ronreiter/scdlp/internal/audit"
	"github.com/ronreiter/scdlp/internal/hook"
	"github.com/ronreiter/scdlp/internal/identity"
	"github.com/ronreiter/scdlp/internal/rules"
)

// fakeResolver swaps the real identity.Resolve for deterministic tests.
type fakeResolver map[int]identity.Identity

func (f fakeResolver) Resolve(pid int) (identity.Identity, error) {
	id := f[pid]
	id.Compute()
	return id, nil
}

func tempEngine(t *testing.T, home string, resolver Resolver) (*Engine, *PromptBus) {
	t.Helper()
	dir := t.TempDir()
	rdb, err := rules.Open(filepath.Join(dir, "rules.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { rdb.Close() })
	adb, err := audit.Open(filepath.Join(dir, "audit.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { adb.Close() })
	bus := NewPromptBus(8)
	return New(Config{
		Homes:    []string{home},
		Rules:    rdb,
		Audit:    adb,
		Resolver: resolver,
		Bus:      bus,
	}), bus
}

func TestEngine_UnprotectedAllow(t *testing.T) {
	home := t.TempDir()
	eng, _ := tempEngine(t, home, fakeResolver{1: {Exe: "/bin/cat", Chain: []string{"/bin/cat"}}})
	d := eng.Decide(hook.Event{Path: "/etc/hosts", PID: 1})
	if d != hook.Allow {
		t.Fatalf("want allow, got %v", d)
	}
}

func TestEngine_ProtectedNoRule_Denies_AndEmitsPrompt(t *testing.T) {
	home := t.TempDir()
	if err := os.MkdirAll(filepath.Join(home, ".aws"), 0o700); err != nil {
		t.Fatal(err)
	}
	creds := filepath.Join(home, ".aws/credentials")
	if err := os.WriteFile(creds, []byte("[default]\naws_access_key_id=AKIAIOSFODNN7EXAMPLE\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	eng, bus := tempEngine(t, home, fakeResolver{
		42: {Exe: "/usr/bin/node", Chain: []string{"/usr/bin/node", "/bin/sh", "/usr/local/bin/npm"}},
	})
	d := eng.Decide(hook.Event{Path: creds, PID: 42})
	if d != hook.Deny {
		t.Fatalf("want deny, got %v", d)
	}
	select {
	case p := <-bus.C():
		if !strings.Contains(p.HumanIdentity, "node") {
			t.Fatalf("unexpected human identity: %s", p.HumanIdentity)
		}
		if p.Category != "aws-credentials" {
			t.Fatalf("unexpected category: %s", p.Category)
		}
	case <-time.After(time.Second):
		t.Fatal("expected prompt on bus")
	}
}

func TestEngine_ProtectedWithAllowRule(t *testing.T) {
	home := t.TempDir()
	_ = os.MkdirAll(filepath.Join(home, ".aws"), 0o700)
	creds := filepath.Join(home, ".aws/credentials")
	_ = os.WriteFile(creds, []byte("[default]\n"), 0o600)

	resolver := fakeResolver{
		42: {Exe: "/usr/local/bin/aws", Chain: []string{"/usr/local/bin/aws", "/bin/zsh"}},
	}
	eng, _ := tempEngine(t, home, resolver)

	id := resolver[42]
	id.Compute()
	if _, err := eng.cfg.Rules.Insert(rules.Rule{
		FileKey: "aws-credentials", FileKeyKind: rules.FKCategory,
		IdentityKey: id.KeyHex, IdentityKind: rules.IKChain,
		Verdict: rules.VerdictAllow, CreatedBy: "test",
	}); err != nil {
		t.Fatal(err)
	}
	if got := eng.Decide(hook.Event{Path: creds, PID: 42}); got != hook.Allow {
		t.Fatalf("want allow, got %v", got)
	}
}

func TestEngine_MonitorOnly_AllowsButStillPrompts(t *testing.T) {
	home := t.TempDir()
	if err := os.MkdirAll(filepath.Join(home, ".aws"), 0o700); err != nil {
		t.Fatal(err)
	}
	creds := filepath.Join(home, ".aws/credentials")
	if err := os.WriteFile(creds, []byte("[default]\naws_access_key_id=AKIAIOSFODNN7EXAMPLE\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	dir := t.TempDir()
	rdb, err := rules.Open(filepath.Join(dir, "rules.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { rdb.Close() })
	adb, err := audit.Open(filepath.Join(dir, "audit.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { adb.Close() })
	bus := NewPromptBus(8)
	eng := New(Config{
		Homes: []string{home}, Rules: rdb, Audit: adb, Bus: bus,
		Resolver:    fakeResolver{42: {Exe: "/usr/bin/node", Chain: []string{"/usr/bin/node"}}},
		MonitorOnly: true,
	})

	// In enforce mode this unknown read would be denied; monitor-only must allow.
	if got := eng.Decide(hook.Event{Path: creds, PID: 42}); got != hook.Allow {
		t.Fatalf("monitor-only must allow, got %v", got)
	}
	// …but it must still surface the decision on the prompt bus.
	select {
	case <-bus.C():
	case <-time.After(time.Second):
		t.Fatal("monitor-only must still publish a prompt event")
	}
}

func TestEngine_WriteOnlyFastAllow(t *testing.T) {
	home := t.TempDir()
	eng, _ := tempEngine(t, home, fakeResolver{1: {Exe: "/bin/cat"}})
	d := eng.Decide(hook.Event{Path: filepath.Join(home, ".aws/credentials"),
		PID: 1, Flags: os.O_WRONLY})
	if d != hook.Allow {
		t.Fatal("write-only opens must short-circuit allow")
	}
}

// TestReadFirst4K_DoesNotBlockOnFIFO is a regression test for the ES deadline
// crash loop. The decision engine runs on a single goroutine; readFirst4K used
// to call os.Open(O_RDONLY), which blocks indefinitely on a FIFO (or other
// non-regular file) that has no writer. A single such open() stalls the whole
// decision loop, so queued AUTH_OPEN events never get answered and the kernel
// SIGKILLs the ES client for missing its deadline. readFirst4K must never block
// on a non-regular file.
func TestReadFirst4K_DoesNotBlockOnFIFO(t *testing.T) {
	dir := t.TempDir()
	fifo := filepath.Join(dir, "hang.fifo")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Skipf("mkfifo unsupported: %v", err)
	}

	done := make(chan struct{})
	go func() {
		_, _ = readFirst4K(fifo) // must return promptly, not block on open()
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("readFirst4K blocked on a FIFO with no writer; it must skip non-regular files")
	}
}

// TestDecide_DoesNotBlockOnFIFO exercises the same hazard through the public
// decision path: a process opening a FIFO must get a prompt verdict, never a
// hang that would blow the ES deadline.
func TestDecide_DoesNotBlockOnFIFO(t *testing.T) {
	home := t.TempDir()
	fifo := filepath.Join(home, "hang.fifo")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Skipf("mkfifo unsupported: %v", err)
	}
	eng, _ := tempEngine(t, home, fakeResolver{7: {Exe: "/bin/cat", Chain: []string{"/bin/cat"}}})

	done := make(chan hook.Decision, 1)
	go func() { done <- eng.Decide(hook.Event{Path: fifo, PID: 7}) }()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Decide blocked opening a FIFO; non-regular files must short-circuit")
	}
}

func TestEngine_RunLoopAgainstMockHook(t *testing.T) {
	home := t.TempDir()
	_ = os.MkdirAll(filepath.Join(home, ".aws"), 0o700)
	creds := filepath.Join(home, ".aws/credentials")
	_ = os.WriteFile(creds, []byte("[default]\n"), 0o600)

	eng, _ := tempEngine(t, home, fakeResolver{
		99: {Exe: "/usr/bin/curl", Chain: []string{"/usr/bin/curl"}},
	})
	mh := hook.NewMock()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go eng.Run(ctx, mh)

	got := mh.Inject(hook.Event{Path: creds, PID: 99})
	if got != hook.Deny {
		t.Fatalf("want deny, got %v", got)
	}
}
