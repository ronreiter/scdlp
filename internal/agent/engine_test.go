package agent

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ronreiter/scdlp/internal/audit"
	"github.com/ronreiter/scdlp/internal/classify"
	"github.com/ronreiter/scdlp/internal/config"
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
	// Scope left zero → New() applies the default scan list (["env"]).
	return New(Config{
		Homes:    []string{home},
		Rules:    rdb,
		Audit:    adb,
		Resolver: resolver,
		Bus:      bus,
	}), bus
}

// writeEnv creates an in-scope (name contains "env") secret file and returns it.
func writeEnv(t *testing.T, home string) string {
	t.Helper()
	p := filepath.Join(home, ".env")
	if err := os.WriteFile(p, []byte("AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestEngine_OutOfScope_Allow(t *testing.T) {
	home := t.TempDir()
	eng, bus := tempEngine(t, home, fakeResolver{1: {Exe: "/bin/cat", Chain: []string{"/bin/cat"}}})
	// /etc/hosts has no "env" in its name — must be allowed without inspection.
	if d := eng.Decide(hook.Event{Path: "/etc/hosts", PID: 1}); d != hook.Allow {
		t.Fatalf("want allow, got %v", d)
	}
	select {
	case <-bus.C():
		t.Fatal("out-of-scope file must not publish a prompt")
	case <-time.After(100 * time.Millisecond):
	}
}

func TestEngine_OutOfScope_EvenWithSecretContent(t *testing.T) {
	// Scope is name-based: a non-"env" file is NOT inspected even if it holds
	// what looks like a credential.
	home := t.TempDir()
	secret := filepath.Join(home, "notes.txt")
	if err := os.WriteFile(secret, []byte("aws_access_key_id=AKIAIOSFODNN7EXAMPLE\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	eng, _ := tempEngine(t, home, fakeResolver{1: {Exe: "/bin/cat"}})
	if d := eng.Decide(hook.Event{Path: secret, PID: 1}); d != hook.Allow {
		t.Fatalf("non-env file must be allowed regardless of content, got %v", d)
	}
}

func TestEngine_InScopeNoRule_Denies_AndEmitsPrompt(t *testing.T) {
	home := t.TempDir()
	env := writeEnv(t, home)
	eng, bus := tempEngine(t, home, fakeResolver{
		42: {Exe: "/usr/bin/node", Chain: []string{"/usr/bin/node", "/bin/sh", "/usr/local/bin/npm"}},
	})
	if d := eng.Decide(hook.Event{Path: env, PID: 42}); d != hook.Deny {
		t.Fatalf("want deny (deny-first), got %v", d)
	}
	select {
	case p := <-bus.C():
		if !strings.Contains(p.HumanIdentity, "node") {
			t.Fatalf("unexpected human identity: %s", p.HumanIdentity)
		}
		if p.Category == "" {
			t.Fatal("prompt event must carry a category")
		}
	case <-time.After(time.Second):
		t.Fatal("expected prompt on bus")
	}
}

func TestEngine_InScopeWithAllowRule(t *testing.T) {
	home := t.TempDir()
	env := writeEnv(t, home)

	resolver := fakeResolver{
		42: {Exe: "/usr/local/bin/aws", Chain: []string{"/usr/local/bin/aws", "/bin/zsh"}},
	}
	eng, _ := tempEngine(t, home, resolver)

	id := resolver[42]
	id.Compute()
	// The category is the matched glob (e.g. "*.env*"); the allow rule must use
	// the same key the engine derives.
	_, cat := eng.matchPolicy(env)
	if _, err := eng.cfg.Rules.Insert(rules.Rule{
		FileKey: cat, FileKeyKind: rules.FKCategory,
		IdentityKey: id.KeyHex, IdentityKind: rules.IKChain,
		Verdict: rules.VerdictAllow, CreatedBy: "test",
	}); err != nil {
		t.Fatal(err)
	}
	if got := eng.Decide(hook.Event{Path: env, PID: 42}); got != hook.Allow {
		t.Fatalf("want allow, got %v", got)
	}
}

func TestEngine_MonitorOnly_AllowsButStillPrompts(t *testing.T) {
	home := t.TempDir()
	env := writeEnv(t, home)

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
	if got := eng.Decide(hook.Event{Path: env, PID: 42}); got != hook.Allow {
		t.Fatalf("monitor-only must allow, got %v", got)
	}
	// …but it must still surface the decision on the prompt bus.
	select {
	case <-bus.C():
	case <-time.After(time.Second):
		t.Fatal("monitor-only must still publish a prompt event")
	}
}

func TestEngine_NoHelper_AllowsFirst(t *testing.T) {
	home := t.TempDir()
	env := writeEnv(t, home)
	eng, _ := tempEngine(t, home, fakeResolver{42: {Exe: "/usr/bin/node", Chain: []string{"/usr/bin/node"}}})
	eng.SetHelperPresent(func() bool { return false }) // prompt UI down

	// Would be deny-first, but with no helper to approve it we fail open.
	if got := eng.Decide(hook.Event{Path: env, PID: 42}); got != hook.Allow {
		t.Fatalf("no-helper must allow-first, got %v", got)
	}
}

func TestEngine_HelperPresent_DeniesFirst(t *testing.T) {
	home := t.TempDir()
	env := writeEnv(t, home)
	eng, _ := tempEngine(t, home, fakeResolver{42: {Exe: "/usr/bin/node", Chain: []string{"/usr/bin/node"}}})
	eng.SetHelperPresent(func() bool { return true })

	if got := eng.Decide(hook.Event{Path: env, PID: 42}); got != hook.Deny {
		t.Fatalf("helper present must deny-first, got %v", got)
	}
}

func TestEngine_Policy_AllowBlock_AndSetPolicy(t *testing.T) {
	home := t.TempDir()
	eng, _ := tempEngine(t, home, fakeResolver{1: {Exe: "/bin/cat", Chain: []string{"/bin/cat"}}})
	eng.SetPolicy(config.Config{Policy: []config.PolicyEntry{
		{Glob: "*.secret", Action: "block"},
		{Glob: "*.env", Action: "allow"},
	}})
	if got := eng.Decide(hook.Event{Path: filepath.Join(home, "x.secret"), PID: 1}); got != hook.Deny {
		t.Fatalf("block glob must deny, got %v", got)
	}
	if got := eng.Decide(hook.Event{Path: filepath.Join(home, "x.env"), PID: 1}); got != hook.Allow {
		t.Fatalf("allow glob must allow, got %v", got)
	}
	if got := eng.Decide(hook.Event{Path: filepath.Join(home, "x.txt"), PID: 1}); got != hook.Allow {
		t.Fatalf("unmatched file must be ignored/allowed, got %v", got)
	}
}

func TestEngine_Disabled_AllowsEverything(t *testing.T) {
	home := t.TempDir()
	env := writeEnv(t, home)
	eng, _ := tempEngine(t, home, fakeResolver{1: {Exe: "/bin/cat", Chain: []string{"/bin/cat"}}})
	eng.SetEnabled(false)
	if got := eng.Decide(hook.Event{Path: env, PID: 1}); got != hook.Allow {
		t.Fatalf("disabled engine must allow everything, got %v", got)
	}
	eng.SetEnabled(true)
	if got := eng.Decide(hook.Event{Path: env, PID: 1}); got != hook.Deny {
		t.Fatalf("re-enabled engine must enforce (deny-first), got %v", got)
	}
}

func TestEngine_RepromptCooldown_SuppressesRepeatPrompts(t *testing.T) {
	home := t.TempDir()
	env := writeEnv(t, home)
	eng, bus := tempEngine(t, home, fakeResolver{42: {Exe: "/usr/bin/node", Chain: []string{"/usr/bin/node"}}})
	eng.SetHelperPresent(func() bool { return true })
	now := time.Unix(1000, 0)
	eng.SetClock(func() time.Time { return now })

	// First read: deny-first + a prompt is published.
	if d := eng.Decide(hook.Event{Path: env, PID: 42}); d != hook.Deny {
		t.Fatalf("want deny, got %v", d)
	}
	select {
	case <-bus.C():
	case <-time.After(time.Second):
		t.Fatal("expected first prompt")
	}

	// Repeat within the cooldown window: still denied, but must NOT re-prompt.
	now = now.Add(5 * time.Second)
	if d := eng.Decide(hook.Event{Path: env, PID: 42}); d != hook.Deny {
		t.Fatalf("want deny on repeat, got %v", d)
	}
	select {
	case <-bus.C():
		t.Fatal("repeat within cooldown must not re-prompt (this is the flood)")
	case <-time.After(150 * time.Millisecond):
	}

	// Once the cooldown elapses, prompting resumes.
	now = now.Add(2 * time.Minute)
	if d := eng.Decide(hook.Event{Path: env, PID: 42}); d != hook.Deny {
		t.Fatalf("want deny after cooldown, got %v", d)
	}
	select {
	case <-bus.C():
	case <-time.After(time.Second):
		t.Fatal("expected a fresh prompt after cooldown expired")
	}
}

func TestEngine_RepromptCooldown_CoalescesAcrossUnstableIdentity(t *testing.T) {
	// Same file, but each attempt presents a *different* process-ancestry chain
	// (e.g. an app spawning a fresh subprocess tree, or a helper at a per-launch
	// temp path). The cooldown is keyed on the file, so the second attempt must
	// be denied WITHOUT raising a duplicate popup for the same file.
	home := t.TempDir()
	env := writeEnv(t, home)
	eng, bus := tempEngine(t, home, fakeResolver{
		42: {Exe: "/usr/bin/node", Chain: []string{"/usr/bin/node", "/usr/bin/sh", "/Apps/Moltty"}},
		43: {Exe: "/usr/bin/node", Chain: []string{"/usr/bin/node", "/Apps/Moltty"}}, // different chain ⇒ different identityKey
	})
	eng.SetHelperPresent(func() bool { return true })
	now := time.Unix(1000, 0)
	eng.SetClock(func() time.Time { return now })

	if d := eng.Decide(hook.Event{Path: env, PID: 42}); d != hook.Deny {
		t.Fatalf("want deny, got %v", d)
	}
	select {
	case <-bus.C():
	case <-time.After(time.Second):
		t.Fatal("expected first prompt")
	}

	// Second attempt on the SAME file via a different identity, within cooldown.
	now = now.Add(3 * time.Second)
	if d := eng.Decide(hook.Event{Path: env, PID: 43}); d != hook.Deny {
		t.Fatalf("want deny on repeat, got %v", d)
	}
	select {
	case <-bus.C():
		t.Fatal("same file within cooldown must not re-prompt even with a different identity (this is the duplicate popup)")
	case <-time.After(150 * time.Millisecond):
	}
}

func TestEngine_TrustedApp_AllowsWithoutPrompt(t *testing.T) {
	home := t.TempDir()
	env := writeEnv(t, home)
	// A background reader whose own exe is an unstable/versioned helper, but whose
	// ancestry includes the trusted GUI app (Moltty). This is exactly the case
	// that floods: per-exe rules never match, but trusting the app does.
	eng, bus := tempEngine(t, home, fakeResolver{42: {
		Exe:   "/Applications/Moltty.app/Contents/MacOS/2.1.159",
		Chain: []string{"/Applications/Moltty.app/Contents/MacOS/2.1.159", "/bin/zsh", "/Applications/Moltty.app/Contents/MacOS/Moltty"},
	}})
	eng.SetHelperPresent(func() bool { return true })
	eng.SetPolicy(config.Config{Policy: config.Default().Policy, TrustedApps: []string{"Moltty"}})

	if d := eng.Decide(hook.Event{Path: env, PID: 42}); d != hook.Allow {
		t.Fatalf("trusted-app read must be allowed, got %v", d)
	}
	select {
	case <-bus.C():
		t.Fatal("trusted-app read must not prompt")
	case <-time.After(150 * time.Millisecond):
	}
}

func TestEngine_WriteOnlyFastAllow(t *testing.T) {
	home := t.TempDir()
	eng, _ := tempEngine(t, home, fakeResolver{1: {Exe: "/bin/cat"}})
	d := eng.Decide(hook.Event{Path: filepath.Join(home, ".env"), PID: 1, Flags: os.O_WRONLY})
	if d != hook.Allow {
		t.Fatal("write-only opens must short-circuit allow")
	}
}

func TestEngine_RunLoopAgainstMockHook(t *testing.T) {
	home := t.TempDir()
	env := writeEnv(t, home)

	eng, _ := tempEngine(t, home, fakeResolver{
		99: {Exe: "/usr/bin/curl", Chain: []string{"/usr/bin/curl"}},
	})
	mh := hook.NewMock()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go eng.Run(ctx, mh)

	got := mh.Inject(hook.Event{Path: env, PID: 99})
	if got != hook.Deny {
		t.Fatalf("want deny, got %v", got)
	}
}

func TestEngine_InScope_BenignContent_AllowsWithoutPromptOrRule(t *testing.T) {
	home := t.TempDir()
	env := writeEnv(t, home) // path matches the default "env" scope glob
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

	var reads int
	eng := New(Config{
		Homes: []string{home}, Rules: rdb, Audit: adb, Bus: bus,
		Resolver:   fakeResolver{42: {Exe: "/usr/bin/node", Chain: []string{"/usr/bin/node"}}},
		Classifier: classify.New(),
		ReadHead: func(string) ([]byte, error) {
			reads++
			return []byte("port=8080\nlog_level=info\n"), nil // no secret
		},
	})
	eng.SetHelperPresent(func() bool { return true })

	if d := eng.Decide(hook.Event{Path: env, PID: 42}); d != hook.Allow {
		t.Fatalf("benign protected file must be allowed, got %v", d)
	}
	if reads != 1 {
		t.Fatalf("expected exactly one head read, got %d", reads)
	}
	// Must NOT prompt.
	select {
	case <-bus.C():
		t.Fatal("benign content must not raise a prompt")
	case <-time.After(150 * time.Millisecond):
	}
	// Must NOT persist any rule.
	rs, err := rdb.List(rules.ListFilter{})
	if err != nil {
		t.Fatal(err)
	}
	if len(rs) != 0 {
		t.Fatalf("clean scan must not write a rule, found %d", len(rs))
	}
	// Spec §5: clean allows must be recorded with verdict "allow-clean".
	// The engine writes audit rows asynchronously, so poll briefly.
	deadline := time.Now().Add(time.Second)
	var auditVerdict string
	for time.Now().Before(deadline) {
		evts, err := adb.Tail(audit.TailFilter{Limit: 10})
		if err != nil {
			t.Fatal(err)
		}
		for _, e := range evts {
			if e.FilePath == env {
				auditVerdict = e.Verdict
				break
			}
		}
		if auditVerdict != "" {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if auditVerdict != "allow-clean" {
		t.Fatalf("expected audit verdict %q, got %q", "allow-clean", auditVerdict)
	}
}

func TestEngine_InScope_SecretContent_DeniesAndPrompts(t *testing.T) {
	home := t.TempDir()
	env := writeEnv(t, home)
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
		Resolver:   fakeResolver{42: {Exe: "/usr/bin/node", Chain: []string{"/usr/bin/node"}}},
		Classifier: classify.New(),
		ReadHead: func(string) ([]byte, error) {
			// PEM header → classifier confidence 1.0 → IsSecret true.
			return []byte("-----BEGIN OPENSSH PRIVATE KEY-----\nabc\n"), nil
		},
	})
	eng.SetHelperPresent(func() bool { return true })

	if d := eng.Decide(hook.Event{Path: env, PID: 42}); d != hook.Deny {
		t.Fatalf("secret content must deny-first, got %v", d)
	}
	select {
	case <-bus.C():
	case <-time.After(time.Second):
		t.Fatal("secret content must raise a prompt")
	}
}

func TestEngine_InScope_ReadFailure_FailsSafeToPrompt(t *testing.T) {
	home := t.TempDir()
	env := writeEnv(t, home)
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
		Resolver:   fakeResolver{42: {Exe: "/usr/bin/node", Chain: []string{"/usr/bin/node"}}},
		Classifier: classify.New(),
		ReadHead:   func(string) ([]byte, error) { return nil, os.ErrPermission },
	})
	eng.SetHelperPresent(func() bool { return true })

	if d := eng.Decide(hook.Event{Path: env, PID: 42}); d != hook.Deny {
		t.Fatalf("read failure must fail safe to deny, got %v", d)
	}
	select {
	case <-bus.C():
	case <-time.After(time.Second):
		t.Fatal("read failure must raise a prompt (fail safe)")
	}
}

func TestEngine_ClassifierNil_PreservesDenyFirst(t *testing.T) {
	// Default tempEngine sets no Classifier → feature off → existing behavior.
	home := t.TempDir()
	env := writeEnv(t, home)
	eng, bus := tempEngine(t, home, fakeResolver{42: {Exe: "/usr/bin/node", Chain: []string{"/usr/bin/node"}}})
	eng.SetHelperPresent(func() bool { return true })
	if d := eng.Decide(hook.Event{Path: env, PID: 42}); d != hook.Deny {
		t.Fatalf("nil classifier must deny-first, got %v", d)
	}
	select {
	case <-bus.C():
	case <-time.After(time.Second):
		t.Fatal("nil classifier must still prompt")
	}
}
