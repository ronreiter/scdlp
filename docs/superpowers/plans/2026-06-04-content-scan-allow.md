# Content-Scan Auto-Allow Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Wire the existing 4 KiB secret classifier into the decision engine so a `prompt`-glob-flagged file whose first 4 KiB contains no secret is allowed silently (no rule persisted), instead of denying + prompting the user.

**Architecture:** Add two fields to `agent.Config` (`Classifier *classify.Classifier`, `ReadHead func(string)([]byte,error)`). In `decideInner`, at the top of the `ActionPrompt` → `default:` case (path matched a prompt glob, no existing rule), read the head and run `ClassifyBuf(...).IsSecret()`. Clean → `Allow` with audit verdict `allow-clean` and no rule written. Read error or secret found → fall through to today's deny-first + prompt. `Classifier == nil` disables the whole feature, preserving existing behavior. Then wire `classify.New()` into the agent's engine construction.

**Tech Stack:** Go, existing `internal/classify` (Aho-Corasick + regex), `internal/agent`, standard `os` file IO. Tests use `go test` with `MockHook` and injected `ReadHead`.

**Reference spec:** `docs/superpowers/specs/2026-06-04-content-scan-allow-design.md`

---

### Task 1: Add `Classifier` + `ReadHead` config fields and the default head reader

**Files:**
- Modify: `internal/agent/engine.go` (Config struct ~line 32-59; imports ~line 4-19; `New` ~line 77-102)
- Test: `internal/agent/engine_test.go`

This task adds the plumbing (config fields + default reader) with no behavior change yet. The classifier is not consulted until Task 2, so all existing tests must still pass.

- [ ] **Step 1: Add the two fields to `agent.Config`**

In `internal/agent/engine.go`, add to the `Config` struct (place after the `RepromptCooldown` field, before the closing brace at ~line 59):

```go
	// Classifier runs the 4 KiB secret scan on path-flagged files before
	// prompting. Nil ⇒ content scanning is disabled and the engine behaves
	// exactly as before this feature (deny-first + prompt on unmatched
	// in-scope reads).
	Classifier *classify.Classifier

	// ReadHead returns up to the first 4 KiB of the file at path. Injectable so
	// the engine is testable without touching disk. Nil ⇒ a default reader that
	// opens the path and reads ≤4096 bytes.
	ReadHead func(path string) ([]byte, error)
```

- [ ] **Step 2: Add the `classify` import**

In the import block (`internal/agent/engine.go` ~line 4-19), add:

```go
	"github.com/ronreiter/scdlp/internal/classify"
```

(Keep imports grouped/sorted as the file already has them — `classify` sorts before `config`.)

- [ ] **Step 3: Add the default head reader constant + function**

At the end of `internal/agent/engine.go`, append:

```go
// headScanBytes is the content-scan window: the first 4 KiB of a file. Matches
// the classifier's own maxScanBytes so we never read more than it inspects.
const headScanBytes = 4096

// defaultReadHead opens path and returns up to the first headScanBytes bytes.
// The agent runs as root, so it can read the head regardless of the calling
// process's own permissions. A zero-byte file returns an empty slice, nil err.
func defaultReadHead(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	buf := make([]byte, headScanBytes)
	n, err := f.Read(buf)
	if err != nil && err != io.EOF {
		return nil, err
	}
	return buf[:n], nil
}
```

- [ ] **Step 4: Add the `io` import**

In the import block, add `"io"` (sorts after `context`, before `log`).

- [ ] **Step 5: Default `ReadHead` in `New`**

In `New` (`internal/agent/engine.go` ~line 77), add alongside the other defaulting blocks (e.g. after the `RepromptCooldown` default at ~line 87-89):

```go
	if cfg.ReadHead == nil {
		cfg.ReadHead = defaultReadHead
	}
```

- [ ] **Step 6: Run the existing engine tests to confirm no behavior change**

Run: `go test ./internal/agent/ -run TestEngine -v`
Expected: PASS (all pre-existing tests green; the new fields are unused so far, `Classifier` defaults nil).

- [ ] **Step 7: Commit**

```bash
git add internal/agent/engine.go
git commit -m "feat(agent): add Classifier + ReadHead config plumbing for content scan

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

### Task 2: Content-scan benign protected files → allow (the core branch)

**Files:**
- Modify: `internal/agent/engine.go` (`decideInner`, the `ActionPrompt` `default:` case ~line 305-327)
- Test: `internal/agent/engine_test.go`

We add the scan at the very top of the `default:` case (after `Rules.Lookup` returned no allow/deny rule), before today's helper-present / cooldown / prompt logic. Write the tests first.

- [ ] **Step 1: Write the failing tests**

Add to `internal/agent/engine_test.go`. These build an engine with a real classifier and an injected `ReadHead`, plus a counter to assert the reader is/isn't called.

```go
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
}

func TestEngine_InScope_SecretContent_DeniesAndPrompts(t *testing.T) {
	home := t.TempDir()
	env := writeEnv(t, home)
	dir := t.TempDir()
	rdb, _ := rules.Open(filepath.Join(dir, "rules.db"))
	t.Cleanup(func() { rdb.Close() })
	adb, _ := audit.Open(filepath.Join(dir, "audit.db"))
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
	rdb, _ := rules.Open(filepath.Join(dir, "rules.db"))
	t.Cleanup(func() { rdb.Close() })
	adb, _ := audit.Open(filepath.Join(dir, "audit.db"))
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
```

- [ ] **Step 2: Run the new tests to verify they fail**

Run: `go test ./internal/agent/ -run 'TestEngine_InScope_BenignContent|TestEngine_InScope_SecretContent|TestEngine_InScope_ReadFailure|TestEngine_ClassifierNil' -v`
Expected: `TestEngine_InScope_BenignContent...` FAILS (engine denies + prompts because the scan branch does not exist yet). The Secret/ReadFailure/ClassifierNil tests may already pass (they expect today's deny+prompt) — that is fine; the benign test is the one proving the new branch is missing.

- [ ] **Step 3: Add the content-scan branch in `decideInner`**

In `internal/agent/engine.go`, find the `default:` case of the `switch` on the rule lookup (currently starting at ~line 305 with the comment `// Deny-first only if a prompt UI is available...`). Insert the scan block at the **very top** of that `default:` case, before the existing `if e.cfg.HelperPresent != nil && !e.cfg.HelperPresent() {` line:

```go
	default:
		// Content tier: this path matched a prompt glob but has no rule yet.
		// The glob is coarse (it flags candidate secret files by location); if
		// the first 4 KiB holds no actual secret, it's a false positive — allow
		// it silently instead of nagging. Nothing is persisted: every open
		// re-scans, so a file that later gains a secret is caught next time.
		if e.cfg.Classifier != nil {
			if buf, rerr := e.cfg.ReadHead(ev.Path); rerr == nil {
				if !e.cfg.Classifier.ClassifyBuf(buf).IsSecret() {
					audited.Verdict = "allow-clean"
					return hook.Allow, audited
				}
			}
			// read failed (fail safe) or secret found → fall through to
			// today's helper-present / cooldown / deny-first + prompt logic.
		}
		// Deny-first only if a prompt UI is available to approve it; if the
```

(The trailing comment line above is the existing first line of the `default:` case — keep the original code that follows it unchanged.)

- [ ] **Step 4: Run the new tests to verify they pass**

Run: `go test ./internal/agent/ -run 'TestEngine_InScope_BenignContent|TestEngine_InScope_SecretContent|TestEngine_InScope_ReadFailure|TestEngine_ClassifierNil' -v`
Expected: PASS (all four).

- [ ] **Step 5: Run the full agent package to confirm no regressions**

Run: `go test ./internal/agent/ -v`
Expected: PASS (all pre-existing tests still green — they use `tempEngine`, which leaves `Classifier` nil).

- [ ] **Step 6: Commit**

```bash
git add internal/agent/engine.go internal/agent/engine_test.go
git commit -m "feat(agent): allow benign protected files via 4KiB content scan

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

### Task 3: Wire the classifier into the real agent

**Files:**
- Modify: `cmd/scdlp-agent/main.go` (imports; engine construction ~line 95-103)

The engine feature is dormant until a real `Classifier` is supplied. This task turns it on in the production binary.

- [ ] **Step 1: Add the `classify` import**

In `cmd/scdlp-agent/main.go`, add to the import block (sorted with the other `github.com/ronreiter/scdlp/internal/...` imports):

```go
	"github.com/ronreiter/scdlp/internal/classify"
```

- [ ] **Step 2: Pass a `Classifier` into the engine Config**

In `cmd/scdlp-agent/main.go`, modify the `agent.New(agent.Config{...})` call (~line 95-103) to add the `Classifier` field. The result:

```go
	eng := agent.New(agent.Config{
		Homes: []string{*home}, Rules: r, Audit: a, Bus: bus,
		MonitorOnly: *monitorOnly,
		Scope:       scanCfg,
		// Content tier: scan the first 4 KiB of prompt-flagged files; benign
		// ones are allowed without a prompt (ReadHead defaults to disk).
		Classifier: classify.New(),
		// Use the process logger (redirected to extension.log under sysextd)
		// rather than the engine's stderr default, which sysextd discards —
		// otherwise decision/monitor/panic logs would be invisible.
		Logger: log.Default(),
	})
```

- [ ] **Step 3: Build the agent binary**

Run: `go build ./cmd/scdlp-agent/`
Expected: builds with no errors.

- [ ] **Step 4: Run the full test + vet sweep**

Run: `go vet ./... && go test ./...`
Expected: PASS across all packages (including `e2e`).

- [ ] **Step 5: Commit**

```bash
git add cmd/scdlp-agent/main.go
git commit -m "feat(agent): enable content-scan auto-allow in the agent binary

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

## Self-Review

**Spec coverage:**
- §4.1 (Config fields + default reader) → Task 1. ✓
- §4.2 (decision flow, all four decision-table rows: nil / read-error / clean / secret) → Task 2 (branch) + its four tests. ✓
- §4.3 (agent wiring with `classify.New()`, `ReadHead` left default) → Task 3. ✓
- §2 (no rules/schema/IPC changes) → no task touches `internal/rules`, `schema.sql`, or `internal/ipc`. ✓
- §2 (clean scan persists nothing) → asserted by `rdb.List` length 0 in the benign test. ✓
- §5 (audit verdict `allow-clean`) → set in Task 2 Step 3. ✓
- §7 (test matrix incl. "explicit allow still wins" without invoking ReadHead) → covered by the pre-existing `TestEngine_InScopeWithAllowRule` (allow rule hits at `Rules.Lookup`, before the `default:` case, so `ReadHead`/classifier are never reached); no new test needed. ✓

**Placeholder scan:** No TBD/TODO/"handle edge cases"; every code step shows full code. ✓

**Type consistency:** `Config.Classifier *classify.Classifier`, `Config.ReadHead func(string)([]byte,error)`, `defaultReadHead`, `headScanBytes`, verdict string `"allow-clean"`, and `classify.New()`/`ClassifyBuf`/`Verdict.IsSecret()` are used consistently across Tasks 1-3 and match the real classifier API. ✓
