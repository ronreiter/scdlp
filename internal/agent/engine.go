// Package agent contains the synchronous decision engine.
package agent

import (
	"context"
	"io"
	"log"
	"os"
	"runtime/debug"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ronreiter/scdlp/internal/audit"
	"github.com/ronreiter/scdlp/internal/classify"
	"github.com/ronreiter/scdlp/internal/config"
	"github.com/ronreiter/scdlp/internal/hook"
	"github.com/ronreiter/scdlp/internal/identity"
	"github.com/ronreiter/scdlp/internal/rules"
)

// Resolver lets tests swap out identity.Resolve.
type Resolver interface {
	Resolve(pid int) (identity.Identity, error)
}

type defaultResolver struct{}

func (defaultResolver) Resolve(pid int) (identity.Identity, error) {
	return identity.Resolve(pid)
}

type Config struct {
	Homes    []string
	Rules    *rules.Store
	Audit    *audit.Store
	Resolver Resolver
	Bus      *PromptBus
	Logger   *log.Logger

	// MonitorOnly: classify, audit, and publish prompt events as normal, but
	// never return Deny — unknown reads are allowed through instead of blocked
	// with EACCES. Safe default until the user-facing approval prompt exists.
	MonitorOnly bool

	// Scope is the initial glob policy (which paths to prompt/allow/block).
	Scope config.Config

	// HelperPresent reports whether the user-facing prompt UI is available. When
	// it returns false, an unknown in-scope read fails OPEN (allow-first) rather
	// than being denied with no way to approve it. Nil ⇒ always-present.
	HelperPresent func() bool

	// RepromptCooldown is how long after prompting on a file the engine
	// suppresses *re-prompting* that same file. The read is still denied, but
	// no new prompt is raised — this is what stops a chatty background reader
	// (e.g. an AI terminal) from flooding the user, even when its process
	// identity shifts between attempts. Zero ⇒ default 60s.
	RepromptCooldown time.Duration

	// Classifier runs the 4 KiB secret scan on path-flagged files before
	// prompting. Nil ⇒ content scanning is disabled and the engine behaves
	// exactly as before this feature (deny-first + prompt on unmatched
	// in-scope reads).
	Classifier *classify.Classifier

	// ReadHead returns up to the first 4 KiB of the file at path. Injectable so
	// the engine is testable without touching disk. Nil ⇒ a default reader that
	// opens the path and reads ≤4096 bytes.
	ReadHead func(path string) ([]byte, error)
}

type Engine struct {
	cfg Config

	enabled atomic.Bool // false = DLP off: allow everything, no prompts

	policyMu sync.RWMutex
	policy   config.Config // swappable at runtime via SetPolicy

	now func() time.Time // injectable clock (tests); defaults to time.Now

	promptMu   sync.Mutex
	lastPrompt map[string]time.Time // path → last time we raised a prompt

	auditCh chan audit.Event // 256-deep; full = drop with counter increment
}

func New(cfg Config) *Engine {
	if cfg.Resolver == nil {
		cfg.Resolver = defaultResolver{}
	}
	if cfg.Logger == nil {
		cfg.Logger = log.New(os.Stderr, "agent: ", log.LstdFlags|log.Lmicroseconds)
	}
	if len(cfg.Scope.Policy) == 0 {
		cfg.Scope = config.Default()
	}
	if cfg.RepromptCooldown == 0 {
		cfg.RepromptCooldown = 60 * time.Second
	}
	if cfg.ReadHead == nil {
		cfg.ReadHead = defaultReadHead
	}
	e := &Engine{
		cfg:        cfg,
		policy:     cfg.Scope,
		now:        time.Now,
		lastPrompt: make(map[string]time.Time),
		auditCh:    make(chan audit.Event, 256),
	}
	e.enabled.Store(true)
	// Background audit writer. Keeps SQLite INSERTs off the decision path
	// — otherwise a slow audit IO could push us past the ES deadline.
	go e.auditWriter()
	return e
}

// SetHelperPresent wires the prompt-UI liveness check after construction. Call
// before Run starts (no concurrent access).
func (e *Engine) SetHelperPresent(f func() bool) { e.cfg.HelperPresent = f }

// SetEnabled turns enforcement on/off at runtime. When disabled, every open is
// allowed with no inspection or prompt — the user-facing kill switch.
func (e *Engine) SetEnabled(on bool) { e.enabled.Store(on) }

// Enabled reports the current enforcement state.
func (e *Engine) Enabled() bool { return e.enabled.Load() }

// SetPolicy swaps the active glob policy at runtime (e.g. after the user edits
// it). Safe to call concurrently with Decide. Empty policy is ignored.
func (e *Engine) SetPolicy(c config.Config) {
	if len(c.Policy) == 0 {
		return
	}
	e.policyMu.Lock()
	e.policy = c
	e.policyMu.Unlock()
}

func (e *Engine) matchPolicy(path string) (config.Action, string) {
	e.policyMu.RLock()
	defer e.policyMu.RUnlock()
	return e.policy.Matched(path)
}

// SetClock overrides the engine clock (tests only).
func (e *Engine) SetClock(f func() time.Time) { e.now = f }

// trustsChain reports whether the process ancestry belongs to a trusted app.
func (e *Engine) trustsChain(chain []string) bool {
	e.policyMu.RLock()
	defer e.policyMu.RUnlock()
	return e.policy.TrustsChain(chain)
}

// shouldPrompt records that we are about to prompt on a file and reports
// whether a prompt should actually be raised — false if we prompted on the
// same file within RepromptCooldown (so we deny silently instead of flooding).
// It only updates the timestamp when it returns true.
//
// The cooldown is keyed on the file alone, not (identity, file): a single
// logical reader can present an unstable process-ancestry identity between
// back-to-back attempts (e.g. an app spawning a fresh subprocess tree, or a
// helper that lives at a per-launch temp path), which would otherwise sail
// past an identity-scoped cooldown as a "first" prompt and raise a duplicate
// popup for the same file. The access is denied either way; coalescing here
// only suppresses the redundant prompt.
func (e *Engine) shouldPrompt(path string) bool {
	now := e.now()
	e.promptMu.Lock()
	defer e.promptMu.Unlock()
	if last, ok := e.lastPrompt[path]; ok && now.Sub(last) < e.cfg.RepromptCooldown {
		return false
	}
	e.lastPrompt[path] = now
	return true
}

func (e *Engine) auditWriter() {
	defer func() {
		if r := recover(); r != nil {
			e.cfg.Logger.Printf("PANIC in auditWriter: %v\n%s", r, debug.Stack())
			// Restart so audit logging keeps working.
			go e.auditWriter()
		}
	}()
	for ev := range e.auditCh {
		if err := e.cfg.Audit.Log(ev); err != nil {
			e.cfg.Logger.Printf("audit log: %v", err)
		}
	}
}

func (e *Engine) Decide(ev hook.Event) (verdict hook.Decision) {
	// Per-event panic recovery. Decide is on the hot path; any panic here
	// would crash the entire process, which under sysextd means the
	// extension thrashes in a restart loop. Allow-on-panic is the safer
	// fail mode than crash-out (kernel would auto-deny by deadline anyway).
	defer func() {
		if r := recover(); r != nil {
			e.cfg.Logger.Printf("PANIC in Decide path=%q pid=%d: %v\n%s",
				ev.Path, ev.PID, r, debug.Stack())
			verdict = hook.Allow
		}
	}()

	start := time.Now()
	v, audited := e.decideInner(ev)
	verdict = v
	// Monitor-only: surface what we *would* have done (audit row + prompt event
	// keep the real verdict) but never actually block the open.
	if e.cfg.MonitorOnly && verdict == hook.Deny {
		e.cfg.Logger.Printf("MONITOR would-deny path=%q pid=%d (allowed: monitor-only)", ev.Path, ev.PID)
		verdict = hook.Allow
	}
	dur := time.Since(start).Microseconds()
	if audited != nil {
		audited.DurationUs = dur
		// Push audit row to the background writer. If the channel is full,
		// drop the row rather than block the decision path — losing an
		// audit entry is strictly better than missing the ES deadline.
		select {
		case e.auditCh <- *audited:
		default:
			// TODO: counter for dropped audit rows; surface in status.
		}
	}
	return verdict
}

func (e *Engine) decideInner(ev hook.Event) (hook.Decision, *audit.Event) {
	// Kill switch: when disabled, allow everything with no inspection.
	if !e.enabled.Load() {
		return hook.Allow, nil
	}
	// Fast-skip: write-only opens cannot leak data.
	if ev.Flags&(os.O_WRONLY|os.O_RDWR) == os.O_WRONLY {
		return hook.Allow, nil
	}

	action, category := e.matchPolicy(ev.Path) // category = the matched glob
	switch action {
	case config.ActionIgnore:
		return hook.Allow, nil // no glob matched — not inspected, not audited
	case config.ActionAllow:
		// Blanket allow by policy. Record it cheaply (skip the identity walk).
		return hook.Allow, &audit.Event{
			TS: time.Now().Unix(), FilePath: ev.Path,
			FileKey: category, FileKeyKind: "category",
			ProcessPID: ev.PID, ProcessExe: ev.Exe,
			Verdict: "allow", MatchedKind: category,
		}
	}

	// block or prompt → resolve identity (for the record and for rule lookup).
	id, err := e.cfg.Resolver.Resolve(ev.PID)
	if err != nil {
		e.cfg.Logger.Printf("identity resolve pid=%d: %v", ev.PID, err)
	}
	if id.Exe == "" {
		id.Exe = ev.Exe
		if len(id.Chain) == 0 {
			id.Chain = []string{ev.Exe}
		}
		id.Compute()
	}

	// Trusted app: any ancestor belongs to an app the user has allowlisted, so
	// allow without prompting (and record it). This is the durable escape hatch
	// for legitimate-but-chatty readers whose per-exe identity is unstable.
	if e.trustsChain(id.Chain) {
		return hook.Allow, &audit.Event{
			TS: time.Now().Unix(), FilePath: ev.Path,
			FileKey: category, FileKeyKind: "category",
			ProcessPID: ev.PID, ProcessExe: id.Exe,
			ProcessChain: strings.Join(id.HumanChain(), "|"),
			IdentityKey:  id.KeyHex, MatchedKind: category,
			Verdict: "allow-trusted",
		}
	}

	audited := &audit.Event{
		TS:           time.Now().Unix(),
		FilePath:     ev.Path,
		FileKey:      category,
		FileKeyKind:  "category",
		ProcessPID:   ev.PID,
		ProcessExe:   id.Exe,
		ProcessChain: strings.Join(id.HumanChain(), "|"),
		IdentityKey:  id.KeyHex,
		MatchedKind:  category,
	}

	if action == config.ActionBlock {
		audited.Verdict = "block"
		return hook.Deny, audited
	}

	// ActionPrompt: an existing rule decides; otherwise deny-first + prompt.
	r, err := e.cfg.Rules.Lookup(rules.LookupKey{
		PathKey:     ev.Path,
		CategoryKey: category,
		ChainKey:    id.KeyHex,
		ExeKey:      id.ExeOnlyKey,
		Now:         time.Now().Unix(),
	})
	if err != nil {
		e.cfg.Logger.Printf("rules lookup: %v", err)
	}
	switch {
	case r != nil && r.Verdict == rules.VerdictAllow:
		audited.Verdict = "allow"
		audited.RuleID = &r.ID
		return hook.Allow, audited
	case r != nil && r.Verdict == rules.VerdictDeny:
		audited.Verdict = "deny"
		audited.RuleID = &r.ID
		return hook.Deny, audited
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
		// helper is down, fail OPEN rather than silently blocking.
		if e.cfg.HelperPresent != nil && !e.cfg.HelperPresent() {
			audited.Verdict = "allow-no-helper"
			e.cfg.Logger.Printf("no prompt helper; allowing in-scope read path=%q pid=%d", ev.Path, ev.PID)
			return hook.Allow, audited
		}
		// Deny either way; only raise a prompt if we haven't recently prompted
		// on this file — otherwise a chatty reader floods us.
		if !e.shouldPrompt(ev.Path) {
			audited.Verdict = "deny-cooldown"
			return hook.Deny, audited
		}
		audited.Verdict = "deny"
		e.cfg.Bus.Publish(PromptEvent{
			FilePath: ev.Path, Category: category,
			MatchedKind: category, PID: ev.PID, Exe: id.Exe,
			HumanIdentity: id.HumanChainStr(),
			IdentityKey:   id.KeyHex, ExeOnlyKey: id.ExeOnlyKey,
		})
		return hook.Deny, audited
	}
}

func (e *Engine) Run(ctx context.Context, h hook.Hook) {
	// Outer recover: if anything bubbles up past Decide's per-event
	// recover (e.g. a panic in h.Next or in the hook callback we hand
	// back), restart the loop instead of crashing the process.
	defer func() {
		if r := recover(); r != nil {
			e.cfg.Logger.Printf("PANIC in Run loop: %v\n%s", r, debug.Stack())
			// Restart the loop from a fresh goroutine.
			go e.Run(ctx, h)
		}
	}()
	for {
		ev, decide, err := h.Next(ctx)
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			e.cfg.Logger.Printf("hook next: %v", err)
			continue
		}
		decide(e.Decide(ev))
	}
}

// defaultReadHead opens path and returns up to the first classify.MaxScanBytes
// bytes (the classifier's scan window). The agent runs as root, so it can read
// the head regardless of the calling process's own permissions. A zero-byte
// file returns an empty slice, nil err.
func defaultReadHead(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	buf := make([]byte, classify.MaxScanBytes)
	n, err := io.ReadFull(f, buf)
	if err != nil && err != io.ErrUnexpectedEOF && err != io.EOF {
		return nil, err
	}
	return buf[:n], nil
}
