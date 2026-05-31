// Package agent contains the synchronous decision engine.
package agent

import (
	"context"
	"log"
	"os"
	"runtime/debug"
	"strings"
	"sync"
	"time"

	"github.com/ronreiter/scdlp/internal/audit"
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
}

type Engine struct {
	cfg Config

	policyMu sync.RWMutex
	policy   config.Config // swappable at runtime via SetPolicy

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
	e := &Engine{
		cfg:     cfg,
		policy:  cfg.Scope,
		auditCh: make(chan audit.Event, 256),
	}
	// Background audit writer. Keeps SQLite INSERTs off the decision path
	// — otherwise a slow audit IO could push us past the ES deadline.
	go e.auditWriter()
	return e
}

// SetHelperPresent wires the prompt-UI liveness check after construction. Call
// before Run starts (no concurrent access).
func (e *Engine) SetHelperPresent(f func() bool) { e.cfg.HelperPresent = f }

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
		// Deny-first only if a prompt UI is available to approve it; if the
		// helper is down, fail OPEN rather than silently blocking.
		if e.cfg.HelperPresent != nil && !e.cfg.HelperPresent() {
			audited.Verdict = "allow-no-helper"
			e.cfg.Logger.Printf("no prompt helper; allowing in-scope read path=%q pid=%d", ev.Path, ev.PID)
			return hook.Allow, audited
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
