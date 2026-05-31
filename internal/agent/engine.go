// Package agent contains the synchronous decision engine.
package agent

import (
	"context"
	"log"
	"os"
	"path/filepath"
	"runtime/debug"
	"strings"
	"time"

	"github.com/ronreiter/scdlp/internal/audit"
	"github.com/ronreiter/scdlp/internal/config"
	"github.com/ronreiter/scdlp/internal/hook"
	"github.com/ronreiter/scdlp/internal/identity"
	"github.com/ronreiter/scdlp/internal/pathrules"
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

	// Scope decides which files are inspected at all: a file is checked only if
	// its base name matches the configured scan list (default ["env"]).
	Scope config.Config
}

type Engine struct {
	cfg     Config
	matcher *pathrules.Matcher

	auditCh chan audit.Event // 256-deep; full = drop with counter increment
}

func New(cfg Config) *Engine {
	if cfg.Resolver == nil {
		cfg.Resolver = defaultResolver{}
	}
	if cfg.Logger == nil {
		cfg.Logger = log.New(os.Stderr, "agent: ", log.LstdFlags|log.Lmicroseconds)
	}
	if len(cfg.Scope.ScanNameSubstrings) == 0 {
		cfg.Scope = config.Default()
	}
	e := &Engine{
		cfg:     cfg,
		matcher: pathrules.NewWithDefaults(cfg.Homes),
		auditCh: make(chan audit.Event, 256),
	}
	// Background audit writer. Keeps SQLite INSERTs off the decision path
	// — otherwise a slow audit IO could push us past the ES deadline.
	go e.auditWriter()
	return e
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

	// Scope gate: only files whose base name matches the configured scan list
	// are inspected (default ["env"]). Everything else is allowed untouched.
	if !e.cfg.Scope.InScope(filepath.Base(ev.Path)) {
		return hook.Allow, nil
	}

	// In scope → a protected file. Use the path-rule category as a friendly
	// label when one matches (e.g. ".env" → "dotenv"); otherwise "env-file".
	_, category := e.matcher.Match(ev.Path)
	if category == "" {
		category = "env-file"
	}
	matchedKind := category

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

	audited := &audit.Event{
		TS:           time.Now().Unix(),
		FilePath:     ev.Path,
		FileKey:      category,
		FileKeyKind:  "category",
		ProcessPID:   ev.PID,
		ProcessExe:   id.Exe,
		ProcessChain: strings.Join(id.HumanChain(), "|"),
		IdentityKey:  id.KeyHex,
		MatchedKind:  matchedKind,
	}

	if r != nil {
		audited.FileKey = r.FileKey
		audited.FileKeyKind = string(r.FileKeyKind)
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
		audited.Verdict = "deny"
		e.cfg.Bus.Publish(PromptEvent{
			FilePath: ev.Path, Category: category,
			MatchedKind: matchedKind, PID: ev.PID, Exe: id.Exe,
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
