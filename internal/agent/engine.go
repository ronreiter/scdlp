// Package agent contains the synchronous decision engine.
package agent

import (
	"context"
	"io"
	"log"
	"os"
	"runtime/debug"
	"strings"
	"syscall"
	"time"

	"github.com/ronreiter/scdlp/internal/audit"
	"github.com/ronreiter/scdlp/internal/classify"
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
}

type Engine struct {
	cfg     Config
	matcher *pathrules.Matcher
	classif *classify.Classifier

	auditCh chan audit.Event // 256-deep; full = drop with counter increment
}

func New(cfg Config) *Engine {
	if cfg.Resolver == nil {
		cfg.Resolver = defaultResolver{}
	}
	if cfg.Logger == nil {
		cfg.Logger = log.New(os.Stderr, "agent: ", log.LstdFlags|log.Lmicroseconds)
	}
	e := &Engine{
		cfg:     cfg,
		matcher: pathrules.NewWithDefaults(cfg.Homes),
		classif: classify.New(),
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

	matched, category := e.matcher.Match(ev.Path)
	matchedKind := category
	contentMatch := ""
	if !matched {
		buf, err := readFirst4K(ev.Path)
		if err != nil {
			// Silently dropped before; now surface as warning so we can
			// see when sandbox/TCC denies reads we expected to succeed.
			e.cfg.Logger.Printf("readFirst4K %q: %v", ev.Path, err)
		}
		if buf != nil {
			v := e.classif.ClassifyBuf(buf)
			if v.IsSecret() {
				matched = true
				matchedKind = v.Match
				contentMatch = v.Match
			}
		}
	}
	if !matched {
		return hook.Allow, nil
	}

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
			FilePath: ev.Path, Category: ifEmpty(category, contentMatch),
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

// readFirst4K returns the first 4 KiB of path. Returns (nil, err) on open
// failures (sandbox denials, missing file, permission); (buf, nil) when
// readable. EOF before 4 KiB is normal and returns the partial buffer.
func readFirst4K(path string) ([]byte, error) {
	// O_NONBLOCK so opening a FIFO/device with no peer cannot block the
	// (single-threaded) decision path. A stalled open() would let queued
	// AUTH_OPEN events miss the kernel's response deadline and get the whole
	// ES client SIGKILLed — the v1.0.x restart loop.
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	// Only regular files hold credentials worth classifying. FIFOs, devices,
	// sockets, and directories are never secret stores, and reading them can
	// block or trigger side effects — skip them (treated as non-secret).
	fi, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !fi.Mode().IsRegular() {
		return nil, nil
	}

	buf := make([]byte, 4096)
	n, err := io.ReadFull(f, buf)
	if err != nil && err != io.EOF && err != io.ErrUnexpectedEOF {
		return nil, err
	}
	return buf[:n], nil
}

func ifEmpty(a, b string) string {
	if a != "" {
		return a
	}
	return b
}
