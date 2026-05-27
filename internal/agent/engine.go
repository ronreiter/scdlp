// Package agent contains the synchronous decision engine.
package agent

import (
	"context"
	"io"
	"log"
	"os"
	"strings"
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
}

func New(cfg Config) *Engine {
	if cfg.Resolver == nil {
		cfg.Resolver = defaultResolver{}
	}
	if cfg.Logger == nil {
		cfg.Logger = log.New(os.Stderr, "agent: ", log.LstdFlags|log.Lmicroseconds)
	}
	return &Engine{
		cfg:     cfg,
		matcher: pathrules.NewWithDefaults(cfg.Homes),
		classif: classify.New(),
	}
}

func (e *Engine) Decide(ev hook.Event) hook.Decision {
	start := time.Now()
	verdict, audited := e.decideInner(ev)
	dur := time.Since(start).Microseconds()
	if audited != nil {
		audited.DurationUs = dur
		if err := e.cfg.Audit.Log(*audited); err != nil {
			e.cfg.Logger.Printf("audit log: %v", err)
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
		if buf, ok := readFirst4K(ev.Path); ok {
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

func readFirst4K(path string) ([]byte, bool) {
	f, err := os.Open(path)
	if err != nil {
		return nil, false
	}
	defer f.Close()
	buf := make([]byte, 4096)
	n, err := io.ReadFull(f, buf)
	if err != nil && err != io.EOF && err != io.ErrUnexpectedEOF {
		return nil, false
	}
	return buf[:n], true
}

func ifEmpty(a, b string) string {
	if a != "" {
		return a
	}
	return b
}
