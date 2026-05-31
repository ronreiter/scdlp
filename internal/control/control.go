// Package control is the user-UI → extension command channel: a world-writable
// directory the menu bar app uses to edit the live policy and revoke rules.
// (History/rules reads go straight to the SQLite DBs; this is only for writes.)
//
// Security: world-writable, like the prompt spool — fine for a single-user Mac.
// Hardening (XPC + audit-token peer validation) is a follow-up.
package control

import (
	"context"
	"encoding/json"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/ronreiter/scdlp/internal/audit"
	"github.com/ronreiter/scdlp/internal/config"
	"github.com/ronreiter/scdlp/internal/rules"
)

// PolicyApplier controls the engine (implemented by *agent.Engine): swap the
// live policy and toggle enforcement (the kill switch).
type PolicyApplier interface {
	SetPolicy(config.Config)
	SetEnabled(bool)
}

// RuleRevoker removes a rule by id (implemented by *rules.Store).
type RuleRevoker interface{ Revoke(int64) error }

// AuditTailer / RuleLister let the controller export read-only views for the UI
// (implemented by *audit.Store / *rules.Store).
type AuditTailer interface {
	Tail(audit.TailFilter) ([]audit.Event, error)
}
type RuleLister interface {
	List(rules.ListFilter) ([]rules.Rule, error)
}

type Controller struct {
	dir, cmdDir string
	applier     PolicyApplier
	revoker     RuleRevoker
	auditSrc    AuditTailer
	ruleSrc     RuleLister
	log         *log.Logger
	lastMod     time.Time
	lastEnabled bool
}

// New creates the control + commands dirs (world-writable so the user-session
// app can edit them) and seeds policy.json from the initial policy if absent.
func New(dir string, initial config.Config, applier PolicyApplier, revoker RuleRevoker, logger *log.Logger) (*Controller, error) {
	if logger == nil {
		logger = log.New(os.Stderr, "control: ", log.LstdFlags)
	}
	cmdDir := filepath.Join(dir, "commands")
	if err := os.MkdirAll(cmdDir, 0o777); err != nil {
		return nil, err
	}
	_ = os.Chmod(dir, 0o777)
	_ = os.Chmod(cmdDir, 0o777)
	c := &Controller{dir: dir, cmdDir: cmdDir, applier: applier, revoker: revoker, log: logger, lastEnabled: true}
	c.seedPolicy(initial)
	c.SyncEnabled() // apply initial on/off state from the disabled marker
	return c, nil
}

func (c *Controller) policyPath() string   { return filepath.Join(c.dir, "policy.json") }
func (c *Controller) disabledPath() string { return filepath.Join(c.dir, "disabled") }

// SyncEnabled toggles enforcement to match the presence of the "disabled"
// marker file (the menu-bar kill switch creates/removes it).
func (c *Controller) SyncEnabled() {
	_, err := os.Stat(c.disabledPath())
	enabled := os.IsNotExist(err) // marker present ⇒ disabled
	if enabled == c.lastEnabled {
		return
	}
	c.lastEnabled = enabled
	c.applier.SetEnabled(enabled)
	if enabled {
		c.log.Print("DLP re-enabled")
	} else {
		c.log.Print("DLP DISABLED (kill switch)")
	}
}

func (c *Controller) seedPolicy(initial config.Config) {
	if _, err := os.Stat(c.policyPath()); err == nil {
		return // already present — don't clobber the user's edits
	}
	data, _ := json.MarshalIndent(config.Config{Policy: initial.Policy}, "", "  ")
	if err := os.WriteFile(c.policyPath(), data, 0o666); err == nil {
		_ = os.Chmod(c.policyPath(), 0o666)
		if fi, err := os.Stat(c.policyPath()); err == nil {
			c.lastMod = fi.ModTime() // don't trigger an immediate redundant reload
		}
	}
}

// ReloadPolicyIfChanged re-reads policy.json when its mtime advances and applies
// it. Returns true if a (valid, non-empty) policy was applied.
func (c *Controller) ReloadPolicyIfChanged() bool {
	fi, err := os.Stat(c.policyPath())
	if err != nil || !fi.ModTime().After(c.lastMod) {
		return false
	}
	c.lastMod = fi.ModTime()
	data, err := os.ReadFile(c.policyPath())
	if err != nil {
		return false
	}
	var cfg config.Config
	if err := json.Unmarshal(data, &cfg); err != nil || len(cfg.Policy) == 0 {
		c.log.Printf("ignoring invalid/empty policy.json (err=%v)", err)
		return false
	}
	c.applier.SetPolicy(cfg)
	c.log.Printf("policy reloaded (%d entries)", len(cfg.Policy))
	return true
}

// ApplyCommands runs and removes queued command files. Returns the count run.
func (c *Controller) ApplyCommands() int {
	matches, _ := filepath.Glob(filepath.Join(c.cmdDir, "*.cmd"))
	n := 0
	for _, p := range matches {
		base := filepath.Base(p)
		if strings.HasPrefix(base, "revoke-") {
			idStr := strings.TrimSuffix(strings.TrimPrefix(base, "revoke-"), ".cmd")
			if id, err := strconv.ParseInt(idStr, 10, 64); err == nil {
				if err := c.revoker.Revoke(id); err != nil {
					c.log.Printf("revoke rule %d: %v", id, err)
				} else {
					c.log.Printf("revoked rule %d", id)
					n++
				}
			}
		}
		os.Remove(p)
	}
	return n
}

// SetExportSources wires the read-only views the controller publishes for the
// UI (history.json + rules.json). Call before Watch.
func (c *Controller) SetExportSources(a AuditTailer, r RuleLister) {
	c.auditSrc, c.ruleSrc = a, r
}

// HistoryRow / RuleRow are the JSON shapes the UI consumes.
type HistoryRow struct {
	TS       int64  `json:"ts"`
	Verdict  string `json:"verdict"`
	Path     string `json:"path"`
	Process  string `json:"process"`
	Category string `json:"category"`
}
type RuleRow struct {
	ID           int64  `json:"id"`
	Glob         string `json:"glob"`
	IdentityKind string `json:"identity_kind"`
	Verdict      string `json:"verdict"`
	CreatedBy    string `json:"created_by"`
}

// export writes world-readable history.json + rules.json for the UI to read,
// so it never has to open the SQLite DBs (which the root extension is writing).
func (c *Controller) export() {
	if c.auditSrc != nil {
		if evs, err := c.auditSrc.Tail(audit.TailFilter{Limit: 500}); err == nil {
			rows := make([]HistoryRow, 0, len(evs))
			for _, e := range evs {
				rows = append(rows, HistoryRow{
					TS: e.TS, Verdict: e.Verdict, Path: e.FilePath,
					Process: e.ProcessChain, Category: e.FileKey,
				})
			}
			writeJSON(filepath.Join(c.dir, "history.json"), rows)
		}
	}
	if c.ruleSrc != nil {
		if rs, err := c.ruleSrc.List(rules.ListFilter{}); err == nil {
			rows := make([]RuleRow, 0, len(rs))
			for _, r := range rs {
				rows = append(rows, RuleRow{
					ID: r.ID, Glob: r.FileKey, IdentityKind: string(r.IdentityKind),
					Verdict: string(r.Verdict), CreatedBy: r.CreatedBy,
				})
			}
			writeJSON(filepath.Join(c.dir, "rules.json"), rows)
		}
	}
}

func writeJSON(path string, v any) {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return
	}
	tmp := path + ".tmp"
	if os.WriteFile(tmp, data, 0o644) == nil {
		_ = os.Rename(tmp, path)
	}
}

// Watch polls for policy edits + commands, and publishes the read-only exports,
// until ctx is cancelled.
func (c *Controller) Watch(ctx context.Context) {
	poll := time.NewTicker(250 * time.Millisecond)
	exp := time.NewTicker(time.Second)
	defer poll.Stop()
	defer exp.Stop()
	c.export()
	for {
		select {
		case <-ctx.Done():
			return
		case <-poll.C:
			c.SyncEnabled()
			c.ReloadPolicyIfChanged()
			c.ApplyCommands()
		case <-exp.C:
			c.export()
		}
	}
}
