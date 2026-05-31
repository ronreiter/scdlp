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

	"github.com/ronreiter/scdlp/internal/config"
)

// PolicyApplier swaps the engine's live policy (implemented by *agent.Engine).
type PolicyApplier interface{ SetPolicy(config.Config) }

// RuleRevoker removes a rule by id (implemented by *rules.Store).
type RuleRevoker interface{ Revoke(int64) error }

type Controller struct {
	dir, cmdDir string
	applier     PolicyApplier
	revoker     RuleRevoker
	log         *log.Logger
	lastMod     time.Time
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
	c := &Controller{dir: dir, cmdDir: cmdDir, applier: applier, revoker: revoker, log: logger}
	c.seedPolicy(initial)
	return c, nil
}

func (c *Controller) policyPath() string { return filepath.Join(c.dir, "policy.json") }

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

// Watch polls for policy edits and commands until ctx is cancelled.
func (c *Controller) Watch(ctx context.Context) {
	t := time.NewTicker(250 * time.Millisecond)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			c.ReloadPolicyIfChanged()
			c.ApplyCommands()
		}
	}
}
