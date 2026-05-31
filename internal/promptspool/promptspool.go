// Package promptspool is the file-based transport between the (root) system
// extension and the user-session menu bar app. The extension writes a
// "<id>.req.json" describing a blocked access; the app shows the prompt and
// writes "<id>.reply.json" with the user's choice. On an "always" reply the
// spool inserts a persistent rule so the access isn't prompted again.
//
// Security: this trusts the filesystem (the spool dir is shared between root
// and the console user). Adequate for a single-user Mac; a hardened build
// should move to XPC with audit-token peer validation.
package promptspool

import (
	"context"
	"encoding/json"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/ronreiter/scdlp/internal/rules"
)

// Request is written by the extension for each blocked, in-scope access.
type Request struct {
	ID          string `json:"id"`
	TS          int64  `json:"ts"`
	PID         int    `json:"pid"`
	Exe         string `json:"exe"`
	HumanChain  string `json:"human_chain"`
	Path        string `json:"path"`
	Category    string `json:"category"`
	IdentityKey string `json:"identity_key"`
	ExeOnlyKey  string `json:"exe_only_key"`
}

// Reply is written by the menu bar app with the user's decision.
type Reply struct {
	Decision string `json:"decision"` // "allow" | "deny"
	Scope    string `json:"scope"`    // "once" | "always"
}

type Spool struct {
	dir   string
	rules *rules.Store
	log   *log.Logger

	mu      sync.Mutex
	pending map[string]bool // dedup key (identity|category) → request outstanding
}

func dedupKey(identityKey, category string) string {
	return identityKey + "|" + category
}

// New creates the spool directory (group/other-writable so the user-session app
// can drop reply files next to the root-written requests).
func New(dir string, r *rules.Store, logger *log.Logger) (*Spool, error) {
	if logger == nil {
		logger = log.New(os.Stderr, "promptspool: ", log.LstdFlags)
	}
	if err := os.MkdirAll(dir, 0o777); err != nil {
		return nil, err
	}
	// MkdirAll is subject to umask; force the mode so the console user can write.
	_ = os.Chmod(dir, 0o777)

	// Clear any leftover requests/replies from a previous run. Stale prompts
	// must never be replayed — those accesses are long gone, and a backlog
	// would flood the user with popups the moment a helper starts draining it.
	if entries, err := filepath.Glob(filepath.Join(dir, "*.json")); err == nil {
		for _, p := range entries {
			os.Remove(p)
		}
	}
	return &Spool{dir: dir, rules: r, log: logger, pending: map[string]bool{}}, nil
}

// Write persists a prompt request and returns its id. Repeated requests for the
// same (identity, file) while one is still outstanding are deduped (return
// "", nil) so a process reading a file in a loop raises a single prompt, not
// hundreds.
func (s *Spool) Write(req Request) (string, error) {
	key := dedupKey(req.IdentityKey, req.Path)
	s.mu.Lock()
	if s.pending[key] {
		s.mu.Unlock()
		return "", nil
	}
	s.pending[key] = true
	s.mu.Unlock()

	if req.ID == "" {
		req.ID = uuid.NewString()
	}
	if req.TS == 0 {
		req.TS = time.Now().Unix()
	}
	data, err := json.MarshalIndent(req, "", "  ")
	if err != nil {
		return "", err
	}
	// Write to a temp file then rename so the watcher never sees a partial req.
	final := filepath.Join(s.dir, req.ID+".req.json")
	tmp := final + ".tmp"
	if err := os.WriteFile(tmp, data, 0o644); err != nil {
		s.clearPending(key)
		return "", err
	}
	if err := os.Rename(tmp, final); err != nil {
		s.clearPending(key)
		return "", err
	}
	return req.ID, nil
}

func (s *Spool) clearPending(key string) {
	s.mu.Lock()
	delete(s.pending, key)
	s.mu.Unlock()
}

// ProcessReplies scans for reply files, applies each (inserting a rule when the
// scope is "always"), removes the request+reply pair, and returns the count
// handled.
func (s *Spool) ProcessReplies() (int, error) {
	matches, err := filepath.Glob(filepath.Join(s.dir, "*.reply.json"))
	if err != nil {
		return 0, err
	}
	n := 0
	for _, replyPath := range matches {
		id := strings.TrimSuffix(filepath.Base(replyPath), ".reply.json")
		reqPath := filepath.Join(s.dir, id+".req.json")

		var reply Reply
		if data, err := os.ReadFile(replyPath); err != nil || json.Unmarshal(data, &reply) != nil {
			// Unreadable/garbage reply — drop it so it can't wedge the spool.
			os.Remove(replyPath)
			continue
		}
		var req Request
		if data, err := os.ReadFile(reqPath); err == nil {
			_ = json.Unmarshal(data, &req)
		}

		if err := s.apply(req, reply); err != nil {
			s.log.Printf("apply reply id=%s: %v", id, err)
		}
		// Allow this (identity, file) to prompt again (unless a rule was created,
		// in which case future reads won't reach the prompt).
		s.clearPending(dedupKey(req.IdentityKey, req.Path))
		os.Remove(replyPath)
		os.Remove(reqPath)
		n++
	}
	return n, nil
}

func (s *Spool) apply(req Request, reply Reply) error {
	// "once" (default) leaves no persistent rule. "always" matches the exact
	// process chain; "always-exe" matches just the leaf executable (broader —
	// any launch context of that program). Either way the rule is scoped to the
	// SPECIFIC file that was accessed, not the whole policy glob — so allowing
	// "cat ./spaceforge/.env" does not allow cat to read every other .env file.
	var identityKey string
	var kind rules.IdentityKind
	switch reply.Scope {
	case "always":
		identityKey, kind = req.IdentityKey, rules.IKChain
	case "always-exe":
		identityKey, kind = req.ExeOnlyKey, rules.IKExeOnly
	default:
		return nil
	}
	if identityKey == "" || req.Path == "" {
		return nil // not enough context to build a rule
	}
	verdict := rules.VerdictAllow
	if reply.Decision == "deny" {
		verdict = rules.VerdictDeny
	}
	_, err := s.rules.Insert(rules.Rule{
		FileKey: req.Path, FileKeyKind: rules.FKPath,
		IdentityKey: identityKey, IdentityKind: kind,
		Verdict: verdict, CreatedBy: "prompt",
	})
	return err
}

// Heartbeat file the menu bar helper touches periodically; the extension uses
// its freshness to decide whether a prompt UI is available (see HelperAlive).
const heartbeatName = ".helper-alive"
const heartbeatTTL = 6 * time.Second

// HeartbeatPath is where the helper should touch its liveness file.
func (s *Spool) HeartbeatPath() string { return filepath.Join(s.dir, heartbeatName) }

// HelperAlive reports whether the menu bar helper has touched its heartbeat
// recently. When false, the engine fails OPEN (allow-first) rather than
// silently denying in-scope reads no one can approve.
func (s *Spool) HelperAlive() bool {
	fi, err := os.Stat(filepath.Join(s.dir, heartbeatName))
	if err != nil {
		return false
	}
	return time.Since(fi.ModTime()) < heartbeatTTL
}

// Watch polls for replies until ctx is cancelled.
func (s *Spool) Watch(ctx context.Context) {
	t := time.NewTicker(250 * time.Millisecond)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if _, err := s.ProcessReplies(); err != nil {
				s.log.Printf("process replies: %v", err)
			}
		}
	}
}
