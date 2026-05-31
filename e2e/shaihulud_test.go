//go:build darwin

package e2e_test

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/ronreiter/scdlp/internal/agent"
	"github.com/ronreiter/scdlp/internal/audit"
	"github.com/ronreiter/scdlp/internal/hook"
	"github.com/ronreiter/scdlp/internal/identity"
	"github.com/ronreiter/scdlp/internal/ipc"
	"github.com/ronreiter/scdlp/internal/rules"
)

type fakeResolver map[int]identity.Identity

func (f fakeResolver) Resolve(pid int) (identity.Identity, error) {
	id := f[pid]
	id.Compute()
	return id, nil
}

type backend struct {
	r *rules.Store
	a *audit.Store
}

func (b *backend) AddRule(s ipc.AddRuleSpec) (int64, error) {
	exp := s.ExpiresAt
	return b.r.Insert(rules.Rule{
		FileKey: s.FileKey, FileKeyKind: rules.FileKeyKind(s.FileKeyKind),
		IdentityKey: s.IdentityKey, IdentityKind: rules.IdentityKind(s.IdentityKind),
		Verdict: rules.Verdict(s.Verdict), CreatedBy: "test",
		ExpiresAt: exp, Note: s.Note,
	})
}
func (b *backend) RevokeRule(id int64) error                      { return b.r.Revoke(id) }
func (b *backend) ListRules(_ ipc.ListReq) ([]ipc.RuleRow, error) { return nil, nil }
func (b *backend) Status() (ipc.StatusRow, error)                 { return ipc.StatusRow{Healthy: true}, nil }
func (b *backend) TailAudit(_ ipc.TailReq) ([]ipc.AuditRow, error) {
	rows, _ := b.a.Tail(audit.TailFilter{Limit: 100})
	out := make([]ipc.AuditRow, 0, len(rows))
	for _, r := range rows {
		out = append(out, ipc.AuditRow{
			TS: r.TS, FilePath: r.FilePath, FileKey: r.FileKey, FileKeyKind: r.FileKeyKind,
			ProcessPID: r.ProcessPID, ProcessExe: r.ProcessExe, ProcessChain: r.ProcessChain,
			IdentityKey: r.IdentityKey, Verdict: r.Verdict, MatchedKind: r.MatchedKind,
		})
	}
	return out, nil
}

func TestShaiHulud_DeniesPostinstall(t *testing.T) {
	home := t.TempDir()
	// Shai-Hulud-style worms exfiltrate .env files; that's our in-scope target.
	creds := filepath.Join(home, ".env")
	_ = os.WriteFile(creds, []byte("AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n"), 0o600)

	dir := t.TempDir()

	// macOS unix socket path limit is 104 chars; use /tmp directly for the socket.
	sockDir, err := os.MkdirTemp("/tmp", fmt.Sprintf("scdlp-%d", os.Getpid()))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(sockDir) })

	r, err := rules.Open(filepath.Join(dir, "rules.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	a, err := audit.Open(filepath.Join(dir, "audit.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()

	bus := agent.NewPromptBus(8)
	eng := agent.New(agent.Config{
		Homes: []string{home}, Rules: r, Audit: a, Bus: bus,
		Resolver: fakeResolver{
			4242: {Exe: "/usr/bin/node",
				Chain: []string{"/usr/bin/node", "/bin/sh", "/usr/local/bin/npm", "/usr/bin/node"}},
			1: {Exe: "/usr/local/bin/aws",
				Chain: []string{"/usr/local/bin/aws", "/bin/zsh", "/Applications/Utilities/Terminal.app/Contents/MacOS/Terminal"}},
		},
	})

	sock := filepath.Join(sockDir, "scdlp.sock")
	srv := ipc.NewServer(sock, &backend{r: r, a: a})
	if err := srv.Start(); err != nil {
		t.Fatal(err)
	}
	defer srv.Stop()

	mh := hook.NewMock()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go eng.Run(ctx, mh)

	// 1. Malicious postinstall denied + prompt fires.
	d := mh.Inject(hook.Event{Path: creds, PID: 4242})
	if d != hook.Deny {
		t.Fatalf("postinstall must be denied, got %v", d)
	}
	var cat string
	select {
	case p := <-bus.C():
		if p.Category == "" {
			t.Fatal("prompt event must carry a category")
		}
		cat = p.Category
	case <-time.After(time.Second):
		t.Fatal("expected prompt for the postinstall")
	}

	// 2. User clicks 'Allow Always' for legit aws via CLI.
	c, err := ipc.Dial(sock)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	legit := identity.Identity{Exe: "/usr/local/bin/aws",
		Chain: []string{"/usr/local/bin/aws", "/bin/zsh", "/Applications/Utilities/Terminal.app/Contents/MacOS/Terminal"}}
	legit.Compute()
	if _, err := c.AddRule(ipc.AddRuleSpec{
		FileKey: cat, FileKeyKind: "category",
		IdentityKey: legit.KeyHex, IdentityKind: "chain", Verdict: "allow",
	}); err != nil {
		t.Fatal(err)
	}

	// 3. Legit aws → allow.
	if got := mh.Inject(hook.Event{Path: creds, PID: 1}); got != hook.Allow {
		t.Fatalf("legit aws must be allowed, got %v", got)
	}

	// 4. Postinstall again — still denied (different identity chain).
	if got := mh.Inject(hook.Event{Path: creds, PID: 4242}); got != hook.Deny {
		t.Fatalf("postinstall must remain denied, got %v", got)
	}

	// 5. Audit log has all events. The audit writer is asynchronous, so poll
	//    until the rows land (or time out) rather than reading once.
	var rows []ipc.AuditRow
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		rows, _ = c.TailAudit(context.Background(), ipc.TailReq{Limit: 100})
		if len(rows) >= 3 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if len(rows) < 3 {
		t.Fatalf("expected ≥3 audit rows, got %d", len(rows))
	}
}
