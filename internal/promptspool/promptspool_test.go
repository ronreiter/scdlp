package promptspool

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/ronreiter/scdlp/internal/rules"
)

func newSpool(t *testing.T) (*Spool, *rules.Store, string) {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "prompts")
	r, err := rules.Open(filepath.Join(t.TempDir(), "rules.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { r.Close() })
	s, err := New(dir, r, nil)
	if err != nil {
		t.Fatal(err)
	}
	return s, r, dir
}

func TestWrite_CreatesRequestFile(t *testing.T) {
	s, _, dir := newSpool(t)
	id, err := s.Write(Request{Path: "/Users/x/.env", Category: "dotenv", IdentityKey: "abc", Exe: "/bin/cat"})
	if err != nil {
		t.Fatal(err)
	}
	if id == "" {
		t.Fatal("Write must return a non-empty id")
	}
	data, err := os.ReadFile(filepath.Join(dir, id+".req.json"))
	if err != nil {
		t.Fatalf("request file not written: %v", err)
	}
	var got Request
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatal(err)
	}
	if got.Path != "/Users/x/.env" || got.Category != "dotenv" || got.ID != id {
		t.Fatalf("round-trip mismatch: %+v", got)
	}
}

func TestWrite_DedupsSameIdentityCategory(t *testing.T) {
	s, _, dir := newSpool(t)
	req := Request{Path: "/Users/x/.env", Category: "env-file", IdentityKey: "chainK"}
	id1, _ := s.Write(req)
	id2, _ := s.Write(req) // same (identity, category) while first is outstanding
	if id1 == "" {
		t.Fatal("first write should produce a request")
	}
	if id2 != "" {
		t.Fatalf("duplicate write must be deduped (empty id), got %q", id2)
	}
	reqs, _ := filepath.Glob(filepath.Join(dir, "*.req.json"))
	if len(reqs) != 1 {
		t.Fatalf("want exactly 1 request file, got %d", len(reqs))
	}

	// After the reply is processed, the same key may prompt again.
	writeReply(t, dir, id1, "deny", "once")
	if _, err := s.ProcessReplies(); err != nil {
		t.Fatal(err)
	}
	if id3, _ := s.Write(req); id3 == "" {
		t.Fatal("after the reply is handled, a new prompt should be allowed")
	}
}

func writeReply(t *testing.T, dir, id, decision, scope string) {
	t.Helper()
	b, _ := json.Marshal(Reply{Decision: decision, Scope: scope})
	if err := os.WriteFile(filepath.Join(dir, id+".reply.json"), b, 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestProcessReplies_AlwaysAllow_InsertsRuleAndCleansUp(t *testing.T) {
	s, r, dir := newSpool(t)
	id, _ := s.Write(Request{Path: "/Users/x/.env", Category: "dotenv", IdentityKey: "chainkey1"})
	writeReply(t, dir, id, "allow", "always")

	n, err := s.ProcessReplies()
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("want 1 processed, got %d", n)
	}
	rule, err := r.Lookup(rules.LookupKey{CategoryKey: "dotenv", ChainKey: "chainkey1", Now: time.Now().Unix()})
	if err != nil || rule == nil {
		t.Fatalf("expected an allow rule, got rule=%v err=%v", rule, err)
	}
	if rule.Verdict != rules.VerdictAllow {
		t.Fatalf("want allow rule, got %v", rule.Verdict)
	}
	// both files removed
	if _, err := os.Stat(filepath.Join(dir, id+".req.json")); !os.IsNotExist(err) {
		t.Fatal("req file should be deleted")
	}
	if _, err := os.Stat(filepath.Join(dir, id+".reply.json")); !os.IsNotExist(err) {
		t.Fatal("reply file should be deleted")
	}
}

func TestProcessReplies_AlwaysDeny_InsertsDenyRule(t *testing.T) {
	s, r, dir := newSpool(t)
	id, _ := s.Write(Request{Category: "dotenv", IdentityKey: "chainkey2"})
	writeReply(t, dir, id, "deny", "always")
	if _, err := s.ProcessReplies(); err != nil {
		t.Fatal(err)
	}
	rule, _ := r.Lookup(rules.LookupKey{CategoryKey: "dotenv", ChainKey: "chainkey2", Now: time.Now().Unix()})
	if rule == nil || rule.Verdict != rules.VerdictDeny {
		t.Fatalf("want deny rule, got %v", rule)
	}
}

func TestProcessReplies_Once_NoRule(t *testing.T) {
	s, r, dir := newSpool(t)
	id, _ := s.Write(Request{Category: "dotenv", IdentityKey: "chainkey3"})
	writeReply(t, dir, id, "allow", "once")
	if _, err := s.ProcessReplies(); err != nil {
		t.Fatal(err)
	}
	rule, _ := r.Lookup(rules.LookupKey{CategoryKey: "dotenv", ChainKey: "chainkey3", Now: time.Now().Unix()})
	if rule != nil {
		t.Fatalf("once must not create a rule, got %v", rule)
	}
}
