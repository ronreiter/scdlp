package control

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/ronreiter/scdlp/internal/config"
)

type fakeApplier struct{ last config.Config }

func (f *fakeApplier) SetPolicy(c config.Config) { f.last = c }

type fakeRevoker struct{ revoked []int64 }

func (f *fakeRevoker) Revoke(id int64) error { f.revoked = append(f.revoked, id); return nil }

func newCtl(t *testing.T, initial config.Config) (*Controller, *fakeApplier, *fakeRevoker, string) {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "control")
	a, r := &fakeApplier{}, &fakeRevoker{}
	c, err := New(dir, initial, a, r, nil)
	if err != nil {
		t.Fatal(err)
	}
	return c, a, r, dir
}

func TestNew_SeedsPolicyFile(t *testing.T) {
	initial := config.Config{Policy: []config.PolicyEntry{{Glob: "*.env*", Action: "prompt"}}}
	_, _, _, dir := newCtl(t, initial)
	if _, err := os.Stat(filepath.Join(dir, "policy.json")); err != nil {
		t.Fatalf("New must seed policy.json: %v", err)
	}
}

func TestReloadPolicyIfChanged_AppliesNewPolicy(t *testing.T) {
	c, a, _, dir := newCtl(t, config.Default())
	// User edits policy.json.
	newPolicy := `{"policy":[{"glob":"*/secret/*","action":"block"}]}`
	if err := os.WriteFile(filepath.Join(dir, "policy.json"), []byte(newPolicy), 0o644); err != nil {
		t.Fatal(err)
	}
	if !c.ReloadPolicyIfChanged() {
		t.Fatal("expected a reload after policy.json changed")
	}
	if a.last.Match("/x/secret/y") != config.ActionBlock {
		t.Fatalf("edited policy not applied: %+v", a.last)
	}
}

func TestApplyCommands_RevokesRuleAndDeletes(t *testing.T) {
	c, _, r, dir := newCtl(t, config.Default())
	cmd := filepath.Join(dir, "commands", "revoke-7.cmd")
	if err := os.WriteFile(cmd, []byte(""), 0o644); err != nil {
		t.Fatal(err)
	}
	if n := c.ApplyCommands(); n != 1 {
		t.Fatalf("want 1 command applied, got %d", n)
	}
	if len(r.revoked) != 1 || r.revoked[0] != 7 {
		t.Fatalf("want rule 7 revoked, got %v", r.revoked)
	}
	if _, err := os.Stat(cmd); !os.IsNotExist(err) {
		t.Fatal("command file should be deleted after applying")
	}
}
