package rules

import (
	"path/filepath"
	"testing"
	"time"
)

func openTest(t *testing.T) *Store {
	t.Helper()
	dbPath := filepath.Join(t.TempDir(), "rules.db")
	s, err := Open(dbPath)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func TestStore_InsertAndLookup_Path(t *testing.T) {
	s := openTest(t)
	r := Rule{
		FileKey: "/Users/alice/.aws/credentials", FileKeyKind: FKPath,
		IdentityKey: "abc", IdentityKind: IKChain,
		Verdict: VerdictAllow, CreatedBy: "user-prompt",
	}
	if _, err := s.Insert(r); err != nil {
		t.Fatalf("Insert: %v", err)
	}
	got, err := s.Lookup(LookupKey{
		PathKey: "/Users/alice/.aws/credentials", CategoryKey: "aws-credentials",
		ChainKey: "abc", ExeKey: "EXE:xyz", Now: time.Now().Unix(),
	})
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	if got == nil || got.Verdict != VerdictAllow {
		t.Fatalf("expected allow rule, got %+v", got)
	}
}

func TestStore_Lookup_PathBeatsCategory(t *testing.T) {
	s := openTest(t)
	if _, err := s.Insert(Rule{
		FileKey: "aws-credentials", FileKeyKind: FKCategory,
		IdentityKey: "abc", IdentityKind: IKChain,
		Verdict: VerdictDeny, CreatedBy: "user",
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Insert(Rule{
		FileKey: "/Users/alice/.aws/credentials", FileKeyKind: FKPath,
		IdentityKey: "abc", IdentityKind: IKChain,
		Verdict: VerdictAllow, CreatedBy: "user",
	}); err != nil {
		t.Fatal(err)
	}
	got, err := s.Lookup(LookupKey{
		PathKey: "/Users/alice/.aws/credentials", CategoryKey: "aws-credentials",
		ChainKey: "abc", ExeKey: "EXE:zzz", Now: time.Now().Unix(),
	})
	if err != nil {
		t.Fatal(err)
	}
	if got == nil || got.Verdict != VerdictAllow || got.FileKeyKind != FKPath {
		t.Fatalf("path-specific allow should win, got %+v", got)
	}
}

func TestStore_Lookup_ExpiredIgnored(t *testing.T) {
	s := openTest(t)
	exp := time.Now().Add(-time.Hour).Unix()
	if _, err := s.Insert(Rule{
		FileKey: "aws-credentials", FileKeyKind: FKCategory,
		IdentityKey: "abc", IdentityKind: IKChain,
		Verdict: VerdictAllow, ExpiresAt: &exp, CreatedBy: "user",
	}); err != nil {
		t.Fatal(err)
	}
	got, err := s.Lookup(LookupKey{
		CategoryKey: "aws-credentials", ChainKey: "abc",
		Now: time.Now().Unix(),
	})
	if err != nil {
		t.Fatal(err)
	}
	if got != nil {
		t.Fatalf("expired rule must not match, got %+v", got)
	}
}

func TestStore_ListAndRevoke(t *testing.T) {
	s := openTest(t)
	id, err := s.Insert(Rule{
		FileKey: "aws-credentials", FileKeyKind: FKCategory,
		IdentityKey: "abc", IdentityKind: IKChain,
		Verdict: VerdictAllow, CreatedBy: "user",
	})
	if err != nil {
		t.Fatal(err)
	}
	all, err := s.List(ListFilter{})
	if err != nil {
		t.Fatal(err)
	}
	if len(all) != 1 || all[0].ID != id {
		t.Fatalf("List returned %+v", all)
	}
	if err := s.Revoke(id); err != nil {
		t.Fatal(err)
	}
	all, _ = s.List(ListFilter{})
	if len(all) != 0 {
		t.Fatalf("expected no rules after revoke, got %d", len(all))
	}
}
