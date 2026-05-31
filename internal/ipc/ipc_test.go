package ipc

import (
	"bytes"
	"context"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestEndToEnd_AddRevoke(t *testing.T) {
	sock := filepath.Join(t.TempDir(), "scdlp.sock")
	srv := NewServer(sock, &fakeBackend{})
	if err := srv.Start(); err != nil {
		t.Fatal(err)
	}
	defer srv.Stop()

	c, err := Dial(sock)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	id, err := c.AddRule(AddRuleSpec{
		FileKey: "aws-credentials", FileKeyKind: "category",
		IdentityKey: "abc", IdentityKind: "chain", Verdict: "allow",
	})
	if err != nil || id == 0 {
		t.Fatalf("AddRule: id=%d err=%v", id, err)
	}
	if err := c.RevokeRule(id); err != nil {
		t.Fatalf("RevokeRule: %v", err)
	}
}

func TestEndToEnd_TailAudit(t *testing.T) {
	sock := filepath.Join(t.TempDir(), "scdlp.sock")
	fb := &fakeBackend{tail: []AuditRow{
		{TS: 1, Verdict: "allow", FilePath: "/a"},
		{TS: 2, Verdict: "deny", FilePath: "/b"},
	}}
	srv := NewServer(sock, fb)
	_ = srv.Start()
	defer srv.Stop()

	c, _ := Dial(sock)
	defer c.Close()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	got, err := c.TailAudit(ctx, TailReq{Limit: 10})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("expected 2 audit rows, got %d", len(got))
	}
}

func TestReadFrame_RejectsOversizedLength(t *testing.T) {
	// Construct a header that claims 2 MiB of body — over the 1 MiB cap.
	var buf bytes.Buffer
	hdr := []byte{0x00, 0x20, 0x00, 0x00, 0x01} // length 2 MiB + 1, tag 0x01
	buf.Write(hdr)
	_, _, err := ReadFrame(&buf)
	if err == nil || !strings.Contains(err.Error(), "too large") {
		t.Fatalf("expected too-large error, got %v", err)
	}
}

type fakeBackend struct {
	tail []AuditRow
	last int64
}

func (f *fakeBackend) AddRule(s AddRuleSpec) (int64, error) {
	f.last++
	return f.last, nil
}
func (f *fakeBackend) RevokeRule(id int64) error              { return nil }
func (f *fakeBackend) ListRules(_ ListReq) ([]RuleRow, error) { return nil, nil }
func (f *fakeBackend) Status() (StatusRow, error)             { return StatusRow{Healthy: true}, nil }
func (f *fakeBackend) TailAudit(_ TailReq) ([]AuditRow, error) {
	return f.tail, nil
}
