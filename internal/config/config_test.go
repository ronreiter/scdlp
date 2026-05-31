package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoad_MissingFile_DefaultsToEnv(t *testing.T) {
	c := Load(filepath.Join(t.TempDir(), "does-not-exist.json"))
	if len(c.ScanNameSubstrings) != 1 || c.ScanNameSubstrings[0] != "env" {
		t.Fatalf("want default [env], got %v", c.ScanNameSubstrings)
	}
}

func TestLoad_ReadsConfiguredList(t *testing.T) {
	p := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(p, []byte(`{"scan_name_substrings":["secret","key"]}`), 0o644); err != nil {
		t.Fatal(err)
	}
	c := Load(p)
	if len(c.ScanNameSubstrings) != 2 || c.ScanNameSubstrings[0] != "secret" || c.ScanNameSubstrings[1] != "key" {
		t.Fatalf("unexpected list: %v", c.ScanNameSubstrings)
	}
}

func TestLoad_EmptyListFallsBackToDefault(t *testing.T) {
	p := filepath.Join(t.TempDir(), "config.json")
	_ = os.WriteFile(p, []byte(`{"scan_name_substrings":[]}`), 0o644)
	c := Load(p)
	if len(c.ScanNameSubstrings) != 1 || c.ScanNameSubstrings[0] != "env" {
		t.Fatalf("want default on empty, got %v", c.ScanNameSubstrings)
	}
}

func TestInScope(t *testing.T) {
	c := Default()
	cases := map[string]bool{
		".env":        true,
		".env.local":  true,
		".ENV":        true, // case-insensitive
		"environment": true,
		"hosts":       false,
		"id_rsa":      false,
		"foo.txt":     false,
	}
	for name, want := range cases {
		if got := c.InScope(name); got != want {
			t.Errorf("InScope(%q)=%v want %v", name, got, want)
		}
	}
}
