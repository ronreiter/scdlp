package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoad_MissingFile_DefaultsToPolicy(t *testing.T) {
	c := Load(filepath.Join(t.TempDir(), "does-not-exist.json"))
	if c.Match("/Users/ron/.env") != ActionPrompt {
		t.Fatalf("missing config must use default policy (prompt on .env)")
	}
}

func TestMatch_Default_PromptsSecrets(t *testing.T) {
	c := Default()
	if c.Match("/Users/ron/proj/.env") != ActionPrompt {
		t.Error(".env should prompt under default policy")
	}
	if c.Match("/Users/ron/.aws/credentials") != ActionPrompt {
		t.Error(".aws/credentials should prompt under default policy")
	}
	if c.Match("/etc/hosts") != ActionIgnore {
		t.Error("unrelated file should be ignored")
	}
}

func TestMatch_UserGlobs(t *testing.T) {
	c := Config{Policy: []PolicyEntry{
		{Glob: "*.env*", Action: "prompt"},
		{Glob: "*/.aws/credentials", Action: "prompt"},
	}}
	cases := map[string]Action{
		"/Users/ron/spaceforge/.env":  ActionPrompt,
		"/Users/ron/app/.env.local":   ActionPrompt,
		"/Users/ron/.aws/credentials": ActionPrompt,
		"/Users/ron/notes.txt":        ActionIgnore,
		"/Users/ron/.aws/config":      ActionIgnore,
	}
	for path, want := range cases {
		if got := c.Match(path); got != want {
			t.Errorf("Match(%q)=%q want %q", path, got, want)
		}
	}
}

func TestMatch_FirstMatchWins(t *testing.T) {
	c := Config{Policy: []PolicyEntry{
		{Glob: "*/Caches/*", Action: "allow"},
		{Glob: "*.env*", Action: "prompt"},
		{Glob: "*/evil/*", Action: "block"},
	}}
	if c.Match("/x/Caches/secret.env") != ActionAllow {
		t.Error("earlier allow glob must win over later prompt glob")
	}
	if c.Match("/x/proj/.env") != ActionPrompt {
		t.Error(".env should prompt")
	}
	if c.Match("/x/evil/data") != ActionBlock {
		t.Error("evil path should block")
	}
}

func TestLoad_MigratesScanSubstrings(t *testing.T) {
	p := filepath.Join(t.TempDir(), "config.json")
	_ = os.WriteFile(p, []byte(`{"scan_name_substrings":["env"]}`), 0o644)
	c := Load(p)
	if c.Match("/Users/ron/.env") != ActionPrompt {
		t.Errorf("legacy scan list should migrate to a prompt glob; got %q", c.Match("/Users/ron/.env"))
	}
	if c.Match("/Users/ron/file.txt") != ActionIgnore {
		t.Error("non-matching file should ignore after migration")
	}
}

func TestLoad_ReadsPolicy(t *testing.T) {
	p := filepath.Join(t.TempDir(), "config.json")
	_ = os.WriteFile(p, []byte(`{"policy":[{"glob":"*/secret/*","action":"block"}]}`), 0o644)
	c := Load(p)
	if c.Match("/a/secret/x") != ActionBlock {
		t.Errorf("policy from file not applied; got %q", c.Match("/a/secret/x"))
	}
}
