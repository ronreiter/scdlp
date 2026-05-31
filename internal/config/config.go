// Package config loads scdlp's runtime configuration. The key knob is which
// files are in scope for inspection: only files whose base name contains one of
// the configured substrings are checked; everything else is allowed untouched.
package config

import (
	"encoding/json"
	"os"
	"strings"
)

type Config struct {
	// ScanNameSubstrings: a file is inspected iff its base name contains one of
	// these (case-insensitive). Default ["env"].
	ScanNameSubstrings []string `json:"scan_name_substrings"`
}

// Default is the built-in configuration used when none is present on disk.
func Default() Config {
	return Config{ScanNameSubstrings: []string{"env"}}
}

// Load reads JSON config from path. Any error (missing/unreadable/malformed) or
// an empty scan list falls back to Default — scdlp must always have a scope.
func Load(path string) Config {
	data, err := os.ReadFile(path)
	if err != nil {
		return Default()
	}
	var c Config
	if err := json.Unmarshal(data, &c); err != nil || len(c.ScanNameSubstrings) == 0 {
		return Default()
	}
	return c
}

// InScope reports whether a file with the given base name should be inspected.
func (c Config) InScope(baseName string) bool {
	lower := strings.ToLower(baseName)
	for _, s := range c.ScanNameSubstrings {
		if s != "" && strings.Contains(lower, strings.ToLower(s)) {
			return true
		}
	}
	return false
}
