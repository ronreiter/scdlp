// Package config loads scdlp's runtime configuration. The core is the policy: an
// ordered list of (glob, action) entries deciding what to do with a file open.
// First match wins; a file matching no glob is ignored (allowed, not inspected).
package config

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"

	"github.com/bmatcuk/doublestar/v4"
)

// Action is what to do with an opened file.
type Action string

const (
	ActionPrompt Action = "prompt" // deny-first + raise an approval prompt
	ActionAllow  Action = "allow"  // always allow
	ActionBlock  Action = "block"  // always deny
	ActionIgnore Action = "ignore" // no glob matched — not inspected
)

// PolicyEntry maps a path glob to an action.
type PolicyEntry struct {
	Glob   string `json:"glob"`
	Action string `json:"action"`
}

type Config struct {
	// Policy is the ordered glob→action list (first match wins).
	Policy []PolicyEntry `json:"policy"`
	// ScanNameSubstrings is the legacy scope knob; migrated to Policy on load.
	ScanNameSubstrings []string `json:"scan_name_substrings,omitempty"`
}

// Default is the built-in policy: prompt on a broad set of common credential
// and secret-bearing files. Each match prompts (deny-first) and the user's
// "remember" choice is scoped to the specific file, so the list can be generous.
func Default() Config {
	globs := []string{
		// dotenv
		"*.env*",
		// cloud providers
		"*/.aws/credentials", "*/.aws/config",
		"*/.config/gcloud/*credential*", "*/.config/gcloud/access_tokens.db",
		"*/.azure/accessTokens.json", "*/.azure/*credential*",
		"*/.oci/*",
		// ssh / gpg / key material. NB: deliberately NOT "*.pem" (too broad —
		// many public certs) or "*.keychain*" (the macOS keychains are read
		// constantly by the OS; guarding them deny-first breaks auth/signing).
		"*/.ssh/id_*", "*/.ssh/*.pem", "*/.gnupg/*",
		"*.p12", "*.pfx", "*.kdbx",
		// package managers / language toolchains
		"*/.npmrc", "*/.pypirc", "*/.gem/credentials", "*/.cargo/credentials*",
		"*/.netrc", "*/.bundle/config",
		// git / forge tokens
		"*/.git-credentials", "*/.config/gh/hosts.yml", "*/.config/hub",
		// containers / k8s
		"*/.docker/config.json", "*/.kube/config", "*kubeconfig",
		// infra-as-code (often embeds secrets)
		"*/.terraform.d/credentials.tfrc.json", "*.tfstate", "*.tfvars",
		"*/.databricks/*",
		// misc credential stores
		"*/.boto", "*/.s3cfg", "*/.pgpass", "*/.my.cnf",
	}
	p := make([]PolicyEntry, 0, len(globs))
	for _, g := range globs {
		p = append(p, PolicyEntry{Glob: g, Action: string(ActionPrompt)})
	}
	return Config{Policy: p}
}

// Load reads JSON config from path. A missing/unreadable/malformed file, or one
// with neither a policy nor a legacy scan list, yields Default. A legacy
// scan_name_substrings list (and no policy) is migrated to prompt globs.
func Load(path string) Config {
	data, err := os.ReadFile(path)
	if err != nil {
		return Default()
	}
	var c Config
	if err := json.Unmarshal(data, &c); err != nil {
		return Default()
	}
	if len(c.Policy) == 0 {
		if len(c.ScanNameSubstrings) > 0 {
			for _, s := range c.ScanNameSubstrings {
				c.Policy = append(c.Policy, PolicyEntry{Glob: "*" + s + "*", Action: string(ActionPrompt)})
			}
		} else {
			return Default()
		}
	}
	return c
}

// Match returns the action for the given path (ActionIgnore if no glob matches).
func (c Config) Match(path string) Action {
	a, _ := c.Matched(path)
	return a
}

// Matched returns the action and the glob of the first matching policy entry,
// or (ActionIgnore, "") if none match. The glob serves as the file's category.
func (c Config) Matched(path string) (Action, string) {
	base := filepath.Base(path)
	for _, e := range c.Policy {
		if globMatches(e.Glob, path, base) {
			switch Action(e.Action) {
			case ActionAllow:
				return ActionAllow, e.Glob
			case ActionBlock:
				return ActionBlock, e.Glob
			default:
				return ActionPrompt, e.Glob // prompt + any unknown token
			}
		}
	}
	return ActionIgnore, ""
}

// globMatches reports whether glob matches the file. It matches against the
// base name (so "*.env*" hits any .env* file) and against the full path with a
// "**/" prefix for relative globs (so "*/.aws/credentials" hits any such tail).
func globMatches(glob, fullPath, base string) bool {
	if ok, _ := doublestar.Match(glob, base); ok {
		return true
	}
	pat := glob
	if !strings.HasPrefix(glob, "/") {
		pat = "**/" + glob
	}
	ok, _ := doublestar.Match(pat, fullPath)
	return ok
}
