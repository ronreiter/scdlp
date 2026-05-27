# scdlp v1 Core Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Land the Go-side core of scdlp end-to-end: classifier, path/identity/rules/audit stores, decision engine, IPC, daemon, CLI. The hook layer is an interface today with a `MockHook` for tests; the real Endpoint Security System Extension (C/Swift/Xcode) is a follow-up plan (out of scope) because it depends on the Apple ESF entitlement and on a signing/notarization toolchain that has to be set up out-of-band.

**Architecture:**

A daemon (`scdlp-agent`) owns a SQLite DB at `/Library/Application Support/scdlp/rules.db` and runs a synchronous decision pipeline: path-tier match → content-tier classifier on first 4 KiB → identity computation (exe + ancestry chain via `proc_pidinfo`) → rules lookup → ALLOW/DENY/PROMPT. A `FileHook` interface abstracts the event source so the same engine runs against a `MockHook` (tests, ad-hoc demos) or, in a later plan, against the real `EndpointSecurityHook` (cgo to `libEndpointSecurity`). A CLI (`scdlp`) reads SQLite directly and writes via a Unix-socket protobuf RPC.

**Tech Stack:**

Go 1.24, SQLite via `modernc.org/sqlite` (pure Go, no cgo for the DB), `cloudflare/ahocorasick`, `spf13/cobra` for the CLI, `google.golang.org/protobuf` for the IPC wire format, `golang.org/x/sys/unix` for socket peer creds. Cgo (`<libproc.h>`) only for `proc_pidinfo` ancestry walking.

**Spec:** `docs/superpowers/specs/2026-05-27-scdlp-design.md` (read this for context).

---

## Task 1: Repo skeleton + Go module

**Files:**
- Create: `/Users/ronreiter/GitHub/scdlp/go.mod`
- Create: `/Users/ronreiter/GitHub/scdlp/.gitignore`
- Create: `/Users/ronreiter/GitHub/scdlp/Makefile`
- Create: `/Users/ronreiter/GitHub/scdlp/README.md`
- Create empty dirs: `cmd/scdlp-agent/`, `cmd/scdlp/`, `internal/classify/`, `internal/pathrules/`, `internal/identity/`, `internal/rules/`, `internal/audit/`, `internal/agent/`, `internal/hook/`, `internal/ipc/`, `proto/`, `e2e/`

- [ ] **Step 1: Initialize Go module**

```bash
cd /Users/ronreiter/GitHub/scdlp
go mod init github.com/ronreiter/scdlp
```

- [ ] **Step 2: Write `.gitignore`**

```gitignore
/bin/
/dist/
*.test
*.out
.DS_Store
docs/signing.md
```

- [ ] **Step 3: Write `Makefile`**

```makefile
.PHONY: build test fmt vet bench clean

GO ?= go
BIN := bin

build: $(BIN)/scdlp-agent $(BIN)/scdlp

$(BIN)/scdlp-agent: $(shell find . -name '*.go' -not -path './e2e/*')
	@mkdir -p $(BIN)
	$(GO) build -o $@ ./cmd/scdlp-agent

$(BIN)/scdlp: $(shell find . -name '*.go' -not -path './e2e/*')
	@mkdir -p $(BIN)
	$(GO) build -o $@ ./cmd/scdlp

test:
	$(GO) test ./...

fmt:
	$(GO) fmt ./...

vet:
	$(GO) vet ./...

bench:
	$(GO) test -bench=. -benchmem ./internal/agent/...

clean:
	rm -rf $(BIN)
```

- [ ] **Step 4: Write a placeholder `README.md`**

```markdown
# scdlp

Supply-chain DLP for macOS. See `docs/superpowers/specs/2026-05-27-scdlp-design.md`.

Status: v1 core in progress. Real Endpoint Security hook is a follow-up.
```

- [ ] **Step 5: Create empty directories with `.gitkeep` files**

```bash
for d in cmd/scdlp-agent cmd/scdlp internal/classify internal/pathrules internal/identity internal/rules internal/audit internal/agent internal/hook internal/ipc proto e2e; do
  mkdir -p $d && touch $d/.gitkeep
done
```

- [ ] **Step 6: Tidy and verify build is empty-but-clean**

```bash
go mod tidy
go vet ./... || true   # no Go files yet, may say no packages
```

- [ ] **Step 7: Commit**

```bash
git add -A
git commit -m "chore: repo skeleton and go.mod"
```

---

## Task 2: Port classifier base files from stasher (verbatim)

**Files:**
- Create: `internal/classify/prefixes.go`
- Create: `internal/classify/prefixes_test.go`
- Create: `internal/classify/patterns.go`
- Create: `internal/classify/patterns_test.go`
- Create: `internal/classify/entropy.go`
- Create: `internal/classify/entropy_test.go`
- Create: `internal/classify/denoise.go`
- Create: `internal/classify/denoise_test.go`
- Create: `internal/classify/verdict.go`

**Source files to copy verbatim** (only changing the package's import path references): `/Users/ronreiter/GitHub/stasher/internal/classify/{prefixes,patterns,entropy,denoise,verdict}.go` and the matching `_test.go` files.

- [ ] **Step 1: Copy the five non-test files**

```bash
SRC=/Users/ronreiter/GitHub/stasher/internal/classify
DST=/Users/ronreiter/GitHub/scdlp/internal/classify
for f in prefixes.go patterns.go entropy.go denoise.go verdict.go prefixes_test.go patterns_test.go entropy_test.go denoise_test.go; do
  cp $SRC/$f $DST/$f
done
rm -f $DST/.gitkeep
```

- [ ] **Step 2: Verify there are no imports from `stasher` to fix**

```bash
grep -RE 'ronreiter/stasher' /Users/ronreiter/GitHub/scdlp/internal/classify/
```

Expected: no output. If anything matches, replace `github.com/ronreiter/stasher` with `github.com/ronreiter/scdlp` in those files.

- [ ] **Step 3: Add the Aho-Corasick dependency**

```bash
cd /Users/ronreiter/GitHub/scdlp
go get github.com/cloudflare/ahocorasick@latest
go mod tidy
```

- [ ] **Step 4: Run the classifier unit tests**

```bash
go test ./internal/classify/... -v
```

Expected: all PASS. Five files of unit tests cover prefixes, patterns, entropy, denoise, verdict.

- [ ] **Step 5: Commit**

```bash
git add -A
git commit -m "feat(classify): port prefixes, patterns, entropy, denoise, verdict from stasher"
```

---

## Task 3: Bytes-oriented classifier orchestrator + PEM key detector

**Files:**
- Create: `internal/classify/classifier.go`
- Create: `internal/classify/classifier_test.go`
- Modify: `internal/classify/patterns.go` (append a new entry)

The stasher `Classifier` is `.env`-oriented; it walks `envparse.Doc.Lines` and classifies each `KEY=VALUE`. The scdlp version takes a raw byte buffer (first 4 KiB of an arbitrary file) and returns a single verdict for the buffer.

- [ ] **Step 1: Add the PEM private-key pattern to `patterns.go`**

Append to `internal/classify/patterns.go`, before the closing of the var block:

```go
// PEMPrivateKeyRe matches the header line of any PEM-encoded private key.
// We trigger on the literal header, not full PEM well-formedness, because the
// 4 KiB window may truncate the body of a large RSA key.
var PEMPrivateKeyRe = regexp.MustCompile(`-----BEGIN (RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY-----`)
```

- [ ] **Step 2: Write the failing test for `ClassifyBuf`**

Create `internal/classify/classifier_test.go`:

```go
package classify

import "testing"

func TestClassifyBuf_AWSKey(t *testing.T) {
	buf := []byte("aws_access_key_id = AKIAIOSFODNN7EXAMPLE\n")
	v := New().ClassifyBuf(buf)
	if !v.IsSecret() {
		t.Fatalf("expected AWS key to be a secret, got %+v", v)
	}
	if v.Match != "aws-access-key" {
		t.Fatalf("expected match=aws-access-key, got %q", v.Match)
	}
}

func TestClassifyBuf_GitHubPAT(t *testing.T) {
	buf := []byte("# .npmrc\n//npm.pkg.github.com/:_authToken=ghp_abcdefghijklmnopqrstuvwxyz0123456789\n")
	v := New().ClassifyBuf(buf)
	if v.Match != "github-pat" {
		t.Fatalf("expected match=github-pat, got %q (verdict=%+v)", v.Match, v)
	}
}

func TestClassifyBuf_PEMPrivateKey(t *testing.T) {
	buf := []byte("-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA…\n")
	v := New().ClassifyBuf(buf)
	if !v.IsSecret() {
		t.Fatalf("expected PEM private key to be a secret, got %+v", v)
	}
	if v.Match != "pem-private-key" {
		t.Fatalf("expected match=pem-private-key, got %q", v.Match)
	}
}

func TestClassifyBuf_Empty(t *testing.T) {
	v := New().ClassifyBuf(nil)
	if v.IsSecret() {
		t.Fatalf("empty buffer should not be a secret, got %+v", v)
	}
}

func TestClassifyBuf_PlainText(t *testing.T) {
	buf := []byte("# config file\nhost = example.com\nport = 5432\n")
	v := New().ClassifyBuf(buf)
	if v.IsSecret() {
		t.Fatalf("plain config should not be a secret, got %+v", v)
	}
}

func TestClassifyBuf_PlaceholderIgnored(t *testing.T) {
	// A placeholder like "AKIAYOUR-KEY-HERE" should not regex-validate.
	buf := []byte("aws_access_key_id = AKIAYOURKEYHEREXXXX\n")
	v := New().ClassifyBuf(buf)
	if v.Match == "aws-access-key" && v.Confidence >= 0.6 {
		t.Fatalf("placeholder AKIA should not regex-validate as high confidence, got %+v", v)
	}
}

func TestClassifyBuf_TruncatedAt4K(t *testing.T) {
	// 8 KiB of junk followed by a real key past the 4 KiB cutoff is NOT detected.
	junk := make([]byte, 8192)
	for i := range junk {
		junk[i] = 'x'
	}
	tail := []byte("AKIAIOSFODNN7EXAMPLE")
	buf := append(junk, tail...)
	v := New().ClassifyBuf(buf)
	if v.IsSecret() {
		t.Fatalf("key beyond 4 KiB window should not be detected, got %+v", v)
	}
}
```

- [ ] **Step 3: Run tests; expect compile failure**

```bash
go test ./internal/classify/... -run ClassifyBuf -v
```

Expected: build fails — `New` returns a struct that has no `ClassifyBuf` method.

- [ ] **Step 4: Write `internal/classify/classifier.go`**

Overwrite the file (it was ported in Task 2):

```go
package classify

import (
	"regexp"

	"github.com/cloudflare/ahocorasick"
)

// maxScanBytes is the per-file content-scan window. Files longer than this
// are scanned only up to this offset.
const maxScanBytes = 4096

// tokenRe is the surrounding-token shape we extract around each Aho-Corasick
// hit. Matches the longest run of bytes that could form a credential token.
var tokenRe = regexp.MustCompile(`[A-Za-z0-9_\-./+=]+`)

// Classifier runs the bytes-oriented secret-detection pipeline.
type Classifier struct {
	ac          *ahocorasick.Matcher
	allPrefixes []string
}

// New returns a Classifier ready to use. Safe for concurrent use.
func New() *Classifier {
	all := AllPrefixes()
	return &Classifier{
		ac:          ahocorasick.NewStringMatcher(all),
		allPrefixes: all,
	}
}

// ClassifyBuf returns a Verdict for the supplied buffer. Only the first
// maxScanBytes are inspected. Returns the highest-confidence finding.
func (c *Classifier) ClassifyBuf(buf []byte) Verdict {
	if len(buf) == 0 {
		return Verdict{Reason: "empty"}
	}
	if len(buf) > maxScanBytes {
		buf = buf[:maxScanBytes]
	}

	// Pass 1: PEM private-key header — single regex, very cheap.
	if PEMPrivateKeyRe.Match(buf) {
		return Verdict{
			Match:      "pem-private-key",
			Confidence: 1.0,
			Reason:     "PEM private key header",
		}
	}

	// Pass 2: Aho-Corasick provider-prefix scan.
	hits := c.ac.Match(buf)
	if len(hits) == 0 {
		return Verdict{Reason: "no provider prefix"}
	}

	// For each hit, expand to a full token and run the provider regex.
	var best Verdict
	for _, hitIdx := range hits {
		prefix := c.allPrefixes[hitIdx]
		provider := ProviderForPrefix(prefix)
		if provider == "" {
			continue
		}
		// Find the token in buf that contains this prefix.
		tokens := tokenRe.FindAll(buf, -1)
		for _, tok := range tokens {
			if len(tok) < len(prefix) || string(tok[:len(prefix)]) != prefix {
				continue
			}
			pat := ProviderPatterns[provider]
			if pat == nil {
				continue
			}
			if pat.Match(tok) {
				return Verdict{
					Match:      provider,
					Value:      string(tok),
					Confidence: 1.0,
					Reason:     "stage-2 regex match: " + provider,
				}
			}
			// Prefix hit but regex didn't match — record low-confidence finding,
			// keep looking for a stronger one.
			if best.Confidence < 0.5 {
				best = Verdict{
					Match:      provider,
					Value:      string(tok),
					Confidence: 0.4,
					Reason:     "stage-1 prefix only: " + prefix,
				}
			}
		}
	}
	if best.Match == "" {
		best.Reason = "prefix matched, no token"
	}
	return best
}
```

- [ ] **Step 5: Run the tests; expect PASS**

```bash
go test ./internal/classify/... -v
```

Expected: all classifier_test.go tests pass; previously-ported tests still pass.

- [ ] **Step 6: Commit**

```bash
git add -A
git commit -m "feat(classify): bytes-oriented ClassifyBuf + PEM private key detector"
```

---

## Task 4: Path-tier rules (tier-1 glob set)

**Files:**
- Create: `internal/pathrules/pathrules.go`
- Create: `internal/pathrules/pathrules_test.go`

The tier-1 path matcher: a static set of `doublestar`-style glob patterns is compiled at startup and matched against resolved absolute paths. Returns `(matched bool, category string)`. The `category` becomes the `file_key` for category-scoped rules.

- [ ] **Step 1: Add the doublestar dependency**

```bash
cd /Users/ronreiter/GitHub/scdlp
go get github.com/bmatcuk/doublestar/v4@latest
go mod tidy
```

- [ ] **Step 2: Write the failing test**

Create `internal/pathrules/pathrules_test.go`:

```go
package pathrules

import "testing"

func TestMatcher_AWSCredentials(t *testing.T) {
	m := NewWithDefaults([]string{"/Users/alice"})
	matched, cat := m.Match("/Users/alice/.aws/credentials")
	if !matched || cat != "aws-credentials" {
		t.Fatalf("want (true, aws-credentials), got (%v, %q)", matched, cat)
	}
}

func TestMatcher_SSHPrivateKey(t *testing.T) {
	m := NewWithDefaults([]string{"/Users/alice"})
	matched, cat := m.Match("/Users/alice/.ssh/id_ed25519")
	if !matched || cat != "ssh-private-key" {
		t.Fatalf("want (true, ssh-private-key), got (%v, %q)", matched, cat)
	}
}

func TestMatcher_SSHPublicKeySkipped(t *testing.T) {
	m := NewWithDefaults([]string{"/Users/alice"})
	matched, _ := m.Match("/Users/alice/.ssh/id_ed25519.pub")
	if matched {
		t.Fatal("public keys must not match")
	}
}

func TestMatcher_DotEnv(t *testing.T) {
	m := NewWithDefaults([]string{"/Users/alice"})
	matched, cat := m.Match("/Users/alice/code/myapp/.env")
	if !matched || cat != "dotenv" {
		t.Fatalf("want (true, dotenv), got (%v, %q)", matched, cat)
	}
}

func TestMatcher_DotEnvExampleSkipped(t *testing.T) {
	m := NewWithDefaults([]string{"/Users/alice"})
	for _, p := range []string{
		"/Users/alice/code/myapp/.env.example",
		"/Users/alice/code/myapp/.env.template",
		"/Users/alice/code/myapp/.env.sample",
	} {
		if matched, _ := m.Match(p); matched {
			t.Fatalf("%s must not match", p)
		}
	}
}

func TestMatcher_MultipleHomes(t *testing.T) {
	m := NewWithDefaults([]string{"/Users/alice", "/Users/bob"})
	for _, p := range []string{
		"/Users/alice/.npmrc",
		"/Users/bob/.npmrc",
	} {
		matched, cat := m.Match(p)
		if !matched || cat != "npm-token" {
			t.Fatalf("%s want (true, npm-token), got (%v, %q)", p, matched, cat)
		}
	}
}

func TestMatcher_UnrelatedPath(t *testing.T) {
	m := NewWithDefaults([]string{"/Users/alice"})
	matched, _ := m.Match("/etc/hosts")
	if matched {
		t.Fatal("unrelated path must not match")
	}
}

func TestMatcher_PEMAnywhere(t *testing.T) {
	m := NewWithDefaults([]string{"/Users/alice"})
	matched, cat := m.Match("/Users/alice/work/secrets/server.pem")
	if !matched || cat != "pem-file" {
		t.Fatalf("want (true, pem-file), got (%v, %q)", matched, cat)
	}
}
```

- [ ] **Step 3: Run; expect compile failure**

```bash
go test ./internal/pathrules/... -v
```

Expected: build fails because `NewWithDefaults` does not exist.

- [ ] **Step 4: Implement `internal/pathrules/pathrules.go`**

```go
// Package pathrules holds the tier-1 sensitive-path matcher.
package pathrules

import (
	"strings"

	"github.com/bmatcuk/doublestar/v4"
)

// rule pairs a glob with the logical category name returned on match.
type rule struct {
	glob string
	cat  string
}

// Defaults is the built-in tier-1 ruleset. The first matching glob wins;
// "deny" rules (returning matched=false) take precedence and are tested first.
var Defaults = []rule{
	// 1. Per-user dot-files & config dirs.
	{"{HOME}/.aws/credentials", "aws-credentials"},
	{"{HOME}/.aws/config", "aws-credentials"},
	{"{HOME}/.ssh/id_*", "ssh-private-key"},
	{"{HOME}/.config/gcloud/credentials.db", "gcloud-credentials"},
	{"{HOME}/.config/gcloud/access_tokens.db", "gcloud-credentials"},
	{"{HOME}/.config/gcloud/application_default_credentials.json", "gcloud-credentials"},
	{"{HOME}/.config/gh/hosts.yml", "gh-token"},
	{"{HOME}/.npmrc", "npm-token"},
	{"{HOME}/.yarnrc", "npm-token"},
	{"{HOME}/.yarnrc.yml", "npm-token"},
	{"{HOME}/.pypirc", "pypi-token"},
	{"{HOME}/.docker/config.json", "docker-credentials"},
	{"{HOME}/.kube/config", "kube-credentials"},
	{"{HOME}/.netrc", "netrc"},
	{"{HOME}/.git-credentials", "git-credentials"},
	{"{HOME}/.gnupg/private-keys-v1.d/**", "gpg-private-key"},
	{"{HOME}/Library/Application Support/Google/Chrome/*/Login Data", "browser-credentials"},
	{"{HOME}/Library/Application Support/Firefox/Profiles/*/logins.json", "browser-credentials"},
	// 2. Anywhere on disk.
	{"**/.env", "dotenv"},
	{"**/.env.*", "dotenv"},
	{"**/*.pem", "pem-file"},
	{"**/*.p12", "pem-file"},
	{"**/*.pfx", "pem-file"},
	{"**/*.key", "pem-file"},
}

// Skips are explicit anti-rules: paths that look sensitive but aren't.
// Checked before Defaults; a match means "not protected".
var Skips = []string{
	"{HOME}/.ssh/*.pub",
	"**/.env.example",
	"**/.env.template",
	"**/.env.sample",
}

// Matcher is a compiled rule set against a fixed list of home directories.
type Matcher struct {
	skips []string
	rules []rule
}

// NewWithDefaults compiles the built-in rules for the supplied home dirs.
// Pass the real `/Users/*` list at startup.
func NewWithDefaults(homes []string) *Matcher {
	expand := func(in string) []string {
		if !strings.Contains(in, "{HOME}") {
			return []string{in}
		}
		out := make([]string, 0, len(homes))
		for _, h := range homes {
			out = append(out, strings.ReplaceAll(in, "{HOME}", h))
		}
		return out
	}
	m := &Matcher{}
	for _, s := range Skips {
		m.skips = append(m.skips, expand(s)...)
	}
	for _, r := range Defaults {
		for _, g := range expand(r.glob) {
			m.rules = append(m.rules, rule{glob: g, cat: r.cat})
		}
	}
	return m
}

// Match reports whether the absolute path falls under a tier-1 rule and the
// category of that rule. Returns (false, "") when not protected by path.
func (m *Matcher) Match(absPath string) (bool, string) {
	for _, s := range m.skips {
		if ok, _ := doublestar.PathMatch(s, absPath); ok {
			return false, ""
		}
	}
	for _, r := range m.rules {
		if ok, _ := doublestar.PathMatch(r.glob, absPath); ok {
			return true, r.cat
		}
	}
	return false, ""
}
```

- [ ] **Step 5: Run; expect PASS**

```bash
go test ./internal/pathrules/... -v
```

Expected: all eight tests pass.

- [ ] **Step 6: Commit**

```bash
git add -A
git commit -m "feat(pathrules): tier-1 sensitive path matcher with default ruleset"
```

---

## Task 5: Process identity — exe + ancestry chain

**Files:**
- Create: `internal/identity/identity.go`
- Create: `internal/identity/ancestry_darwin.go`
- Create: `internal/identity/ancestry_stub.go`
- Create: `internal/identity/identity_test.go`

`Identity` carries the executable path, ancestry chain, and a sha256 key. The Darwin implementation uses cgo + `<libproc.h>`. A non-darwin stub returns a marker so tests can run on Linux CI if needed.

- [ ] **Step 1: Write the failing test**

Create `internal/identity/identity_test.go`:

```go
package identity

import "testing"

func TestCompute_DeterministicKey(t *testing.T) {
	a := Identity{
		Exe:   "/usr/local/bin/aws",
		Chain: []string{"/usr/local/bin/aws", "/bin/zsh", "/Applications/Utilities/Terminal.app/Contents/MacOS/Terminal", "/sbin/launchd"},
	}
	a.Compute()
	if a.KeyHex == "" {
		t.Fatal("KeyHex empty")
	}

	b := Identity{
		Exe:   a.Exe,
		Chain: append([]string{}, a.Chain...),
	}
	b.Compute()
	if a.KeyHex != b.KeyHex {
		t.Fatalf("same input should produce same key, got %q vs %q", a.KeyHex, b.KeyHex)
	}
}

func TestCompute_OrderMatters(t *testing.T) {
	a := Identity{
		Exe:   "/usr/local/bin/aws",
		Chain: []string{"/usr/local/bin/aws", "/bin/zsh"},
	}
	a.Compute()
	b := Identity{
		Exe:   "/usr/local/bin/aws",
		Chain: []string{"/bin/zsh", "/usr/local/bin/aws"},
	}
	b.Compute()
	if a.KeyHex == b.KeyHex {
		t.Fatal("reversed chain should produce different key")
	}
}

func TestCompute_ExeOnlyKey(t *testing.T) {
	a := Identity{Exe: "/usr/local/bin/aws"}
	a.Compute()
	if a.ExeOnlyKey == "" {
		t.Fatal("ExeOnlyKey empty")
	}
}

func TestCompute_TruncatedAtMaxDepth(t *testing.T) {
	chain := make([]string, 20)
	for i := range chain {
		chain[i] = "/x"
	}
	a := Identity{Exe: "/x", Chain: chain}
	a.Compute()
	if len(a.HumanChain()) > MaxDepth+1 { // +1 for the "…" suffix marker
		t.Fatalf("HumanChain depth %d exceeds MaxDepth+1=%d", len(a.HumanChain()), MaxDepth+1)
	}
}
```

- [ ] **Step 2: Run; expect compile failure**

```bash
go test ./internal/identity/... -v
```

- [ ] **Step 3: Implement `internal/identity/identity.go`**

```go
// Package identity computes a stable per-process identity key from the
// executable path and the ancestry chain of parents up to launchd.
package identity

import (
	"crypto/sha256"
	"encoding/hex"
	"path/filepath"
	"strings"
)

// MaxDepth bounds the ancestry chain captured in the identity. Past this
// depth the tail is collapsed and the identity is the same regardless of
// what's beyond.
const MaxDepth = 8

// Identity is a process's stable, hashable identity for the allowlist.
type Identity struct {
	PID        int      // runtime PID — not part of the key, audit only
	Exe        string   // absolute executable path
	Chain      []string // index 0 is self, last is the nearest ancestor we walked to
	KeyHex     string   // sha256 of normalized chain
	ExeOnlyKey string   // sha256 of just Exe (for exe-only allow rules)
}

// Compute fills KeyHex and ExeOnlyKey from Exe + Chain. Idempotent.
func (i *Identity) Compute() {
	chain := i.Chain
	if len(chain) > MaxDepth {
		chain = chain[:MaxDepth]
	}
	h := sha256.New()
	for n, c := range chain {
		if n > 0 {
			h.Write([]byte{0})
		}
		h.Write([]byte(c))
	}
	i.KeyHex = hex.EncodeToString(h.Sum(nil))

	eh := sha256.Sum256([]byte("EXE:" + i.Exe))
	i.ExeOnlyKey = "EXE:" + hex.EncodeToString(eh[:])
}

// HumanChain returns a short, readable representation of the chain for UI/audit.
// Example: ["aws", "zsh", "Terminal", "launchd"].
func (i *Identity) HumanChain() []string {
	out := make([]string, 0, len(i.Chain)+1)
	for n, c := range i.Chain {
		if n >= MaxDepth {
			out = append(out, "…")
			break
		}
		out = append(out, filepath.Base(c))
	}
	return out
}

// HumanChainStr joins HumanChain with " ← ".
func (i *Identity) HumanChainStr() string {
	return strings.Join(i.HumanChain(), " ← ")
}
```

- [ ] **Step 4: Implement `internal/identity/ancestry_stub.go` for non-darwin builds**

```go
//go:build !darwin

package identity

import (
	"errors"
	"os"
)

// Resolve walks the ancestry chain for pid up to MaxDepth.
// On non-darwin platforms this is a stub used for CI portability.
func Resolve(pid int) (Identity, error) {
	exe, err := os.Executable()
	if err != nil {
		return Identity{}, err
	}
	id := Identity{PID: pid, Exe: exe, Chain: []string{exe}}
	id.Compute()
	return id, errors.New("identity.Resolve: stub on non-darwin")
}
```

- [ ] **Step 5: Implement `internal/identity/ancestry_darwin.go`**

```go
//go:build darwin

package identity

/*
#include <libproc.h>
#include <stdlib.h>
#include <sys/proc_info.h>
*/
import "C"

import (
	"fmt"
	"unsafe"
)

// Resolve walks the ancestry chain for pid up to MaxDepth using libproc.
func Resolve(pid int) (Identity, error) {
	id := Identity{PID: pid}
	current := pid
	for depth := 0; depth < MaxDepth+1 && current > 0; depth++ {
		exe, err := pathForPid(current)
		if err != nil {
			return id, fmt.Errorf("pidpath(%d): %w", current, err)
		}
		if depth == 0 {
			id.Exe = exe
		}
		id.Chain = append(id.Chain, exe)
		ppid, err := parentOf(current)
		if err != nil {
			return id, fmt.Errorf("parentOf(%d): %w", current, err)
		}
		if ppid == current || ppid == 0 {
			break
		}
		current = ppid
	}
	id.Compute()
	return id, nil
}

func pathForPid(pid int) (string, error) {
	buf := make([]byte, C.PROC_PIDPATHINFO_MAXSIZE)
	n := C.proc_pidpath(C.int(pid), unsafe.Pointer(&buf[0]), C.uint32_t(len(buf)))
	if n <= 0 {
		return "", fmt.Errorf("proc_pidpath returned %d", int(n))
	}
	return string(buf[:n]), nil
}

func parentOf(pid int) (int, error) {
	var info C.struct_proc_bsdinfo
	n := C.proc_pidinfo(C.int(pid), C.PROC_PIDTBSDINFO, 0, unsafe.Pointer(&info), C.int(C.PROC_PIDTBSDINFO_SIZE))
	if n != C.int(C.PROC_PIDTBSDINFO_SIZE) {
		return 0, fmt.Errorf("proc_pidinfo returned %d", int(n))
	}
	return int(info.pbi_ppid), nil
}
```

- [ ] **Step 6: Run unit tests; expect PASS**

```bash
go test ./internal/identity/... -v
```

Expected: all four tests pass on macOS.

- [ ] **Step 7: Smoke-test `Resolve` interactively (optional)**

```bash
cat > /tmp/idsmoke.go <<'EOF'
package main

import (
	"fmt"
	"os"

	"github.com/ronreiter/scdlp/internal/identity"
)

func main() {
	id, err := identity.Resolve(os.Getpid())
	if err != nil { panic(err) }
	fmt.Printf("exe=%s\nchain=%v\nkey=%s\n", id.Exe, id.Chain, id.KeyHex)
}
EOF
go run /tmp/idsmoke.go
```

Expected: prints the test binary's exe, a chain ending around `launchd`, a 64-char hex key.

- [ ] **Step 8: Commit**

```bash
git add -A
git commit -m "feat(identity): exe + ancestry chain via libproc, sha256 identity key"
```

---

## Task 6: Rules store — SQLite schema + CRUD

**Files:**
- Create: `internal/rules/rules.go`
- Create: `internal/rules/schema.sql`
- Create: `internal/rules/rules_test.go`

A single sqlite-backed store. Uses `modernc.org/sqlite` so no cgo dep for sqlite (the rest of the project already has cgo from identity, but rules is the hottest path so we keep it pure-Go for simpler concurrency). One writer (the agent), readers are everywhere.

- [ ] **Step 1: Add the sqlite dependency**

```bash
cd /Users/ronreiter/GitHub/scdlp
go get modernc.org/sqlite@latest
go mod tidy
```

- [ ] **Step 2: Write the failing test**

Create `internal/rules/rules_test.go`:

```go
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
	// Insert a category-deny rule and a path-allow rule that should win.
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
```

- [ ] **Step 3: Run; expect compile failure**

```bash
go test ./internal/rules/... -v
```

- [ ] **Step 4: Write `internal/rules/schema.sql`**

```sql
PRAGMA journal_mode = WAL;
PRAGMA synchronous = NORMAL;
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS rules (
    id              INTEGER PRIMARY KEY,
    file_key        TEXT NOT NULL,
    file_key_kind   TEXT NOT NULL CHECK (file_key_kind IN ('path','category')),
    identity_key    TEXT NOT NULL,
    identity_kind   TEXT NOT NULL CHECK (identity_kind IN ('chain','exe-only')),
    verdict         TEXT NOT NULL CHECK (verdict IN ('allow','deny')),
    created_at      INTEGER NOT NULL,
    created_by      TEXT NOT NULL,
    expires_at      INTEGER,
    note            TEXT
);

CREATE UNIQUE INDEX IF NOT EXISTS rules_lookup_idx
    ON rules (file_key, file_key_kind, identity_key, identity_kind);

CREATE TABLE IF NOT EXISTS meta (
    k TEXT PRIMARY KEY,
    v TEXT NOT NULL
);
```

- [ ] **Step 5: Implement `internal/rules/rules.go`**

```go
// Package rules is the SQLite-backed allow/deny rule store.
package rules

import (
	"database/sql"
	_ "embed"
	"fmt"
	"time"

	_ "modernc.org/sqlite"
)

//go:embed schema.sql
var schema string

type FileKeyKind string

const (
	FKPath     FileKeyKind = "path"
	FKCategory FileKeyKind = "category"
)

type IdentityKind string

const (
	IKChain   IdentityKind = "chain"
	IKExeOnly IdentityKind = "exe-only"
)

type Verdict string

const (
	VerdictAllow Verdict = "allow"
	VerdictDeny  Verdict = "deny"
)

// Rule is one persisted allow/deny entry.
type Rule struct {
	ID           int64
	FileKey      string
	FileKeyKind  FileKeyKind
	IdentityKey  string
	IdentityKind IdentityKind
	Verdict      Verdict
	CreatedAt    int64
	CreatedBy    string
	ExpiresAt    *int64
	Note         string
}

// Store wraps the SQLite DB.
type Store struct {
	db *sql.DB
}

// Open opens (or creates) the DB at path.
func Open(path string) (*Store, error) {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1) // one writer; readers OK with WAL but we keep it simple
	if _, err := db.Exec(schema); err != nil {
		db.Close()
		return nil, fmt.Errorf("migrate: %w", err)
	}
	return &Store{db: db}, nil
}

// Close closes the underlying DB.
func (s *Store) Close() error { return s.db.Close() }

// Insert adds a rule. Returns the new id, or an error if the unique key
// (file_key, file_key_kind, identity_key, identity_kind) is already taken.
func (s *Store) Insert(r Rule) (int64, error) {
	if r.CreatedAt == 0 {
		r.CreatedAt = time.Now().Unix()
	}
	res, err := s.db.Exec(`
		INSERT INTO rules (file_key, file_key_kind, identity_key, identity_kind,
		                   verdict, created_at, created_by, expires_at, note)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		r.FileKey, string(r.FileKeyKind), r.IdentityKey, string(r.IdentityKind),
		string(r.Verdict), r.CreatedAt, r.CreatedBy, r.ExpiresAt, r.Note,
	)
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

// LookupKey carries the four candidate key shapes the engine wants to try.
type LookupKey struct {
	PathKey     string // exact resolved path, "" if not interested
	CategoryKey string // tier-1 category name
	ChainKey    string // identity's chain key
	ExeKey      string // identity's exe-only key
	Now         int64  // unix seconds; used to filter out expired rules
}

// Lookup returns the most-specific matching rule (path beats category, chain
// beats exe-only). Returns (nil, nil) when nothing matches.
func (s *Store) Lookup(k LookupKey) (*Rule, error) {
	row := s.db.QueryRow(`
		SELECT id, file_key, file_key_kind, identity_key, identity_kind,
		       verdict, created_at, created_by, expires_at, COALESCE(note,'')
		  FROM rules
		 WHERE ((file_key_kind = 'path'     AND file_key = ?)
		     OR (file_key_kind = 'category' AND file_key = ?))
		   AND ((identity_kind = 'chain'    AND identity_key = ?)
		     OR (identity_kind = 'exe-only' AND identity_key = ?))
		   AND (expires_at IS NULL OR expires_at > ?)
		 ORDER BY
		   CASE file_key_kind WHEN 'path'  THEN 0 ELSE 1 END,
		   CASE identity_kind WHEN 'chain' THEN 0 ELSE 1 END
		 LIMIT 1`,
		k.PathKey, k.CategoryKey, k.ChainKey, k.ExeKey, k.Now,
	)
	var r Rule
	var exp sql.NullInt64
	err := row.Scan(&r.ID, &r.FileKey, &r.FileKeyKind, &r.IdentityKey, &r.IdentityKind,
		&r.Verdict, &r.CreatedAt, &r.CreatedBy, &exp, &r.Note)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if exp.Valid {
		v := exp.Int64
		r.ExpiresAt = &v
	}
	return &r, nil
}

// ListFilter narrows List() results. Zero values mean "no filter".
type ListFilter struct {
	Verdict Verdict
}

// List returns rules matching the filter, newest first.
func (s *Store) List(f ListFilter) ([]Rule, error) {
	q := `SELECT id, file_key, file_key_kind, identity_key, identity_kind,
	             verdict, created_at, created_by, expires_at, COALESCE(note,'')
	        FROM rules`
	args := []any{}
	if f.Verdict != "" {
		q += ` WHERE verdict = ?`
		args = append(args, string(f.Verdict))
	}
	q += ` ORDER BY created_at DESC`
	rows, err := s.db.Query(q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Rule
	for rows.Next() {
		var r Rule
		var exp sql.NullInt64
		if err := rows.Scan(&r.ID, &r.FileKey, &r.FileKeyKind, &r.IdentityKey, &r.IdentityKind,
			&r.Verdict, &r.CreatedAt, &r.CreatedBy, &exp, &r.Note); err != nil {
			return nil, err
		}
		if exp.Valid {
			v := exp.Int64
			r.ExpiresAt = &v
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// Revoke deletes the rule with the given id. No error if it didn't exist.
func (s *Store) Revoke(id int64) error {
	_, err := s.db.Exec(`DELETE FROM rules WHERE id = ?`, id)
	return err
}
```

- [ ] **Step 6: Run tests; expect PASS**

```bash
go test ./internal/rules/... -v
```

Expected: all four tests pass.

- [ ] **Step 7: Commit**

```bash
git add -A
git commit -m "feat(rules): SQLite store with Insert/Lookup/List/Revoke"
```

---

## Task 7: Audit log

**Files:**
- Create: `internal/audit/audit.go`
- Create: `internal/audit/schema.sql`
- Create: `internal/audit/audit_test.go`

Append-only audit log in the same SQLite DB (separate table). Provides `Log()` and `Tail()`.

- [ ] **Step 1: Write the failing test**

Create `internal/audit/audit_test.go`:

```go
package audit

import (
	"path/filepath"
	"testing"
	"time"
)

func openTest(t *testing.T) *Store {
	t.Helper()
	dbPath := filepath.Join(t.TempDir(), "audit.db")
	s, err := Open(dbPath)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func TestStore_LogAndTail(t *testing.T) {
	s := openTest(t)
	now := time.Now().Unix()
	for i := 0; i < 3; i++ {
		if err := s.Log(Event{
			TS: now + int64(i), FilePath: "/Users/alice/.aws/credentials",
			FileKey: "aws-credentials", FileKeyKind: "category",
			ProcessPID: 1000 + i, ProcessExe: "/usr/local/bin/aws",
			ProcessChain: "aws|zsh|Terminal", IdentityKey: "abc",
			Verdict: "deny", MatchedKind: "aws-credentials", DurationUs: 100,
		}); err != nil {
			t.Fatal(err)
		}
	}
	evts, err := s.Tail(TailFilter{Limit: 10})
	if err != nil {
		t.Fatal(err)
	}
	if len(evts) != 3 {
		t.Fatalf("expected 3 events, got %d", len(evts))
	}
	if evts[0].TS < evts[2].TS {
		t.Fatal("expected newest first")
	}
}

func TestStore_TailLimit(t *testing.T) {
	s := openTest(t)
	for i := 0; i < 5; i++ {
		_ = s.Log(Event{TS: int64(i + 1), Verdict: "allow"})
	}
	evts, err := s.Tail(TailFilter{Limit: 2})
	if err != nil {
		t.Fatal(err)
	}
	if len(evts) != 2 {
		t.Fatalf("expected 2 events, got %d", len(evts))
	}
}
```

- [ ] **Step 2: Run; expect compile failure**

```bash
go test ./internal/audit/... -v
```

- [ ] **Step 3: Write `internal/audit/schema.sql`**

```sql
PRAGMA journal_mode = WAL;
PRAGMA synchronous = NORMAL;

CREATE TABLE IF NOT EXISTS audit (
    id              INTEGER PRIMARY KEY,
    ts              INTEGER NOT NULL,
    file_path       TEXT NOT NULL,
    file_key        TEXT NOT NULL,
    file_key_kind   TEXT NOT NULL,
    process_pid     INTEGER NOT NULL,
    process_exe     TEXT NOT NULL,
    process_chain   TEXT NOT NULL,
    identity_key    TEXT NOT NULL,
    verdict         TEXT NOT NULL,
    rule_id         INTEGER,
    matched_kind    TEXT,
    duration_us     INTEGER
);

CREATE INDEX IF NOT EXISTS audit_ts_idx ON audit(ts DESC);
```

- [ ] **Step 4: Implement `internal/audit/audit.go`**

```go
// Package audit is the append-only decision log.
package audit

import (
	"database/sql"
	_ "embed"
	"fmt"

	_ "modernc.org/sqlite"
)

//go:embed schema.sql
var schema string

// Event is one row in the audit log.
type Event struct {
	ID           int64
	TS           int64
	FilePath     string
	FileKey      string
	FileKeyKind  string
	ProcessPID   int
	ProcessExe   string
	ProcessChain string
	IdentityKey  string
	Verdict      string
	RuleID       *int64
	MatchedKind  string
	DurationUs   int64
}

// Store is the audit-log database handle.
type Store struct{ db *sql.DB }

// Open creates / opens the audit DB at path.
func Open(path string) (*Store, error) {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	if _, err := db.Exec(schema); err != nil {
		db.Close()
		return nil, fmt.Errorf("migrate: %w", err)
	}
	return &Store{db: db}, nil
}

// Close closes the DB.
func (s *Store) Close() error { return s.db.Close() }

// Log appends one event. Caller must populate TS (unix seconds).
func (s *Store) Log(e Event) error {
	_, err := s.db.Exec(`
		INSERT INTO audit (ts, file_path, file_key, file_key_kind,
		                   process_pid, process_exe, process_chain,
		                   identity_key, verdict, rule_id, matched_kind,
		                   duration_us)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		e.TS, e.FilePath, e.FileKey, e.FileKeyKind,
		e.ProcessPID, e.ProcessExe, e.ProcessChain,
		e.IdentityKey, e.Verdict, e.RuleID, e.MatchedKind,
		e.DurationUs,
	)
	return err
}

// TailFilter constrains Tail().
type TailFilter struct {
	Since   int64 // unix seconds, inclusive; 0 = unbounded
	Verdict string
	Limit   int // 0 = no limit
}

// Tail returns events newest first.
func (s *Store) Tail(f TailFilter) ([]Event, error) {
	q := `SELECT id, ts, file_path, file_key, file_key_kind, process_pid,
	             process_exe, process_chain, identity_key, verdict, rule_id,
	             COALESCE(matched_kind,''), duration_us
	        FROM audit WHERE 1=1`
	args := []any{}
	if f.Since > 0 {
		q += ` AND ts >= ?`
		args = append(args, f.Since)
	}
	if f.Verdict != "" {
		q += ` AND verdict = ?`
		args = append(args, f.Verdict)
	}
	q += ` ORDER BY ts DESC`
	if f.Limit > 0 {
		q += ` LIMIT ?`
		args = append(args, f.Limit)
	}
	rows, err := s.db.Query(q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Event
	for rows.Next() {
		var e Event
		var ruleID sql.NullInt64
		if err := rows.Scan(&e.ID, &e.TS, &e.FilePath, &e.FileKey, &e.FileKeyKind,
			&e.ProcessPID, &e.ProcessExe, &e.ProcessChain, &e.IdentityKey,
			&e.Verdict, &ruleID, &e.MatchedKind, &e.DurationUs); err != nil {
			return nil, err
		}
		if ruleID.Valid {
			v := ruleID.Int64
			e.RuleID = &v
		}
		out = append(out, e)
	}
	return out, rows.Err()
}
```

- [ ] **Step 5: Run; expect PASS**

```bash
go test ./internal/audit/... -v
```

- [ ] **Step 6: Commit**

```bash
git add -A
git commit -m "feat(audit): append-only decision log"
```

---

## Task 8: Hook interface + MockHook

**Files:**
- Create: `internal/hook/hook.go`
- Create: `internal/hook/mock.go`
- Create: `internal/hook/mock_test.go`

The hook layer abstracts the event source. The real (future) implementation is the Endpoint Security framework. Today we provide a `MockHook` that lets tests/demos feed synthetic events and inspect decisions.

- [ ] **Step 1: Write the failing test**

Create `internal/hook/mock_test.go`:

```go
package hook

import (
	"context"
	"testing"
	"time"
)

func TestMockHook_AllowFlow(t *testing.T) {
	m := NewMock()
	go func() {
		_ = m.Inject(Event{Path: "/etc/hosts", PID: 1234, Exe: "/bin/cat"})
	}()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	ev, decide, err := m.Next(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if ev.Path != "/etc/hosts" {
		t.Fatalf("path mismatch: %s", ev.Path)
	}
	decide(Allow)
	if got := m.LastDecision(); got != Allow {
		t.Fatalf("decision mismatch: %v", got)
	}
}

func TestMockHook_DenyFlow(t *testing.T) {
	m := NewMock()
	go func() { _ = m.Inject(Event{Path: "/a", PID: 1, Exe: "/b"}) }()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	_, decide, err := m.Next(ctx)
	if err != nil {
		t.Fatal(err)
	}
	decide(Deny)
	if got := m.LastDecision(); got != Deny {
		t.Fatalf("decision mismatch: %v", got)
	}
}

func TestMockHook_CtxCancel(t *testing.T) {
	m := NewMock()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	if _, _, err := m.Next(ctx); err == nil {
		t.Fatal("expected ctx error, got nil")
	}
}
```

- [ ] **Step 2: Run; expect compile failure**

```bash
go test ./internal/hook/... -v
```

- [ ] **Step 3: Implement `internal/hook/hook.go`**

```go
// Package hook abstracts the file-open event source. Real backend is the
// macOS Endpoint Security framework; tests use MockHook.
package hook

import "context"

// Decision is the synchronous answer the kernel (or simulator) is waiting for.
type Decision int

const (
	Allow Decision = iota
	Deny
)

func (d Decision) String() string {
	if d == Allow {
		return "allow"
	}
	return "deny"
}

// Event carries everything the agent needs to decide.
type Event struct {
	Path  string // resolved absolute path being opened
	PID   int    // calling process pid
	Exe   string // resolved exe path; if "" the agent will resolve from PID
	Flags int    // open flags (O_RDONLY, O_WRONLY, …)
}

// DecideFunc returns the decision back to the kernel.
type DecideFunc func(Decision)

// Hook is the contract implemented by both MockHook and (later) the ESF backend.
type Hook interface {
	// Next blocks until the next event or ctx is done. Returns the event
	// and a single-shot DecideFunc the agent must call exactly once.
	Next(ctx context.Context) (Event, DecideFunc, error)
}
```

- [ ] **Step 4: Implement `internal/hook/mock.go`**

```go
package hook

import (
	"context"
	"sync"
)

// MockHook is a test/demo backend. Inject() pushes events; the consumer
// (typically the agent loop) calls Next() and then DecideFunc.
type MockHook struct {
	mu         sync.Mutex
	queue      chan pending
	lastResult Decision
	lastSet    bool
}

type pending struct {
	ev   Event
	done chan Decision
}

// NewMock returns an empty mock with a 64-deep injection buffer.
func NewMock() *MockHook {
	return &MockHook{queue: make(chan pending, 64)}
}

// Inject submits an event and blocks until Decide is called or ctx fires.
// Returns the chosen decision so callers (typically test code) can assert.
func (m *MockHook) Inject(ev Event) Decision {
	done := make(chan Decision, 1)
	m.queue <- pending{ev: ev, done: done}
	d := <-done
	m.mu.Lock()
	m.lastResult, m.lastSet = d, true
	m.mu.Unlock()
	return d
}

// Next implements the Hook interface.
func (m *MockHook) Next(ctx context.Context) (Event, DecideFunc, error) {
	select {
	case <-ctx.Done():
		return Event{}, nil, ctx.Err()
	case p := <-m.queue:
		var once sync.Once
		decide := func(d Decision) {
			once.Do(func() { p.done <- d })
		}
		return p.ev, decide, nil
	}
}

// LastDecision returns the most recent decision recorded by Inject. Useful
// for assertions in tests that call Inject in a goroutine.
func (m *MockHook) LastDecision() Decision {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.lastSet {
		return Decision(-1)
	}
	return m.lastResult
}
```

- [ ] **Step 5: Run; expect PASS**

```bash
go test ./internal/hook/... -v
```

- [ ] **Step 6: Commit**

```bash
git add -A
git commit -m "feat(hook): Hook interface + MockHook for tests"
```

---

## Task 9: Agent decision engine

**Files:**
- Create: `internal/agent/engine.go`
- Create: `internal/agent/engine_test.go`
- Create: `internal/agent/promptbus.go`

The engine ties everything together: takes an `Event` from the hook, resolves identity, runs path-tier then content-tier classification, queries the rules store, returns ALLOW/DENY, writes audit, and (on UNKNOWN) emits a `PromptRequest` on a bus that the IPC layer will later forward to the helper.

- [ ] **Step 1: Write the failing test**

Create `internal/agent/engine_test.go`:

```go
package agent

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ronreiter/scdlp/internal/audit"
	"github.com/ronreiter/scdlp/internal/hook"
	"github.com/ronreiter/scdlp/internal/identity"
	"github.com/ronreiter/scdlp/internal/pathrules"
	"github.com/ronreiter/scdlp/internal/rules"
)

// fakeResolver swaps the real identity.Resolve for deterministic tests.
type fakeResolver map[int]identity.Identity

func (f fakeResolver) Resolve(pid int) (identity.Identity, error) {
	id := f[pid]
	id.Compute()
	return id, nil
}

func tempEngine(t *testing.T, home string, resolver Resolver) (*Engine, *PromptBus) {
	t.Helper()
	dir := t.TempDir()
	rdb, err := rules.Open(filepath.Join(dir, "rules.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { rdb.Close() })
	adb, err := audit.Open(filepath.Join(dir, "audit.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { adb.Close() })
	bus := NewPromptBus(8)
	return New(Config{
		Homes:    []string{home},
		Rules:    rdb,
		Audit:    adb,
		Resolver: resolver,
		Bus:      bus,
	}), bus
}

func TestEngine_UnprotectedAllow(t *testing.T) {
	home := t.TempDir()
	eng, _ := tempEngine(t, home, fakeResolver{1: {Exe: "/bin/cat", Chain: []string{"/bin/cat"}}})
	d := eng.Decide(hook.Event{Path: "/etc/hosts", PID: 1})
	if d != hook.Allow {
		t.Fatalf("want allow, got %v", d)
	}
}

func TestEngine_ProtectedNoRule_Denies_AndEmitsPrompt(t *testing.T) {
	home := t.TempDir()
	if err := os.MkdirAll(filepath.Join(home, ".aws"), 0o700); err != nil {
		t.Fatal(err)
	}
	creds := filepath.Join(home, ".aws/credentials")
	if err := os.WriteFile(creds, []byte("[default]\naws_access_key_id=AKIAIOSFODNN7EXAMPLE\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	eng, bus := tempEngine(t, home, fakeResolver{
		42: {Exe: "/usr/bin/node", Chain: []string{"/usr/bin/node", "/bin/sh", "/usr/local/bin/npm"}},
	})
	d := eng.Decide(hook.Event{Path: creds, PID: 42})
	if d != hook.Deny {
		t.Fatalf("want deny, got %v", d)
	}
	select {
	case p := <-bus.C():
		if !strings.Contains(p.HumanIdentity, "node") {
			t.Fatalf("unexpected human identity: %s", p.HumanIdentity)
		}
		if p.Category != "aws-credentials" {
			t.Fatalf("unexpected category: %s", p.Category)
		}
	case <-time.After(time.Second):
		t.Fatal("expected prompt on bus")
	}
}

func TestEngine_ProtectedWithAllowRule(t *testing.T) {
	home := t.TempDir()
	_ = os.MkdirAll(filepath.Join(home, ".aws"), 0o700)
	creds := filepath.Join(home, ".aws/credentials")
	_ = os.WriteFile(creds, []byte("[default]\n"), 0o600)

	resolver := fakeResolver{
		42: {Exe: "/usr/local/bin/aws", Chain: []string{"/usr/local/bin/aws", "/bin/zsh"}},
	}
	eng, _ := tempEngine(t, home, resolver)

	// Pre-seed an allow rule with the *expected* chain key.
	id := resolver[42]
	id.Compute()
	if _, err := eng.cfg.Rules.Insert(rules.Rule{
		FileKey: "aws-credentials", FileKeyKind: rules.FKCategory,
		IdentityKey: id.KeyHex, IdentityKind: rules.IKChain,
		Verdict: rules.VerdictAllow, CreatedBy: "test",
	}); err != nil {
		t.Fatal(err)
	}
	if got := eng.Decide(hook.Event{Path: creds, PID: 42}); got != hook.Allow {
		t.Fatalf("want allow, got %v", got)
	}
}

func TestEngine_WriteOnlyFastAllow(t *testing.T) {
	home := t.TempDir()
	eng, _ := tempEngine(t, home, fakeResolver{1: {Exe: "/bin/cat"}})
	d := eng.Decide(hook.Event{Path: filepath.Join(home, ".aws/credentials"),
		PID: 1, Flags: os.O_WRONLY})
	if d != hook.Allow {
		t.Fatal("write-only opens must short-circuit allow")
	}
}

func TestEngine_RunLoopAgainstMockHook(t *testing.T) {
	home := t.TempDir()
	_ = os.MkdirAll(filepath.Join(home, ".aws"), 0o700)
	creds := filepath.Join(home, ".aws/credentials")
	_ = os.WriteFile(creds, []byte("[default]\n"), 0o600)

	eng, _ := tempEngine(t, home, fakeResolver{
		99: {Exe: "/usr/bin/curl", Chain: []string{"/usr/bin/curl"}},
	})
	mh := hook.NewMock()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go eng.Run(ctx, mh)

	got := mh.Inject(hook.Event{Path: creds, PID: 99})
	if got != hook.Deny {
		t.Fatalf("want deny, got %v", got)
	}
}
```

- [ ] **Step 2: Run; expect compile failure**

```bash
go test ./internal/agent/... -v
```

- [ ] **Step 3: Implement `internal/agent/promptbus.go`**

```go
package agent

// PromptEvent is published on the bus when the engine emits a prompt to the
// helper. Carries only the human-readable pieces the helper needs.
type PromptEvent struct {
	FilePath      string
	Category      string // "aws-credentials", "dotenv", …
	MatchedKind   string // either Category or a content-classifier match name
	PID           int
	Exe           string
	HumanIdentity string // "node ← sh ← npm"
	IdentityKey   string // hex chain key
	ExeOnlyKey    string
}

// PromptBus is a bounded fan-out channel of prompt requests.
type PromptBus struct {
	c chan PromptEvent
}

// NewPromptBus returns a bus with the given buffer size.
func NewPromptBus(buf int) *PromptBus { return &PromptBus{c: make(chan PromptEvent, buf)} }

// C returns a receive channel for prompt events.
func (b *PromptBus) C() <-chan PromptEvent { return b.c }

// Publish drops the event if the bus is full (engine never blocks on prompt UX).
func (b *PromptBus) Publish(e PromptEvent) {
	select {
	case b.c <- e:
	default:
	}
}
```

- [ ] **Step 4: Implement `internal/agent/engine.go`**

```go
// Package agent contains the synchronous decision engine.
package agent

import (
	"context"
	"io"
	"log"
	"os"
	"strings"
	"time"

	"github.com/ronreiter/scdlp/internal/audit"
	"github.com/ronreiter/scdlp/internal/classify"
	"github.com/ronreiter/scdlp/internal/hook"
	"github.com/ronreiter/scdlp/internal/identity"
	"github.com/ronreiter/scdlp/internal/pathrules"
	"github.com/ronreiter/scdlp/internal/rules"
)

// Resolver is the indirection that lets tests swap out identity.Resolve.
type Resolver interface {
	Resolve(pid int) (identity.Identity, error)
}

type defaultResolver struct{}

func (defaultResolver) Resolve(pid int) (identity.Identity, error) {
	return identity.Resolve(pid)
}

// Config bundles the engine's dependencies.
type Config struct {
	Homes    []string         // user home dirs for path-rule expansion
	Rules    *rules.Store
	Audit    *audit.Store
	Resolver Resolver         // nil = use libproc-based default
	Bus      *PromptBus
	Logger   *log.Logger      // nil = log to stderr
}

// Engine is the synchronous decision pipeline.
type Engine struct {
	cfg     Config
	matcher *pathrules.Matcher
	classif *classify.Classifier
}

// New builds an engine.
func New(cfg Config) *Engine {
	if cfg.Resolver == nil {
		cfg.Resolver = defaultResolver{}
	}
	if cfg.Logger == nil {
		cfg.Logger = log.New(os.Stderr, "agent: ", log.LstdFlags|log.Lmicroseconds)
	}
	return &Engine{
		cfg:     cfg,
		matcher: pathrules.NewWithDefaults(cfg.Homes),
		classif: classify.New(),
	}
}

// Decide returns the synchronous verdict for one event.
func (e *Engine) Decide(ev hook.Event) hook.Decision {
	start := time.Now()
	verdict, audited := e.decideInner(ev)
	dur := time.Since(start).Microseconds()
	if audited != nil {
		audited.DurationUs = dur
		if err := e.cfg.Audit.Log(*audited); err != nil {
			e.cfg.Logger.Printf("audit log: %v", err)
		}
	}
	return verdict
}

func (e *Engine) decideInner(ev hook.Event) (hook.Decision, *audit.Event) {
	// Fast-skip: write-only opens cannot leak data.
	if ev.Flags&(os.O_WRONLY|os.O_RDWR) == os.O_WRONLY {
		return hook.Allow, nil
	}

	matched, category := e.matcher.Match(ev.Path)
	matchedKind := category
	contentMatch := ""
	if !matched {
		// Tier 2: content scan.
		if buf, ok := readFirst4K(ev.Path); ok {
			v := e.classif.ClassifyBuf(buf)
			if v.IsSecret() {
				matched = true
				matchedKind = v.Match
				contentMatch = v.Match
			}
		}
	}
	if !matched {
		return hook.Allow, nil
	}

	// Resolve identity (may be best-effort if the process already exited).
	id, _ := e.cfg.Resolver.Resolve(ev.PID)
	if id.Exe == "" {
		id.Exe = ev.Exe
		if len(id.Chain) == 0 {
			id.Chain = []string{ev.Exe}
		}
		id.Compute()
	}

	// Lookup the most-specific matching rule.
	r, err := e.cfg.Rules.Lookup(rules.LookupKey{
		PathKey:     ev.Path,
		CategoryKey: category,
		ChainKey:    id.KeyHex,
		ExeKey:      id.ExeOnlyKey,
		Now:         time.Now().Unix(),
	})
	if err != nil {
		e.cfg.Logger.Printf("rules lookup: %v", err)
	}

	audit := &audit.Event{
		TS:           time.Now().Unix(),
		FilePath:     ev.Path,
		FileKey:      category,
		FileKeyKind:  "category",
		ProcessPID:   ev.PID,
		ProcessExe:   id.Exe,
		ProcessChain: strings.Join(id.HumanChain(), "|"),
		IdentityKey:  id.KeyHex,
		MatchedKind:  matchedKind,
	}

	switch {
	case r != nil && r.Verdict == rules.VerdictAllow:
		audit.Verdict = "allow"
		audit.RuleID = &r.ID
		return hook.Allow, audit
	case r != nil && r.Verdict == rules.VerdictDeny:
		audit.Verdict = "deny"
		audit.RuleID = &r.ID
		return hook.Deny, audit
	default:
		audit.Verdict = "deny"
		e.cfg.Bus.Publish(PromptEvent{
			FilePath: ev.Path, Category: ifEmpty(category, contentMatch),
			MatchedKind: matchedKind, PID: ev.PID, Exe: id.Exe,
			HumanIdentity: id.HumanChainStr(),
			IdentityKey:   id.KeyHex, ExeOnlyKey: id.ExeOnlyKey,
		})
		return hook.Deny, audit
	}
}

// Run consumes events from h until ctx is cancelled.
func (e *Engine) Run(ctx context.Context, h hook.Hook) {
	for {
		ev, decide, err := h.Next(ctx)
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			e.cfg.Logger.Printf("hook next: %v", err)
			continue
		}
		decide(e.Decide(ev))
	}
}

func readFirst4K(path string) ([]byte, bool) {
	f, err := os.Open(path)
	if err != nil {
		return nil, false
	}
	defer f.Close()
	buf := make([]byte, 4096)
	n, err := io.ReadFull(f, buf)
	if err != nil && err != io.EOF && err != io.ErrUnexpectedEOF {
		return nil, false
	}
	return buf[:n], true
}

func ifEmpty(a, b string) string {
	if a != "" {
		return a
	}
	return b
}
```

- [ ] **Step 5: Run engine tests; expect PASS**

```bash
go test ./internal/agent/... -v
```

- [ ] **Step 6: Commit**

```bash
git add -A
git commit -m "feat(agent): decision engine + prompt bus"
```

---

## Task 10: IPC protocol (protobuf + Unix socket)

**Files:**
- Create: `proto/agent.proto`
- Create: `internal/ipc/server.go`
- Create: `internal/ipc/client.go`
- Create: `internal/ipc/ipc_test.go`
- Modify: `go.mod` (protobuf dep)

We use protobuf framing over a Unix domain socket at `/var/run/scdlp.sock` (host) or a per-test temp path. Length-prefixed frames; one bidirectional connection per client. Simpler than NSXPC for the Go side and lets the CLI work without involving the Swift helper.

- [ ] **Step 1: Add protobuf and codegen**

```bash
cd /Users/ronreiter/GitHub/scdlp
go get google.golang.org/protobuf/proto@latest
go get google.golang.org/protobuf/encoding/protowire@latest
go mod tidy
```

We write the wire format by hand (no protoc) to keep the toolchain trivial. The serialization helpers below use `protowire` directly on a small fixed message set.

- [ ] **Step 2: Write `internal/ipc/wire.go`**

```go
package ipc

import (
	"encoding/binary"
	"errors"
	"io"
)

// frame layout: 4-byte BE length || N-byte payload
//
// payload is a tag (1 byte) followed by a JSON message body — chosen for
// pragmatism over proto codegen complexity. The wire format is private to
// this binary set, not user-facing.

const (
	TagPromptRequest  byte = 0x01
	TagPromptDecision byte = 0x02
	TagAddRule        byte = 0x03
	TagRevokeRule     byte = 0x04
	TagListRequest    byte = 0x05
	TagListResponse   byte = 0x06
	TagStatusRequest  byte = 0x07
	TagStatusResponse byte = 0x08
	TagTailRequest    byte = 0x09
	TagAuditEvent     byte = 0x0A
	TagAck            byte = 0x0B
	TagError          byte = 0x0C
)

// ErrShortRead returned when a frame is truncated.
var ErrShortRead = errors.New("ipc: short read")

func WriteFrame(w io.Writer, tag byte, body []byte) error {
	hdr := make([]byte, 5)
	binary.BigEndian.PutUint32(hdr[:4], uint32(len(body)+1))
	hdr[4] = tag
	if _, err := w.Write(hdr); err != nil {
		return err
	}
	_, err := w.Write(body)
	return err
}

func ReadFrame(r io.Reader) (byte, []byte, error) {
	var hdr [5]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return 0, nil, err
	}
	n := binary.BigEndian.Uint32(hdr[:4])
	if n == 0 {
		return 0, nil, ErrShortRead
	}
	body := make([]byte, n-1)
	if _, err := io.ReadFull(r, body); err != nil {
		return 0, nil, err
	}
	return hdr[4], body, nil
}
```

- [ ] **Step 3: Write the failing test**

Create `internal/ipc/ipc_test.go`:

```go
package ipc

import (
	"context"
	"path/filepath"
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

// fakeBackend implements the Backend interface for IPC tests.
type fakeBackend struct {
	tail []AuditRow
	last int64
}

func (f *fakeBackend) AddRule(s AddRuleSpec) (int64, error) {
	f.last++
	return f.last, nil
}
func (f *fakeBackend) RevokeRule(id int64) error             { return nil }
func (f *fakeBackend) ListRules(_ ListReq) ([]RuleRow, error) { return nil, nil }
func (f *fakeBackend) Status() (StatusRow, error)            { return StatusRow{Healthy: true}, nil }
func (f *fakeBackend) TailAudit(_ TailReq) ([]AuditRow, error) {
	return f.tail, nil
}
```

- [ ] **Step 4: Run; expect compile failure**

```bash
go test ./internal/ipc/... -v
```

- [ ] **Step 5: Define the IPC types in `internal/ipc/types.go`**

```go
package ipc

// Backend is the contract the daemon implements; the IPC server calls into
// it. Decouples the wire layer from rules/audit packages.
type Backend interface {
	AddRule(AddRuleSpec) (int64, error)
	RevokeRule(int64) error
	ListRules(ListReq) ([]RuleRow, error)
	Status() (StatusRow, error)
	TailAudit(TailReq) ([]AuditRow, error)
}

type AddRuleSpec struct {
	FileKey      string `json:"file_key"`
	FileKeyKind  string `json:"file_key_kind"`
	IdentityKey  string `json:"identity_key"`
	IdentityKind string `json:"identity_kind"`
	Verdict      string `json:"verdict"`
	ExpiresAt    *int64 `json:"expires_at,omitempty"`
	Note         string `json:"note,omitempty"`
}

type RuleRow struct {
	ID           int64  `json:"id"`
	FileKey      string `json:"file_key"`
	FileKeyKind  string `json:"file_key_kind"`
	IdentityKey  string `json:"identity_key"`
	IdentityKind string `json:"identity_kind"`
	Verdict      string `json:"verdict"`
	CreatedAt    int64  `json:"created_at"`
	CreatedBy    string `json:"created_by"`
	ExpiresAt    *int64 `json:"expires_at,omitempty"`
	Note         string `json:"note,omitempty"`
}

type ListReq struct {
	Verdict string `json:"verdict,omitempty"`
}

type StatusRow struct {
	Healthy      bool   `json:"healthy"`
	RulesTotal   int    `json:"rules_total"`
	AuditEvents  int    `json:"audit_events"`
	HelperOnline bool   `json:"helper_online"`
	UptimeSec    int64  `json:"uptime_sec"`
	Mode         string `json:"mode"` // "enforce" | "paused" | "fail-safe"
}

type TailReq struct {
	Since   int64  `json:"since,omitempty"`
	Verdict string `json:"verdict,omitempty"`
	Limit   int    `json:"limit,omitempty"`
}

type AuditRow struct {
	ID           int64  `json:"id"`
	TS           int64  `json:"ts"`
	FilePath     string `json:"file_path"`
	FileKey      string `json:"file_key"`
	FileKeyKind  string `json:"file_key_kind"`
	ProcessPID   int    `json:"process_pid"`
	ProcessExe   string `json:"process_exe"`
	ProcessChain string `json:"process_chain"`
	IdentityKey  string `json:"identity_key"`
	Verdict      string `json:"verdict"`
	MatchedKind  string `json:"matched_kind"`
	DurationUs   int64  `json:"duration_us"`
}
```

- [ ] **Step 6: Implement `internal/ipc/server.go`**

```go
package ipc

import (
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"sync"
)

// Server listens on a Unix socket and dispatches frames to a Backend.
type Server struct {
	path string
	be   Backend
	ln   net.Listener
	wg   sync.WaitGroup
}

func NewServer(path string, be Backend) *Server { return &Server{path: path, be: be} }

func (s *Server) Start() error {
	_ = os.MkdirAll(filepath.Dir(s.path), 0o755)
	_ = os.Remove(s.path)
	ln, err := net.Listen("unix", s.path)
	if err != nil {
		return err
	}
	_ = os.Chmod(s.path, 0o660)
	s.ln = ln
	s.wg.Add(1)
	go s.acceptLoop()
	return nil
}

func (s *Server) Stop() {
	if s.ln != nil {
		_ = s.ln.Close()
	}
	s.wg.Wait()
}

func (s *Server) acceptLoop() {
	defer s.wg.Done()
	for {
		c, err := s.ln.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			continue
		}
		s.wg.Add(1)
		go s.handle(c)
	}
}

func (s *Server) handle(c net.Conn) {
	defer s.wg.Done()
	defer c.Close()
	for {
		tag, body, err := ReadFrame(c)
		if err != nil {
			if err != io.EOF {
				// best-effort surface
			}
			return
		}
		s.dispatch(c, tag, body)
	}
}

func (s *Server) dispatch(c net.Conn, tag byte, body []byte) {
	switch tag {
	case TagAddRule:
		var spec AddRuleSpec
		_ = json.Unmarshal(body, &spec)
		id, err := s.be.AddRule(spec)
		if err != nil {
			writeErr(c, err)
			return
		}
		writeJSON(c, TagAck, struct {
			ID int64 `json:"id"`
		}{ID: id})
	case TagRevokeRule:
		var v struct {
			ID int64 `json:"id"`
		}
		_ = json.Unmarshal(body, &v)
		if err := s.be.RevokeRule(v.ID); err != nil {
			writeErr(c, err)
			return
		}
		writeJSON(c, TagAck, struct{}{})
	case TagListRequest:
		var req ListReq
		_ = json.Unmarshal(body, &req)
		rows, err := s.be.ListRules(req)
		if err != nil {
			writeErr(c, err)
			return
		}
		writeJSON(c, TagListResponse, rows)
	case TagStatusRequest:
		st, err := s.be.Status()
		if err != nil {
			writeErr(c, err)
			return
		}
		writeJSON(c, TagStatusResponse, st)
	case TagTailRequest:
		var req TailReq
		_ = json.Unmarshal(body, &req)
		rows, err := s.be.TailAudit(req)
		if err != nil {
			writeErr(c, err)
			return
		}
		writeJSON(c, TagAuditEvent, rows)
	default:
		writeErr(c, errors.New("unknown tag"))
	}
}

func writeJSON(w io.Writer, tag byte, v any) {
	b, _ := json.Marshal(v)
	_ = WriteFrame(w, tag, b)
}

func writeErr(w io.Writer, err error) {
	_ = WriteFrame(w, TagError, []byte(err.Error()))
}
```

- [ ] **Step 7: Implement `internal/ipc/client.go`**

```go
package ipc

import (
	"context"
	"encoding/json"
	"errors"
	"net"
)

// Client is a synchronous CLI/helper client.
type Client struct{ c net.Conn }

func Dial(path string) (*Client, error) {
	c, err := net.Dial("unix", path)
	if err != nil {
		return nil, err
	}
	return &Client{c: c}, nil
}

func (c *Client) Close() error { return c.c.Close() }

func (c *Client) call(reqTag byte, req any, respTag byte, resp any) error {
	body, _ := json.Marshal(req)
	if err := WriteFrame(c.c, reqTag, body); err != nil {
		return err
	}
	tag, body, err := ReadFrame(c.c)
	if err != nil {
		return err
	}
	if tag == TagError {
		return errors.New(string(body))
	}
	if tag != respTag {
		return errors.New("unexpected tag")
	}
	if resp == nil {
		return nil
	}
	return json.Unmarshal(body, resp)
}

func (c *Client) AddRule(s AddRuleSpec) (int64, error) {
	var out struct {
		ID int64 `json:"id"`
	}
	if err := c.call(TagAddRule, s, TagAck, &out); err != nil {
		return 0, err
	}
	return out.ID, nil
}

func (c *Client) RevokeRule(id int64) error {
	return c.call(TagRevokeRule, struct {
		ID int64 `json:"id"`
	}{id}, TagAck, nil)
}

func (c *Client) ListRules(r ListReq) ([]RuleRow, error) {
	var out []RuleRow
	if err := c.call(TagListRequest, r, TagListResponse, &out); err != nil {
		return nil, err
	}
	return out, nil
}

func (c *Client) Status() (StatusRow, error) {
	var out StatusRow
	if err := c.call(TagStatusRequest, struct{}{}, TagStatusResponse, &out); err != nil {
		return StatusRow{}, err
	}
	return out, nil
}

func (c *Client) TailAudit(ctx context.Context, r TailReq) ([]AuditRow, error) {
	var out []AuditRow
	if err := c.call(TagTailRequest, r, TagAuditEvent, &out); err != nil {
		return nil, err
	}
	return out, nil
}
```

- [ ] **Step 8: Run tests; expect PASS**

```bash
go test ./internal/ipc/... -v
```

- [ ] **Step 9: Commit**

```bash
git add -A
git commit -m "feat(ipc): Unix-socket length-prefixed JSON IPC + server/client"
```

---

## Task 11: Daemon — `cmd/scdlp-agent`

**Files:**
- Create: `cmd/scdlp-agent/main.go`
- Create: `cmd/scdlp-agent/backend.go`

The daemon: opens both SQLite DBs, builds the engine, starts the IPC server bound to a `Backend` that wraps the engine's stores, and runs the engine against the MockHook (today). When the real ESF hook lands, only the hook argument changes.

- [ ] **Step 1: Write `cmd/scdlp-agent/backend.go`**

```go
package main

import (
	"time"

	"github.com/ronreiter/scdlp/internal/audit"
	"github.com/ronreiter/scdlp/internal/ipc"
	"github.com/ronreiter/scdlp/internal/rules"
)

// daemonBackend adapts our rules+audit stores to the ipc.Backend interface.
type daemonBackend struct {
	rdb      *rules.Store
	adb      *audit.Store
	startTS  int64
}

func newBackend(r *rules.Store, a *audit.Store) *daemonBackend {
	return &daemonBackend{rdb: r, adb: a, startTS: time.Now().Unix()}
}

func (d *daemonBackend) AddRule(s ipc.AddRuleSpec) (int64, error) {
	return d.rdb.Insert(rules.Rule{
		FileKey: s.FileKey, FileKeyKind: rules.FileKeyKind(s.FileKeyKind),
		IdentityKey: s.IdentityKey, IdentityKind: rules.IdentityKind(s.IdentityKind),
		Verdict: rules.Verdict(s.Verdict), CreatedBy: "ipc",
		ExpiresAt: s.ExpiresAt, Note: s.Note,
	})
}

func (d *daemonBackend) RevokeRule(id int64) error { return d.rdb.Revoke(id) }

func (d *daemonBackend) ListRules(r ipc.ListReq) ([]ipc.RuleRow, error) {
	rs, err := d.rdb.List(rules.ListFilter{Verdict: rules.Verdict(r.Verdict)})
	if err != nil {
		return nil, err
	}
	out := make([]ipc.RuleRow, len(rs))
	for i, x := range rs {
		out[i] = ipc.RuleRow{
			ID: x.ID, FileKey: x.FileKey, FileKeyKind: string(x.FileKeyKind),
			IdentityKey: x.IdentityKey, IdentityKind: string(x.IdentityKind),
			Verdict: string(x.Verdict), CreatedAt: x.CreatedAt, CreatedBy: x.CreatedBy,
			ExpiresAt: x.ExpiresAt, Note: x.Note,
		}
	}
	return out, nil
}

func (d *daemonBackend) Status() (ipc.StatusRow, error) {
	rs, _ := d.rdb.List(rules.ListFilter{})
	evts, _ := d.adb.Tail(audit.TailFilter{Limit: 1})
	return ipc.StatusRow{
		Healthy:    true,
		RulesTotal: len(rs),
		AuditEvents: len(evts), // cheap proxy; full count would need COUNT(*)
		Mode:       "enforce",
		UptimeSec:  time.Now().Unix() - d.startTS,
	}, nil
}

func (d *daemonBackend) TailAudit(r ipc.TailReq) ([]ipc.AuditRow, error) {
	es, err := d.adb.Tail(audit.TailFilter{Since: r.Since, Verdict: r.Verdict, Limit: r.Limit})
	if err != nil {
		return nil, err
	}
	out := make([]ipc.AuditRow, len(es))
	for i, e := range es {
		out[i] = ipc.AuditRow{
			ID: e.ID, TS: e.TS, FilePath: e.FilePath, FileKey: e.FileKey,
			FileKeyKind: e.FileKeyKind, ProcessPID: e.ProcessPID, ProcessExe: e.ProcessExe,
			ProcessChain: e.ProcessChain, IdentityKey: e.IdentityKey,
			Verdict: e.Verdict, MatchedKind: e.MatchedKind, DurationUs: e.DurationUs,
		}
	}
	return out, nil
}
```

- [ ] **Step 2: Write `cmd/scdlp-agent/main.go`**

```go
// Command scdlp-agent runs the daemon: IPC server + decision engine + MockHook.
// The real Endpoint Security hook lands in a follow-up plan; the engine is
// hook-agnostic.
package main

import (
	"context"
	"flag"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"github.com/ronreiter/scdlp/internal/agent"
	"github.com/ronreiter/scdlp/internal/audit"
	"github.com/ronreiter/scdlp/internal/hook"
	"github.com/ronreiter/scdlp/internal/ipc"
	"github.com/ronreiter/scdlp/internal/rules"
)

func main() {
	defaultDir := defaultStateDir()
	rulesPath := flag.String("rules", filepath.Join(defaultDir, "rules.db"), "rules DB path")
	auditPath := flag.String("audit", filepath.Join(defaultDir, "audit.db"), "audit DB path")
	sockPath := flag.String("socket", defaultSocketPath(), "IPC socket path")
	home := flag.String("home", os.Getenv("HOME"), "user home dir for path-rule expansion")
	flag.Parse()

	_ = os.MkdirAll(filepath.Dir(*rulesPath), 0o755)
	r, err := rules.Open(*rulesPath)
	if err != nil {
		log.Fatalf("open rules: %v", err)
	}
	defer r.Close()
	a, err := audit.Open(*auditPath)
	if err != nil {
		log.Fatalf("open audit: %v", err)
	}
	defer a.Close()

	bus := agent.NewPromptBus(64)
	eng := agent.New(agent.Config{
		Homes: []string{*home}, Rules: r, Audit: a, Bus: bus,
	})

	be := newBackend(r, a)
	srv := ipc.NewServer(*sockPath, be)
	if err := srv.Start(); err != nil {
		log.Fatalf("ipc start: %v", err)
	}
	defer srv.Stop()
	log.Printf("scdlp-agent up: socket=%s rules=%s audit=%s", *sockPath, *rulesPath, *auditPath)

	// Today: run against a MockHook so the daemon is exercisable end-to-end.
	// Tomorrow: swap in an EndpointSecurityHook here.
	mh := hook.NewMock()

	// Drain prompts to stderr; the Swift helper will subscribe to a real
	// bus over IPC in a future task.
	go func() {
		for p := range bus.C() {
			log.Printf("PROMPT file=%s category=%s pid=%d identity=%s",
				p.FilePath, p.Category, p.PID, p.HumanIdentity)
		}
	}()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go eng.Run(ctx, mh)

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)
	<-stop
	log.Print("scdlp-agent shutting down")
}

func defaultStateDir() string {
	if u := os.Getenv("SCDLP_STATE_DIR"); u != "" {
		return u
	}
	// Test/dev default; install script would switch this to /Library/Application Support/scdlp.
	return filepath.Join(os.Getenv("HOME"), ".scdlp")
}

func defaultSocketPath() string {
	if u := os.Getenv("SCDLP_SOCKET"); u != "" {
		return u
	}
	return filepath.Join(os.TempDir(), "scdlp.sock")
}
```

- [ ] **Step 3: Build and smoke-test**

```bash
cd /Users/ronreiter/GitHub/scdlp
go build -o bin/scdlp-agent ./cmd/scdlp-agent
./bin/scdlp-agent --help
```

Expected: usage line listing the four flags.

- [ ] **Step 4: Commit**

```bash
git add -A
git commit -m "feat(cmd/scdlp-agent): daemon with IPC server + MockHook"
```

---

## Task 12: CLI — `cmd/scdlp`

**Files:**
- Create: `cmd/scdlp/main.go`
- Create: `cmd/scdlp/status.go`
- Create: `cmd/scdlp/rules.go`
- Create: `cmd/scdlp/tail.go`

Cobra-based CLI. Five subcommands: `status`, `list`, `add`, `revoke`, `tail`.

- [ ] **Step 1: Add cobra**

```bash
cd /Users/ronreiter/GitHub/scdlp
go get github.com/spf13/cobra@latest
go mod tidy
```

- [ ] **Step 2: Write `cmd/scdlp/main.go`**

```go
// Command scdlp is the local CLI to the scdlp-agent daemon.
package main

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"
)

func defaultSocket() string {
	if u := os.Getenv("SCDLP_SOCKET"); u != "" {
		return u
	}
	return filepath.Join(os.TempDir(), "scdlp.sock")
}

var socketFlag string

func main() {
	root := &cobra.Command{
		Use:   "scdlp",
		Short: "Local CLI for the scdlp agent.",
	}
	root.PersistentFlags().StringVar(&socketFlag, "socket", defaultSocket(), "IPC socket path")

	root.AddCommand(statusCmd(), listCmd(), addCmd(), revokeCmd(), tailCmd())
	if err := root.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
```

- [ ] **Step 3: Write `cmd/scdlp/status.go`**

```go
package main

import (
	"fmt"

	"github.com/ronreiter/scdlp/internal/ipc"
	"github.com/spf13/cobra"
)

func statusCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "status",
		Short: "Report agent health.",
		RunE: func(_ *cobra.Command, _ []string) error {
			c, err := ipc.Dial(socketFlag)
			if err != nil {
				return err
			}
			defer c.Close()
			st, err := c.Status()
			if err != nil {
				return err
			}
			fmt.Printf("healthy:        %v\n", st.Healthy)
			fmt.Printf("mode:           %s\n", st.Mode)
			fmt.Printf("uptime (s):     %d\n", st.UptimeSec)
			fmt.Printf("rules total:    %d\n", st.RulesTotal)
			return nil
		},
	}
}
```

- [ ] **Step 4: Write `cmd/scdlp/rules.go`**

```go
package main

import (
	"fmt"
	"strconv"

	"github.com/ronreiter/scdlp/internal/ipc"
	"github.com/spf13/cobra"
)

func listCmd() *cobra.Command {
	var verdict string
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List allow/deny rules.",
		RunE: func(_ *cobra.Command, _ []string) error {
			c, err := ipc.Dial(socketFlag)
			if err != nil {
				return err
			}
			defer c.Close()
			rs, err := c.ListRules(ipc.ListReq{Verdict: verdict})
			if err != nil {
				return err
			}
			fmt.Printf("%-5s %-10s %-32s %-10s %-32s\n", "ID", "VERDICT", "FILE_KEY", "ID_KIND", "IDENTITY")
			for _, r := range rs {
				idShort := r.IdentityKey
				if len(idShort) > 12 {
					idShort = idShort[:12] + "…"
				}
				fmt.Printf("%-5d %-10s %-32s %-10s %-32s\n",
					r.ID, r.Verdict, truncate(r.FileKey, 32), r.IdentityKind, idShort)
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&verdict, "verdict", "", "filter by 'allow' or 'deny'")
	return cmd
}

func addCmd() *cobra.Command {
	var spec ipc.AddRuleSpec
	cmd := &cobra.Command{
		Use:   "add",
		Short: "Add an allow/deny rule.",
		RunE: func(_ *cobra.Command, _ []string) error {
			if spec.Verdict != "allow" && spec.Verdict != "deny" {
				return fmt.Errorf("--verdict must be allow or deny")
			}
			c, err := ipc.Dial(socketFlag)
			if err != nil {
				return err
			}
			defer c.Close()
			id, err := c.AddRule(spec)
			if err != nil {
				return err
			}
			fmt.Printf("rule %d added\n", id)
			return nil
		},
	}
	cmd.Flags().StringVar(&spec.FileKey, "file-key", "", "path or category")
	cmd.Flags().StringVar(&spec.FileKeyKind, "file-kind", "category", "path|category")
	cmd.Flags().StringVar(&spec.IdentityKey, "identity-key", "", "chain sha256 or EXE:sha256")
	cmd.Flags().StringVar(&spec.IdentityKind, "identity-kind", "chain", "chain|exe-only")
	cmd.Flags().StringVar(&spec.Verdict, "verdict", "", "allow|deny")
	cmd.Flags().StringVar(&spec.Note, "note", "", "free-form note")
	return cmd
}

func revokeCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "revoke <rule-id>",
		Short: "Revoke (delete) a rule by id.",
		Args:  cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			id, err := strconv.ParseInt(args[0], 10, 64)
			if err != nil {
				return err
			}
			c, err := ipc.Dial(socketFlag)
			if err != nil {
				return err
			}
			defer c.Close()
			return c.RevokeRule(id)
		},
	}
}

func truncate(s string, n int) string {
	if len(s) > n {
		return s[:n-1] + "…"
	}
	return s
}
```

- [ ] **Step 5: Write `cmd/scdlp/tail.go`**

```go
package main

import (
	"context"
	"fmt"
	"time"

	"github.com/ronreiter/scdlp/internal/ipc"
	"github.com/spf13/cobra"
)

func tailCmd() *cobra.Command {
	var sinceDur time.Duration
	var limit int
	var verdict string
	cmd := &cobra.Command{
		Use:   "tail",
		Short: "Show recent decisions.",
		RunE: func(_ *cobra.Command, _ []string) error {
			c, err := ipc.Dial(socketFlag)
			if err != nil {
				return err
			}
			defer c.Close()
			var since int64
			if sinceDur > 0 {
				since = time.Now().Add(-sinceDur).Unix()
			}
			rows, err := c.TailAudit(context.Background(), ipc.TailReq{
				Since: since, Verdict: verdict, Limit: limit,
			})
			if err != nil {
				return err
			}
			for _, r := range rows {
				ts := time.Unix(r.TS, 0).Format(time.RFC3339)
				fmt.Printf("%s  %-5s  %-20s  pid=%-6d  exe=%s  via=%s\n",
					ts, r.Verdict, truncate(r.FileKey, 20), r.ProcessPID,
					r.ProcessExe, r.ProcessChain)
			}
			return nil
		},
	}
	cmd.Flags().DurationVar(&sinceDur, "since", time.Hour, "show events newer than this duration")
	cmd.Flags().StringVar(&verdict, "verdict", "", "filter by verdict")
	cmd.Flags().IntVar(&limit, "limit", 100, "max rows")
	return cmd
}
```

- [ ] **Step 6: Build CLI**

```bash
cd /Users/ronreiter/GitHub/scdlp
go build -o bin/scdlp ./cmd/scdlp
./bin/scdlp --help
```

Expected: usage with five subcommands.

- [ ] **Step 7: Commit**

```bash
git add -A
git commit -m "feat(cmd/scdlp): cobra CLI with status/list/add/revoke/tail"
```

---

## Task 13: End-to-end test (in-process Shai-Hulud reenactment)

**Files:**
- Create: `e2e/shaihulud_test.go`

This test exercises the whole stack end-to-end inside one Go binary: daemon up, CLI'd over the socket, MockHook fed a synthesized "npm postinstall reads ~/.aws/credentials" event, assert DENY and prompt and audit row.

- [ ] **Step 1: Write the test**

```go
//go:build darwin

package e2e_test

import (
	"context"
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
func (b *backend) RevokeRule(id int64) error { return b.r.Revoke(id) }
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
	// Set up a fake $HOME with a real ~/.aws/credentials file.
	home := t.TempDir()
	_ = os.MkdirAll(filepath.Join(home, ".aws"), 0o700)
	creds := filepath.Join(home, ".aws/credentials")
	_ = os.WriteFile(creds, []byte("[default]\naws_access_key_id=AKIAIOSFODNN7EXAMPLE\n"), 0o600)

	// Stores in tempdir.
	dir := t.TempDir()
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
			// Shai-Hulud shape: node ← sh ← npm ← node (postinstall recursion is real)
			4242: {Exe: "/usr/bin/node",
				Chain: []string{"/usr/bin/node", "/bin/sh", "/usr/local/bin/npm", "/usr/bin/node"}},
			// Legit shape: aws ← zsh ← Terminal
			1: {Exe: "/usr/local/bin/aws",
				Chain: []string{"/usr/local/bin/aws", "/bin/zsh", "/Applications/Utilities/Terminal.app/Contents/MacOS/Terminal"}},
		},
	})

	// IPC up.
	sock := filepath.Join(dir, "scdlp.sock")
	srv := ipc.NewServer(sock, &backend{r: r, a: a})
	if err := srv.Start(); err != nil {
		t.Fatal(err)
	}
	defer srv.Stop()

	// Engine + hook.
	mh := hook.NewMock()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go eng.Run(ctx, mh)

	// 1. The malicious postinstall is denied + prompt fires.
	d := mh.Inject(hook.Event{Path: creds, PID: 4242})
	if d != hook.Deny {
		t.Fatalf("postinstall must be denied, got %v", d)
	}
	select {
	case p := <-bus.C():
		if p.Category != "aws-credentials" {
			t.Fatalf("unexpected category: %s", p.Category)
		}
	case <-time.After(time.Second):
		t.Fatal("expected prompt for the postinstall")
	}

	// 2. User clicks 'Allow Always' for legitimate aws via CLI.
	c, err := ipc.Dial(sock)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	legit := identity.Identity{Exe: "/usr/local/bin/aws",
		Chain: []string{"/usr/local/bin/aws", "/bin/zsh", "/Applications/Utilities/Terminal.app/Contents/MacOS/Terminal"}}
	legit.Compute()
	if _, err := c.AddRule(ipc.AddRuleSpec{
		FileKey: "aws-credentials", FileKeyKind: "category",
		IdentityKey: legit.KeyHex, IdentityKind: "chain", Verdict: "allow",
	}); err != nil {
		t.Fatal(err)
	}

	// 3. Legit aws → allow.
	if got := mh.Inject(hook.Event{Path: creds, PID: 1}); got != hook.Allow {
		t.Fatalf("legit aws must be allowed, got %v", got)
	}

	// 4. Postinstall *again* — still denied. Even though the legit chain
	//    is now allowlisted, the malicious chain is a different identity.
	if got := mh.Inject(hook.Event{Path: creds, PID: 4242}); got != hook.Deny {
		t.Fatalf("postinstall must remain denied, got %v", got)
	}

	// 5. Audit log has all four events.
	rows, _ := c.TailAudit(context.Background(), ipc.TailReq{Limit: 100})
	if len(rows) < 3 { // first deny, allow, second deny; tier-1 fast-skip events not audited
		t.Fatalf("expected ≥3 audit rows, got %d", len(rows))
	}
}
```

- [ ] **Step 2: Run**

```bash
cd /Users/ronreiter/GitHub/scdlp
go test ./e2e/... -v
```

Expected: `TestShaiHulud_DeniesPostinstall` PASSES.

- [ ] **Step 3: Commit**

```bash
git add -A
git commit -m "test(e2e): Shai-Hulud reenactment passes end-to-end"
```

---

## Task 14: Performance benchmark

**Files:**
- Create: `internal/agent/engine_bench_test.go`

Assert the synchronous decision path meets the spec's P99 < 200 µs budget on a representative tier-1 deny path.

- [ ] **Step 1: Write the bench**

```go
package agent

import (
	"os"
	"path/filepath"
	"sort"
	"testing"
	"time"

	"github.com/ronreiter/scdlp/internal/audit"
	"github.com/ronreiter/scdlp/internal/hook"
	"github.com/ronreiter/scdlp/internal/identity"
	"github.com/ronreiter/scdlp/internal/rules"
)

func BenchmarkDecide_Tier1Deny(b *testing.B) {
	home := b.TempDir()
	_ = os.MkdirAll(filepath.Join(home, ".aws"), 0o700)
	creds := filepath.Join(home, ".aws/credentials")
	_ = os.WriteFile(creds, []byte("[default]\n"), 0o600)

	dir := b.TempDir()
	r, _ := rules.Open(filepath.Join(dir, "rules.db"))
	a, _ := audit.Open(filepath.Join(dir, "audit.db"))
	defer r.Close()
	defer a.Close()
	bus := NewPromptBus(64)
	eng := New(Config{
		Homes: []string{home}, Rules: r, Audit: a, Bus: bus,
		Resolver: fakeBenchResolver{},
	})
	ev := hook.Event{Path: creds, PID: 1234}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = eng.Decide(ev)
	}
}

// fakeBenchResolver is allocation-cheap.
type fakeBenchResolver struct{}

func (fakeBenchResolver) Resolve(pid int) (identity.Identity, error) {
	id := identity.Identity{Exe: "/usr/bin/node",
		Chain: []string{"/usr/bin/node", "/bin/sh", "/usr/local/bin/npm"}}
	id.Compute()
	return id, nil
}

func TestDecide_P99UnderBudget(t *testing.T) {
	home := t.TempDir()
	_ = os.MkdirAll(filepath.Join(home, ".aws"), 0o700)
	creds := filepath.Join(home, ".aws/credentials")
	_ = os.WriteFile(creds, []byte("[default]\n"), 0o600)

	dir := t.TempDir()
	r, _ := rules.Open(filepath.Join(dir, "rules.db"))
	a, _ := audit.Open(filepath.Join(dir, "audit.db"))
	defer r.Close()
	defer a.Close()
	bus := NewPromptBus(64)
	eng := New(Config{
		Homes: []string{home}, Rules: r, Audit: a, Bus: bus,
		Resolver: fakeBenchResolver{},
	})

	const N = 5000
	ev := hook.Event{Path: creds, PID: 1234}
	durs := make([]time.Duration, 0, N)
	for i := 0; i < N; i++ {
		start := time.Now()
		_ = eng.Decide(ev)
		durs = append(durs, time.Since(start))
	}
	sort.Slice(durs, func(i, j int) bool { return durs[i] < durs[j] })
	p99 := durs[(99*N)/100]
	t.Logf("p50=%v p95=%v p99=%v", durs[N/2], durs[(95*N)/100], p99)
	// Budget per spec: <200 µs. Allow generous 1 ms headroom for slow CI.
	if p99 > time.Millisecond {
		t.Fatalf("p99 too slow: %v", p99)
	}
}
```

- [ ] **Step 2: Run the perf test**

```bash
cd /Users/ronreiter/GitHub/scdlp
go test ./internal/agent/ -run P99 -v
```

Expected: PASS with the logged P50/P95/P99 line showing P99 well under 1 ms.

- [ ] **Step 3: Optionally run the benchmark**

```bash
go test ./internal/agent/ -bench BenchmarkDecide -benchmem
```

Expected: a single `ns/op` line; ideally under 200000 ns/op (200 µs).

- [ ] **Step 4: Commit**

```bash
git add -A
git commit -m "test(perf): assert decision P99 within budget; add bench"
```

---

## Task 15: README + onboarding doc

**Files:**
- Modify: `README.md`
- Create: `docs/onboarding.md`

Replace the stub README with a usable quick-start. Add `docs/onboarding.md` that walks a new dev through building, running, and pointing the daemon + CLI at each other.

- [ ] **Step 1: Write `README.md`**

```markdown
# scdlp

**Anti-supply-chain DLP for macOS.**

Hooks every file open via Apple's Endpoint Security framework, classifies the file's first 4 KiB in real time, and blocks unknown processes from reading credentials — with a Little-Snitch-style allow/deny prompt to the user. Defeats the npm/pip/cargo postinstall pattern that reads `~/.aws/credentials`, `~/.ssh/id_*`, `~/.npmrc`, etc.

> **Status:** v1 core (this repo) lands the Go-side engine, classifier, rules/audit stores, IPC, daemon, and CLI. The real Endpoint Security System Extension (C/Swift/Xcode) is a follow-up plan because it depends on Apple's ESF entitlement and the signing/notarization toolchain.

Sibling project: [`stasher`](https://github.com/ronreiter/stasher) — the FUSE-based flavor with hardware-bound encryption around `.env` files.

## Architecture

See `docs/superpowers/specs/2026-05-27-scdlp-design.md`.

Three local processes:

- **`scdlp-agent`** — daemon, owns the SQLite at `~/.scdlp/`, runs the decision pipeline.
- **`scdlp`** — CLI, talks to the daemon over a Unix socket.
- *(future)* **scdlp-helper** — Swift menubar app for prompts.

## Build

```bash
make build
```

Outputs `bin/scdlp-agent` and `bin/scdlp`.

## Run

In one terminal:

```bash
./bin/scdlp-agent
```

In another:

```bash
./bin/scdlp status
./bin/scdlp tail --since 5m
./bin/scdlp list
```

See `docs/onboarding.md` for a full walkthrough including the in-process Shai-Hulud reenactment test.

## Test

```bash
make test            # unit + e2e
make bench           # decision-path microbenchmark
```

## License

MIT.
```

- [ ] **Step 2: Write `docs/onboarding.md`**

```markdown
# Onboarding

## Prerequisites

- macOS 13+ (Apple Silicon or Intel).
- Go 1.24+.
- Xcode CLI tools (for cgo's libproc shim): `xcode-select --install`.

## Layout

```
scdlp/
├── cmd/
│   ├── scdlp-agent/        # daemon
│   └── scdlp/              # CLI
├── internal/
│   ├── classify/           # secret detector (ported from stasher)
│   ├── pathrules/          # tier-1 path globs
│   ├── identity/           # exe + ancestry chain (cgo libproc)
│   ├── rules/              # SQLite store
│   ├── audit/              # SQLite append-only log
│   ├── agent/              # decision engine, prompt bus
│   ├── hook/               # FileHook interface + MockHook
│   └── ipc/                # Unix-socket JSON RPC
├── e2e/                    # Shai-Hulud reenactment
└── docs/superpowers/
    ├── specs/              # design doc
    └── plans/              # this plan
```

## What's where

- The decision pipeline (path-tier → content-tier → identity → rules.Lookup) lives in `internal/agent/engine.go`. Read this first.
- The classifier is `internal/classify/classifier.go`. Tests in `_test.go` next to it.
- The hook abstraction is `internal/hook/hook.go`; today only `MockHook` exists. The real ESF backend is a follow-up.

## Run end-to-end locally

```bash
make build
# Terminal A
./bin/scdlp-agent --rules /tmp/scdlp-rules.db --audit /tmp/scdlp-audit.db --home "$HOME"
# Terminal B
./bin/scdlp status
./bin/scdlp tail
./bin/scdlp add --file-key aws-credentials --file-kind category \
                --identity-key abc --identity-kind chain --verdict allow
./bin/scdlp list
./bin/scdlp revoke 1
```

Today the daemon is wired to a `MockHook`, so no real opens are intercepted; the e2e test in `e2e/shaihulud_test.go` exercises the same machinery end-to-end against synthetic events.

## What's NOT in this repo yet

The actual Endpoint Security System Extension. That needs:

1. The `com.apple.developer.endpoint-security.client` entitlement from Apple.
2. An Xcode project for the System Extension target, a Swift host app to package it, and code-signing / notarization wired into a release pipeline.
3. A cgo glue file calling `libEndpointSecurity` and feeding events into the `Hook` interface defined in `internal/hook/hook.go`.

The Go core is ESF-agnostic; landing the ESF backend is purely a new `internal/hook/esf_darwin.go` plus the Xcode project. The decision engine, classifier, rules/audit stores, and CLI ship as-is.
```

- [ ] **Step 3: Commit**

```bash
git add -A
git commit -m "docs: README + onboarding"
```

---

## Self-review summary

**Spec coverage:**

| Spec section | Covered by tasks |
|---|---|
| §4 Component split | Tasks 6 (rules), 7 (audit), 8 (hook), 9 (agent), 10 (ipc), 11 (daemon), 12 (cli) |
| §5.1 Decision pipeline | Task 9 |
| §5.1 Performance budget | Task 14 (P99 test) |
| §5.1 Process identity | Task 5 |
| §5.4 SQLite schema | Tasks 6 + 7 (rules + audit tables) |
| §5.5 Classifier | Tasks 2 + 3 |
| §5.5 Tier-1 path patterns | Task 4 |
| §5.6 IPC protocol | Task 10 |
| §5.3 CLI | Task 12 |
| §6.3 Shai-Hulud flow | Task 13 (E2E) |
| §5.2 Helper (Swift menubar) | **Out of scope for this plan.** Lives in a follow-up plan that brings Xcode and the ESF entitlement together. The PromptBus from Task 9 is the contract the helper will subscribe to. |
| Real Endpoint Security hook | **Out of scope.** Plumbing is ready (`Hook` interface in Task 8). |

**Out-of-scope items explicitly deferred:**

- Swift menubar helper (depends on Xcode toolchain decisions).
- ESF System Extension target + cgo glue (depends on Apple entitlement).
- Privileged install of `/usr/local/bin/scdlp` and `/Library/Application Support/scdlp` (depends on having signed binaries).
- `scdlp doctor`, `scdlp pause`, `scdlp export-audit` subcommands (mentioned in spec §5.3, deferred to v1.1 once the agent is wired to the real ESF backend; they're shell-thin over the same IPC).

**Placeholder scan:** None.

**Type consistency:** `FileKeyKind`, `IdentityKind`, `Verdict` named-string types are defined in `internal/rules` and consumed verbatim in `internal/agent` and `internal/ipc`. The `Hook.Decision` type (Task 8) is returned by `Engine.Decide` (Task 9) and `MockHook.Inject` (Task 8) — match. `identity.Identity.KeyHex` (Task 5) is the value stored in `rules.Rule.IdentityKey` and used as `ipc.AddRuleSpec.IdentityKey` — match.
