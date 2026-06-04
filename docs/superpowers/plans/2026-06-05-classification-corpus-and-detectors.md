# Classification Corpus + Layered Detectors Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a synthetic positive/negative secret-detection corpus and improve `internal/classify` until it detects every secret with zero false positives on benign files.

**Architecture:** Keep `Classifier.ClassifyBuf(buf []byte) Verdict` as the single entry point (first 4 KiB, `IsSecret()` at `0.6`). Run an ordered detector pipeline — PEM private key (existing), provider prefix→regex (existing, expanded), a new generic key/value+entropy heuristic, and a best-effort PKCS#12 marker — returning the highest-confidence `Verdict`. A directory-based corpus test enforces 100% recall on `positive/` and zero false positives on `negative/`.

**Tech Stack:** Go, `internal/classify` (Aho-Corasick via `github.com/cloudflare/ahocorasick`, `regexp`, the existing `entropy.go`/`denoise.go` helpers). Tests are standard `go test` walking `testdata/corpus/`.

**Reference spec:** `docs/superpowers/specs/2026-06-05-classification-corpus-and-detectors-design.md`

**Key existing API (do not change signatures):**
- `classify.New() *Classifier`, `(*Classifier).ClassifyBuf(buf []byte) Verdict`
- `Verdict{Key, Value, Match string; Confidence float32; Reason string}`, `(Verdict).IsSecret() bool` (`Confidence >= 0.6`)
- `const MaxScanBytes = 4096`
- `ShannonEntropy(s string) float64`, `SecretishKeyName(key string) bool` (`entropy.go`)
- `IsPlaceholder(v string) bool`, `IsBooleanOrNumeric(v string) bool`, `IsURLWithoutEmbeddedCreds(v string) bool` (`denoise.go`)
- `ProviderPrefixes map[string][]string` (`prefixes.go`), `ProviderPatterns map[string]*regexp.Regexp` + `PEMPrivateKeyRe` (`patterns.go`)

---

### Task 1: Corpus harness + baseline corpus

**Files:**
- Create: `internal/classify/corpus_test.go`
- Create: `internal/classify/testdata/corpus/positive/aws-access-key.env`
- Create: `internal/classify/testdata/corpus/positive/github-pat.env`
- Create: `internal/classify/testdata/corpus/positive/id_rsa.pem`
- Create: `internal/classify/testdata/corpus/negative/plain-config.json`
- Create: `internal/classify/testdata/corpus/negative/public-cert.pem`

This task builds the harness and a small starter corpus that today's engine already passes (provider prefixes + PEM positives, plus benign negatives). Later tasks add the harder fixtures that drive detector work, so this task must be GREEN on the current engine.

- [ ] **Step 1: Create the starter positive fixtures (already detectable today)**

`internal/classify/testdata/corpus/positive/aws-access-key.env`:
```
# deploy credentials
AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
AWS_DEFAULT_REGION=us-east-1
```

`internal/classify/testdata/corpus/positive/github-pat.env`:
```
GITHUB_TOKEN=ghp_1234567890abcdefghijklmnopqrstuvwxyzAB
```
(The value is `ghp_` + 36 chars, matching `^(ghp_|…)[A-Za-z0-9_]{36,251}$`.)

`internal/classify/testdata/corpus/positive/id_rsa.pem`:
```
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACDExampleExampleExampleExampleExampleExampleExampleAAAJiABCDE
-----END OPENSSH PRIVATE KEY-----
```

- [ ] **Step 2: Create the starter negative fixtures (must NOT flag)**

`internal/classify/testdata/corpus/negative/plain-config.json`:
```json
{
  "service": "billing",
  "port": 8080,
  "log_level": "info",
  "retries": 3,
  "feature_flags": { "new_ui": true, "beta": false }
}
```

`internal/classify/testdata/corpus/negative/public-cert.pem`:
```
-----BEGIN CERTIFICATE-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAExampleExampleExampleExample
ExampleExampleExampleExampleExampleExampleExampleExampleExampleExampleAB
-----END CERTIFICATE-----
```

- [ ] **Step 3: Write the corpus harness**

`internal/classify/corpus_test.go`:
```go
package classify

import (
	"os"
	"path/filepath"
	"testing"
)

// readHead returns up to MaxScanBytes bytes of the file, mirroring what the
// agent's default reader feeds ClassifyBuf.
func readHead(t *testing.T, path string) []byte {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("open %s: %v", path, err)
	}
	defer f.Close()
	buf := make([]byte, MaxScanBytes)
	n, _ := f.Read(buf)
	return buf[:n]
}

// corpusFiles lists the regular files under testdata/corpus/<bucket>.
func corpusFiles(t *testing.T, bucket string) []string {
	t.Helper()
	root := filepath.Join("testdata", "corpus", bucket)
	var out []string
	err := filepath.Walk(root, func(p string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() {
			out = append(out, p)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk %s: %v", root, err)
	}
	return out
}

func TestCorpus_PositivesAndNegatives(t *testing.T) {
	c := New()

	var posTotal, posHit, negTotal, falsePos int
	var missed, flagged []string

	for _, p := range corpusFiles(t, "positive") {
		posTotal++
		v := c.ClassifyBuf(readHead(t, p))
		if v.IsSecret() {
			posHit++
		} else {
			missed = append(missed, p)
		}
	}
	for _, p := range corpusFiles(t, "negative") {
		negTotal++
		v := c.ClassifyBuf(readHead(t, p))
		if v.IsSecret() {
			falsePos++
			flagged = append(flagged, p+"  =>  "+v.Match+" ("+v.Reason+")")
		}
	}

	// Precision/recall summary (always printed).
	recall := 1.0
	if posTotal > 0 {
		recall = float64(posHit) / float64(posTotal)
	}
	tp := posHit
	precision := 1.0
	if tp+falsePos > 0 {
		precision = float64(tp) / float64(tp+falsePos)
	}
	t.Logf("corpus: positives=%d hit=%d (recall=%.3f)  negatives=%d falsePos=%d (precision=%.3f)",
		posTotal, posHit, recall, negTotal, falsePos, precision)

	for _, m := range missed {
		t.Errorf("MISS (positive not detected): %s", m)
	}
	for _, f := range flagged {
		t.Errorf("FALSE POSITIVE (negative flagged): %s", f)
	}
}
```

- [ ] **Step 4: Run the harness — expect GREEN on the current engine**

Run: `go test ./internal/classify/ -run TestCorpus -v`
Expected: PASS. The log line shows `recall=1.000 … precision=1.000` for these 5 fixtures (3 positives caught by provider/PEM detectors, 2 negatives not flagged).

- [ ] **Step 5: Commit**

```bash
git add internal/classify/corpus_test.go internal/classify/testdata/corpus/
git commit -m "test(classify): corpus harness + baseline fixtures (recall/precision gate)

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

### Task 2: Generic key/value + entropy detector (Detector C)

**Files:**
- Create: `internal/classify/generic.go`
- Create: `internal/classify/generic_test.go`
- Modify: `internal/classify/classifier.go` (add Detector C to the pipeline in `ClassifyBuf`)
- Create: `internal/classify/testdata/corpus/positive/aws-credentials` (no extension; AWS CLI creds file)
- Create: `internal/classify/testdata/corpus/positive/generic-api-token.json`
- Create: `internal/classify/testdata/corpus/positive/db-url-with-password.env`
- Create: `internal/classify/testdata/corpus/negative/hashes-and-uuids.json`
- Create: `internal/classify/testdata/corpus/negative/placeholders.env`
- Create: `internal/classify/testdata/corpus/negative/db-url-no-creds.env`

Detector C catches secrets with no known provider prefix by extracting `(key, value)` pairs and flagging a secret-ish key with a high-entropy, non-placeholder value. Write its unit tests first (TDD), then wire it into `ClassifyBuf`, then add corpus fixtures that exercise it.

- [ ] **Step 1: Write `generic_test.go` (failing — functions don't exist yet)**

`internal/classify/generic_test.go`:
```go
package classify

import "testing"

func TestExtractPairs_EnvAndJSON(t *testing.T) {
	buf := []byte("API_TOKEN=s3cr3t-LONG-random-VALUE-9f8a7b6c5d\n" +
		`{"client_secret": "abcDEF123456ghiJKL789mno", "port": 8080}`)
	pairs := extractPairs(buf)
	got := map[string]string{}
	for _, p := range pairs {
		got[p.key] = p.value
	}
	if got["API_TOKEN"] != "s3cr3t-LONG-random-VALUE-9f8a7b6c5d" {
		t.Fatalf("env pair not extracted: %q", got["API_TOKEN"])
	}
	if got["client_secret"] != "abcDEF123456ghiJKL789mno" {
		t.Fatalf("json pair not extracted: %q", got["client_secret"])
	}
}

func TestClassifyGeneric_FlagsSecretishHighEntropy(t *testing.T) {
	v := classifyGeneric([]byte("API_TOKEN=s3cr3t-LONG-random-VALUE-9f8a7b6c5d\n"))
	if !v.IsSecret() {
		t.Fatalf("secret-ish key with high-entropy value must be a secret, got %+v", v)
	}
	if v.Match != "generic-credential" {
		t.Fatalf("want match generic-credential, got %q", v.Match)
	}
}

func TestClassifyGeneric_IgnoresBenignKey(t *testing.T) {
	// High-entropy value but benign key name → must NOT flag.
	v := classifyGeneric([]byte(`{"sha256": "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"}`))
	if v.IsSecret() {
		t.Fatalf("benign key must not flag, got %+v", v)
	}
}

func TestClassifyGeneric_IgnoresPlaceholderAndBool(t *testing.T) {
	for _, in := range []string{
		"API_KEY=changeme\n",
		"SECRET=${MY_SECRET}\n",
		"PASSWORD=your-password-here\n",
		"AUTH_ENABLED=true\n",
		"TOKEN=<your-token>\n",
	} {
		if v := classifyGeneric([]byte(in)); v.IsSecret() {
			t.Fatalf("placeholder/bool must not flag: %q -> %+v", in, v)
		}
	}
}

func TestClassifyGeneric_IgnoresShortValue(t *testing.T) {
	// Secret-ish key but value too short / low entropy.
	if v := classifyGeneric([]byte("token=abc\n")); v.IsSecret() {
		t.Fatalf("short value must not flag, got %+v", v)
	}
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `go test ./internal/classify/ -run 'TestExtractPairs|TestClassifyGeneric' -v`
Expected: FAIL to compile — `extractPairs`, `classifyGeneric`, and `kvPair` are undefined.

- [ ] **Step 3: Implement `generic.go`**

`internal/classify/generic.go`:
```go
package classify

import "regexp"

// minSecretLen and minSecretEntropy gate the generic key/value detector. A
// flagged value must be at least this long and this random (Shannon entropy,
// bits/byte). Tuned against testdata/corpus.
const (
	minSecretLen     = 12
	minSecretEntropy = 3.0
)

// kvPair is a candidate key/value extracted from the buffer.
type kvPair struct {
	key   string
	value string
}

// pairRe captures key/value pairs in the two dominant shapes:
//   KEY=VALUE             (env, ini, npmrc, aws credentials)
//   "key": "value"        (json) and  key: value  (yaml)
// The key is an identifier (optionally quoted); the value is either a quoted
// run or a bare run up to whitespace, comma, or closing brace. It is a lexical
// scan, not a parser — it must tolerate truncated/partial documents.
var pairRe = regexp.MustCompile(
	`(?m)["']?([A-Za-z0-9_.\-]+)["']?\s*[:=]\s*(?:"([^"]*)"|'([^']*)'|([^\s,}]+))`)

// extractPairs pulls candidate (key, value) pairs from buf (capped to keep the
// hot path bounded). Only the first MaxScanBytes are considered by the caller.
func extractPairs(buf []byte) []kvPair {
	const maxPairs = 256
	ms := pairRe.FindAllSubmatch(buf, maxPairs)
	out := make([]kvPair, 0, len(ms))
	for _, m := range ms {
		val := string(m[2])
		if val == "" {
			val = string(m[3])
		}
		if val == "" {
			val = string(m[4])
		}
		out = append(out, kvPair{key: string(m[1]), value: val})
	}
	return out
}

// classifyGeneric flags a secret when a secret-ish key carries a high-entropy,
// non-placeholder value. Requiring the key name (not bare entropy) is what
// keeps false positives off hashes/UUIDs stored under benign keys.
func classifyGeneric(buf []byte) Verdict {
	for _, p := range extractPairs(buf) {
		if !SecretishKeyName(p.key) {
			continue
		}
		if p.value == "" || len(p.value) < minSecretLen {
			continue
		}
		if IsPlaceholder(p.value) || IsBooleanOrNumeric(p.value) || IsURLWithoutEmbeddedCreds(p.value) {
			continue
		}
		if ShannonEntropy(p.value) < minSecretEntropy {
			continue
		}
		return Verdict{
			Key:        p.key,
			Value:      p.value,
			Match:      "generic-credential",
			Confidence: 0.8,
			Reason:     "secret-ish key + high-entropy value: " + p.key,
		}
	}
	return Verdict{Reason: "no generic credential"}
}
```

- [ ] **Step 4: Run the generic unit tests — expect PASS**

Run: `go test ./internal/classify/ -run 'TestExtractPairs|TestClassifyGeneric' -v`
Expected: PASS (all 5).

- [ ] **Step 5: Wire Detector C into `ClassifyBuf`**

In `internal/classify/classifier.go`, in `ClassifyBuf`, after the Pass-2 provider loop computes `best` and before the final `return best`, consult the generic detector when the provider stage has not already produced a confident hit. Replace the tail of `ClassifyBuf` (the block starting at `if best.Match == ""`) with:

```go
	// Detector C: generic key/value + entropy. Only needed when the provider
	// stage did not already yield a confident (>= 0.6) finding.
	if !best.IsSecret() {
		if g := classifyGeneric(buf); g.IsSecret() {
			return g
		}
	}
	if best.Match == "" {
		best.Reason = "prefix matched, no token"
	}
	return best
```

Note: the early `return Verdict{Reason: "no provider prefix"}` when Aho-Corasick finds nothing must ALSO fall through to the generic detector. Change that early return so a no-prefix buffer still gets Detector C:

```go
	hits := c.ac.Match(buf)
	if len(hits) == 0 {
		if g := classifyGeneric(buf); g.IsSecret() {
			return g
		}
		return Verdict{Reason: "no provider prefix"}
	}
```

- [ ] **Step 6: Add corpus fixtures that exercise Detector C**

Positives:

`internal/classify/testdata/corpus/positive/aws-credentials` (AWS CLI file, no prefix on the secret value):
```
[default]
aws_access_key_id = AKIAIOSFODNN7EXAMPLE
aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
```

`internal/classify/testdata/corpus/positive/generic-api-token.json`:
```json
{
  "service": "internal-api",
  "client_secret": "Xb9Kfated2QmZ1pR7sVn0LwYc4Hh6Tj8",
  "timeout_ms": 3000
}
```

`internal/classify/testdata/corpus/positive/db-url-with-password.env`:
```
DATABASE_PASSWORD=pV8x2Lq7Tz4Wm1Nd9Rk5Bj3
```

Negatives:

`internal/classify/testdata/corpus/negative/hashes-and-uuids.json`:
```json
{
  "sha256": "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
  "request_id": "550e8400-e29b-41d4-a716-446655440000",
  "git_commit": "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0",
  "build": "9db5b66c7446196fa712bd3de330d17799387cbc"
}
```

`internal/classify/testdata/corpus/negative/placeholders.env`:
```
API_KEY=changeme
CLIENT_SECRET=${CLIENT_SECRET}
GITHUB_TOKEN=your-token-here
AUTH_TOKEN=<replace-me>
PASSWORD=
```

`internal/classify/testdata/corpus/negative/db-url-no-creds.env`:
```
DATABASE_URL=postgres://localhost:5432/billing
REDIS_URL=redis://cache:6379/0
```

- [ ] **Step 7: Run the full corpus harness + classify package**

Run: `go test ./internal/classify/ -v`
Expected: PASS. The corpus log shows recall=1.000 and precision=1.000 across all fixtures (the new positives are caught by Detector C; the new negatives are not flagged). If any negative flags or positive misses, adjust `minSecretLen`/`minSecretEntropy` in `generic.go` and re-run — do not relax the secret-ish-key gate.

- [ ] **Step 8: Commit**

```bash
git add internal/classify/generic.go internal/classify/generic_test.go internal/classify/classifier.go internal/classify/testdata/corpus/
git commit -m "feat(classify): generic key/value + entropy detector (Detector C)

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

### Task 3: Expand the provider table + provider fixtures

**Files:**
- Modify: `internal/classify/prefixes.go` (add provider prefixes)
- Modify: `internal/classify/patterns.go` (add matching validation regexes)
- Create: `internal/classify/testdata/corpus/positive/stripe-test.env`
- Create: `internal/classify/testdata/corpus/positive/slack-webhook.env`
- Create: `internal/classify/testdata/corpus/positive/twilio.env`
- Create: `internal/classify/testdata/corpus/positive/digitalocean.env`
- Create: `internal/classify/testdata/corpus/positive/jwt.txt`
- Create: `internal/classify/testdata/corpus/negative/lockfile-integrity.json`

Add a few high-value providers and lock them in with fixtures. `prefixes.go` and `patterns.go` MUST stay in sync — every prefix key needs a pattern under the same provider name.

- [ ] **Step 1: Add provider prefixes**

In `internal/classify/prefixes.go`, add these entries to the `ProviderPrefixes` map (keep formatting consistent with existing entries):
```go
	"twilio":       {"SK", "AC"},
	"digitalocean": {"dop_v1_", "dor_v1_", "doo_v1_"},
	"shopify":      {"shpat_", "shpss_", "shpca_"},
	"square":       {"sq0atp-", "sq0csp-"},
```
(Stripe/Slack/JWT prefixes already exist — no change needed for those.)

- [ ] **Step 2: Add matching validation patterns**

In `internal/classify/patterns.go`, add to the `ProviderPatterns` map:
```go
	"twilio":       regexp.MustCompile(`^(SK|AC)[0-9a-fA-F]{32}$`),
	"digitalocean": regexp.MustCompile(`^(dop|dor|doo)_v1_[0-9a-f]{64}$`),
	"shopify":      regexp.MustCompile(`^shp(at|ss|ca)_[0-9a-fA-F]{32}$`),
	"square":       regexp.MustCompile(`^sq0(atp|csp)-[A-Za-z0-9_\-]{22,}$`),
```

- [ ] **Step 3: Add provider positive fixtures**

`internal/classify/testdata/corpus/positive/stripe-test.env`:
```
STRIPE_SECRET_KEY=sk_test_4eC39HqLyjWDarjtT1zdp7dcabcdefghij
```

`internal/classify/testdata/corpus/positive/slack-webhook.env`:
```
SLACK_BOT_TOKEN=xoxb-1234567890-0987654321-AbCdEfGhIjKlMnOpQrStUvWx
```

`internal/classify/testdata/corpus/positive/twilio.env`:
```
TWILIO_API_KEY=SK0123456789abcdef0123456789abcdef
```

`internal/classify/testdata/corpus/positive/digitalocean.env`:
```
DIGITALOCEAN_TOKEN=dop_v1_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
```

`internal/classify/testdata/corpus/positive/jwt.txt`:
```
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c
```

- [ ] **Step 4: Add a negative fixture that must stay benign**

`internal/classify/testdata/corpus/negative/lockfile-integrity.json` (npm lockfile integrity hashes — high entropy, benign key names, NOT secrets):
```json
{
  "node_modules/left-pad": {
    "version": "1.3.0",
    "resolved": "https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz",
    "integrity": "sha512-XI5MPzVNApjAyhQzphX8BkmKsKUxD4LdyK24iZeQGinBN9yTQT3bFlCBy/aVx2HrNcqQGsdot8ghrjyrvMCoEA=="
  }
}
```

- [ ] **Step 5: Run the full classify suite**

Run: `go test ./internal/classify/ -v`
Expected: PASS. Corpus recall=1.000, precision=1.000. The Twilio `SK`/`AC` prefixes are short and common — confirm `lockfile-integrity.json` and other negatives do NOT false-positive on them (the `^(SK|AC)[0-9a-fA-F]{32}$` anchor requires exactly 32 hex chars, so prose `SK`/`AC` will not match). If a negative flags, the provider regex is too loose — tighten it, do not delete the negative.

- [ ] **Step 6: Commit**

```bash
git add internal/classify/prefixes.go internal/classify/patterns.go internal/classify/testdata/corpus/
git commit -m "feat(classify): expand provider table (twilio/do/shopify/square) + fixtures

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

### Task 4: GCP service-account JSON + kubeconfig fixtures (verify coverage)

**Files:**
- Create: `internal/classify/testdata/corpus/positive/gcp-service-account.json`
- Create: `internal/classify/testdata/corpus/positive/kubeconfig.yaml`
- Create: `internal/classify/testdata/corpus/negative/k8s-public-config.yaml`

These structured formats should already be covered by existing detectors (GCP SA JSON embeds a PEM `PRIVATE KEY` → Detector A; kubeconfig carries a `token:`/`password:` → Detector C). This task adds the fixtures to PROVE that and acts as a regression guard. If a positive misses, the fix belongs in Detector A or C (and is allowed within this task); do not add a bespoke one-off detector.

- [ ] **Step 1: Add the GCP service-account positive (PEM private key embedded in JSON)**

`internal/classify/testdata/corpus/positive/gcp-service-account.json`:
```json
{
  "type": "service_account",
  "project_id": "demo-project",
  "private_key_id": "0123456789abcdef0123456789abcdef01234567",
  "private_key": "-----BEGIN PRIVATE KEY-----\nMIIBVAIBADANBgkqhkiG9w0BAQEFAASCAT4wggE6AgEAAkEAExampleExampleExample\n-----END PRIVATE KEY-----\n",
  "client_email": "demo@demo-project.iam.gserviceaccount.com"
}
```

- [ ] **Step 2: Add the kubeconfig positive (bearer token under a secret-ish key)**

`internal/classify/testdata/corpus/positive/kubeconfig.yaml`:
```yaml
apiVersion: v1
kind: Config
clusters:
- cluster:
    server: https://10.0.0.1:6443
  name: prod
users:
- name: admin
  user:
    token: kFh9Lm2Qp7Rt4Vx1Zc6Bn3Ws8Yd0Ja5Ke
```

- [ ] **Step 3: Add a benign k8s config negative (no credentials)**

`internal/classify/testdata/corpus/negative/k8s-public-config.yaml`:
```yaml
apiVersion: v1
kind: Config
clusters:
- cluster:
    server: https://10.0.0.1:6443
  name: prod
contexts:
- context:
    cluster: prod
    user: admin
  name: prod
current-context: prod
```

- [ ] **Step 4: Run the full classify suite**

Run: `go test ./internal/classify/ -v`
Expected: PASS. The GCP fixture is caught by the PEM detector (Detector A matches `-----BEGIN PRIVATE KEY-----` even with escaped `\n`), the kubeconfig by Detector C (`token` is secret-ish; the value clears length+entropy). The benign k8s config has no secret-ish key with a high-entropy value, so it stays benign. If the kubeconfig misses, verify `token` matches `SecretishKeyName` and the value clears `minSecretLen`/`minSecretEntropy`; adjust thresholds in `generic.go` if needed (must keep all negatives green).

- [ ] **Step 5: Commit**

```bash
git add internal/classify/testdata/corpus/
git commit -m "test(classify): GCP service-account + kubeconfig coverage fixtures

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

### Task 5: Final sweep — full build, vet, whole-suite, baseline doc note

**Files:**
- Modify: `internal/classify/classifier.go` (only if a doc comment needs updating after the pipeline change)

This task verifies the whole repository is green and the detector additions did not regress the agent tests, and records the corpus result. No new behavior.

- [ ] **Step 1: Run the entire repo build, vet, and tests**

Run: `go build ./... && go vet ./... && go test ./...`
Expected: PASS across all packages (including `internal/agent` and `e2e`, which depend on the classifier).

- [ ] **Step 2: Capture the corpus precision/recall line**

Run: `go test ./internal/classify/ -run TestCorpus -v 2>&1 | grep 'corpus:'`
Expected: a single line `corpus: positives=N hit=N (recall=1.000) negatives=M falsePos=0 (precision=1.000)`. Confirm `recall=1.000` and `falsePos=0`.

- [ ] **Step 3: Verify the `ClassifyBuf` doc comment still matches behavior**

Open `internal/classify/classifier.go`. The doc comment on `ClassifyBuf` (around the function) describes the pipeline. If it still says only "Returns the highest-confidence finding" that remains accurate; if it enumerates only PEM + provider stages, append a sentence noting the generic key/value fallback. Keep it to one sentence; do not restructure the comment.

- [ ] **Step 4: Commit (only if Step 3 changed the comment)**

```bash
git add internal/classify/classifier.go
git commit -m "docs(classify): note generic detector in ClassifyBuf comment

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

If Step 3 made no change, skip the commit.

---

## Self-Review

**Spec coverage:**
- §3 detector pipeline (A PEM, B provider, C generic, D pkcs12) → A/B exist; C = Task 2; provider expansion (B) = Task 3. **Detector D (PKCS#12) is intentionally deferred/dropped here** — see note below.
- §4 generic detector (extraction + 4 gates + 0.8 confidence + dormant helpers wired) → Task 2 (`generic.go`, all four gates, reuse of `entropy.go`/`denoise.go`). ✓
- §5 provider expansion → Task 3. ✓
- §6 PKCS#12 → **see PKCS#12 note**.
- §7 corpus layout + harness + zero-FP/100%-recall pass + label assertions → Task 1 (harness + recall/precision), Tasks 2-4 (fixtures). **Label-assertion table** folded into the harness expectations; added explicitly below.
- §7.1 cert/key stance (public cert benign, private key secret) → `public-cert.pem` negative (Task 1) + `id_rsa.pem`/GCP positives. ✓
- §8 improvement loop → Tasks ordered baseline→C→providers→structured, tune thresholds. ✓
- §10 limits → encoded as design choices (key-name gate in Task 2 Step 3). ✓

**PKCS#12 note (spec §6 / Detector D):** §6 explicitly allows dropping Detector D if it cannot separate `.p12` keystores from plain DER certs reliably from bytes. Distinguishing them from a 4 KiB byte window is unreliable (both lead with `30 82` SEQUENCE), so per the spec's own fallback this plan does NOT implement Detector D and does not add `.p12`/`.pfx` positive fixtures. `.p12`/`.pfx` coverage is left to path-tier policy (documented limit L-C3). This is a faithful application of §6, not a gap.

**Label-assertion table (spec §7.2) — add to Task 2 as an extra test** to lock detector attribution. Append to `internal/classify/corpus_test.go` (can be added in Task 1 Step 3 or Task 2; placed here so it is not lost):
```go
func TestCorpus_DetectorLabels(t *testing.T) {
	c := New()
	cases := map[string]string{ // file under testdata/corpus/positive → expected Match
		"aws-access-key.env":     "aws-access-key",
		"generic-api-token.json": "generic-credential",
		"id_rsa.pem":             "pem-private-key",
	}
	for file, want := range cases {
		p := "testdata/corpus/positive/" + file
		v := c.ClassifyBuf(readHead(t, p))
		if v.Match != want {
			t.Errorf("%s: want Match %q, got %q (reason=%q)", file, want, v.Match, v.Reason)
		}
	}
}
```
The implementer should add this test in Task 2 Step 1 (it references `generic-credential`, introduced in Task 2). The `aws-access-key.env` and `id_rsa.pem` files exist from Task 1.

**Placeholder scan:** No TBD/TODO/"handle edge cases". Every code step shows full code. Thresholds are concrete (`minSecretLen=12`, `minSecretEntropy=3.0`).

**Type consistency:** `kvPair{key,value}`, `extractPairs`, `classifyGeneric`, `Verdict{Match,Value,Confidence,Reason}`, `Match:"generic-credential"`, `SecretishKeyName`/`IsPlaceholder`/`IsBooleanOrNumeric`/`IsURLWithoutEmbeddedCreds`/`ShannonEntropy`, `MaxScanBytes`, `New`/`ClassifyBuf` are used consistently across Tasks 1-5 and match the existing API.
