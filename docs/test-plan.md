# scdlp v1 core — manual test plan

This plan walks you through verifying everything that landed in v1 core. The daemon runs against `MockHook` today, so **you cannot yet test real `open()` interception** — that comes with the ESF System Extension follow-up. What you CAN test:

1. The build is clean.
2. The unit + e2e suites pass on your machine.
3. The decision-path P99 is within budget.
4. Process identity (exe + ancestry via libproc) resolves correctly.
5. The classifier flags real secret strings and ignores plain config.
6. The daemon ↔ CLI loop works end-to-end (`status`, `list`, `add`, `revoke`, `tail`).
7. The Shai-Hulud reenactment denies the malicious chain and allows the legit one.

All commands assume you're in `/Users/ronreiter/GitHub/scdlp`.

---

## 0. Prereqs

```bash
cd /Users/ronreiter/GitHub/scdlp
go version           # need 1.24+
xcode-select -p      # need /Applications/Xcode.app/... or /Library/Developer/CommandLineTools
```

Expected: Go ≥ 1.24, Xcode tools present (needed for cgo libproc).

---

## 1. Clean build

```bash
task clean && task build
```

**Pass criteria:** no errors. Produces `bin/scdlp-agent` and `bin/scdlp`.

```bash
ls -lh bin/
```

Expected: both binaries, ~10 MiB each.

---

## 2. Full test suite

```bash
task test
```

**Pass criteria:** `54 passed in 11 packages`. No `FAIL`.

If you want package-by-package detail:

```bash
go test ./... -v 2>&1 | grep -E '^(---|=== RUN|PASS|FAIL|ok|FAIL)'
```

Watch for these key tests:

- `TestClassifyBuf_AWSKey`, `..._GitHubPAT`, `..._PEMPrivateKey`, `..._SentryToken` — classifier
- `TestMatcher_AWSCredentials`, `..._SSHPublicKeySkipped`, `..._DotEnvExampleSkipped` — path tier
- `TestCompute_DeterministicKey`, `..._OrderMatters` — identity hashing
- `TestStore_Lookup_PathBeatsCategory`, `..._ExpiredIgnored` — rule precedence
- `TestEngine_ProtectedNoRule_Denies_AndEmitsPrompt`, `..._ProtectedWithAllowRule`, `..._WriteOnlyFastAllow` — engine
- `TestEndToEnd_AddRevoke`, `..._TailAudit`, `TestReadFrame_RejectsOversizedLength` — IPC
- `TestShaiHulud_DeniesPostinstall` — full E2E

---

## 3. Performance assertion

```bash
go test ./internal/agent -run P99 -v
```

**Pass criteria:** PASS, with a log line like `p50=60µs p95=80µs p99=150µs`. Spec budget is 200 µs; the test allows up to 1 ms before failing.

Optional benchmark for raw throughput:

```bash
task bench
```

Expected: `BenchmarkDecide_Tier1Deny` reports something like `60-80 µs/op`.

---

## 4. Process identity smoke test

Verify the cgo libproc walker actually resolves the parent chain on YOUR machine:

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
	if err != nil {
		panic(err)
	}
	fmt.Printf("exe:   %s\n", id.Exe)
	fmt.Printf("chain: %v\n", id.Chain)
	fmt.Printf("key:   %s\n", id.KeyHex)
	fmt.Printf("human: %s\n", id.HumanChainStr())
}
EOF
go run /tmp/idsmoke.go
```

**Pass criteria:**
- `chain` has ≥ 3 entries
- Last entry is `/sbin/launchd`
- Walks through your terminal app (e.g. `/Applications/Utilities/Terminal.app/...` or iTerm)
- `key` is exactly 64 hex chars
- `human` shows the same chain with `←` separators

---

## 5. Daemon + CLI loop

In **terminal A** start the daemon:

```bash
./bin/scdlp-agent \
    --rules /tmp/scdlp-rules.db \
    --audit /tmp/scdlp-audit.db \
    --socket /tmp/scdlp.sock \
    --home "$HOME"
```

Expected: `scdlp-agent up: socket=/tmp/scdlp.sock rules=/tmp/scdlp-rules.db audit=/tmp/scdlp-audit.db` and the process stays in the foreground.

In **terminal B**:

```bash
export SCDLP_SOCKET=/tmp/scdlp.sock

# 5a. status
./bin/scdlp status
```

Expected: `healthy: true`, `mode: enforce`, `rules total: 0`, `uptime (s): <small int>`.

```bash
# 5b. add a rule
./bin/scdlp add \
  --file-key aws-credentials --file-kind category \
  --identity-key chaintest --identity-kind chain \
  --verdict allow
```

Expected: `rule 1 added`.

```bash
# 5c. list rules
./bin/scdlp list
```

Expected: a row with `ID=1`, `VERDICT=allow`, `FILE_KEY=aws-credentials`, `ID_KIND=chain`, identity truncated.

```bash
# 5d. revoke
./bin/scdlp revoke 1
./bin/scdlp list
```

Expected: revoke returns silently. Second `list` shows only the header.

```bash
# 5e. tail (nothing in audit yet)
./bin/scdlp tail
```

Expected: empty (or just nothing prints).

```bash
# 5f. error path: add without --verdict
./bin/scdlp add --file-key x --identity-key y
```

Expected: error `--verdict must be allow or deny`, exit 1.

Stop the daemon: `Ctrl-C` in terminal A. Expected: `scdlp-agent shutting down`.

---

## 6. Classifier ad-hoc smoke

The CLI doesn't expose the classifier directly (it runs inside the daemon's hot path), but you can drive it from a one-liner:

```bash
cat > /tmp/clsmoke.go <<'EOF'
package main

import (
	"fmt"
	"os"

	"github.com/ronreiter/scdlp/internal/classify"
)

func main() {
	c := classify.New()
	for _, p := range os.Args[1:] {
		b, err := os.ReadFile(p)
		if err != nil {
			fmt.Printf("%s: error: %v\n", p, err)
			continue
		}
		v := c.ClassifyBuf(b)
		fmt.Printf("%s: secret=%v match=%q confidence=%.2f reason=%q\n",
			p, v.IsSecret(), v.Match, v.Confidence, v.Reason)
	}
}
EOF

# Test cases:
echo "[default]
aws_access_key_id = AKIAIOSFODNN7EXAMPLE" > /tmp/fake-aws
echo "host = example.com
port = 5432" > /tmp/plain-config
echo "-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEA..." > /tmp/fake-pem

go run /tmp/clsmoke.go /tmp/fake-aws /tmp/plain-config /tmp/fake-pem
```

Expected output (exact match strings, confidence 1.00 on secrets, 0.00 on plain):

```
/tmp/fake-aws:     secret=true  match="aws-access-key"  confidence=1.00 ...
/tmp/plain-config: secret=false match=""                confidence=0.00 ...
/tmp/fake-pem:     secret=true  match="pem-private-key" confidence=1.00 ...
```

---

## 7. Manual Shai-Hulud walkthrough (in-process)

The automated E2E test already exercises this, but if you want to watch it happen yourself in the daemon + CLI:

The daemon currently exposes no public way to inject `MockHook` events from the CLI (it would defeat the purpose of the hook abstraction). For now the trustworthy interactive demo is the **automated** test:

```bash
go test ./e2e -run Shai -v
```

Expected: `--- PASS: TestShaiHulud_DeniesPostinstall (~10ms)`.

Walk through the test source at `e2e/shaihulud_test.go` to see exactly what gets exercised:

1. Build a fake `~/.aws/credentials` in a tempdir.
2. Inject a `MockHook` event from PID 4242 (`node ← sh ← npm ← node`) → engine returns DENY, prompt fires.
3. CLI adds an allow-rule for the legitimate chain (`aws ← zsh ← Terminal`).
4. Inject an event from PID 1 (legit `aws`) → engine returns ALLOW.
5. Inject the postinstall event again → still DENY.
6. Verify audit log has ≥ 3 rows.

---

## 8. What you CANNOT test yet

These need the ESF System Extension follow-up (Apple entitlement + Xcode work):

- Real `open()` calls on your filesystem being intercepted by the kernel.
- The macOS notification prompt rendered to the user.
- The "Allow once" / "Allow always" buttons.
- System Extension install / uninstall through System Settings.
- Notarization / Gatekeeper approval flow.

Until then the daemon is a pure-Go simulator of the decision pipeline, and the `MockHook` is the only event source.

---

## Quick "everything works" one-liner

If you just want a single yes/no answer:

```bash
task clean && task build && task test && \
    echo && echo "✅ scdlp v1 core: all green"
```

Pass = the echo line prints. Fail = the build or tests stop before reaching it.
