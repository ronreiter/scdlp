# scdlp — classification corpus + layered secret detectors

**Author:** Ron Reiter
**Date:** 2026-06-05
**Status:** Design accepted, implementation queued

## 1. Goal

Build a comprehensive, file-based test corpus of realistic secret-bearing and
benign documents (`.env`, JSON, YAML, `.npmrc`, cloud credentials, private keys,
certificates, …), then improve `internal/classify` until it detects every secret
in the corpus with **zero false positives** on the benign files.

Two deliverables, tightly coupled:
1. A positive/negative corpus under `internal/classify/testdata/corpus/` plus a
   harness (`corpus_test.go`) that enforces the pass criterion and reports
   precision/recall.
2. New/expanded detectors in `internal/classify` that make the harness green:
   an expanded provider table, a generic key/value credential heuristic (wiring
   in the currently-dormant entropy/denoise helpers), and a best-effort PKCS#12
   detector.

## 2. Scope and non-goals

- The engine entry point stays `Classifier.ClassifyBuf(buf []byte) Verdict`,
  scanning the first `MaxScanBytes` (4096) bytes and reducing to
  `Verdict.IsSecret()` (`Confidence >= 0.6`). No change to the agent decision
  path or to how `ClassifyBuf` is called.
- **Private key material is a secret; public certificates are not.** PEM
  `PRIVATE KEY` headers and PKCS#12 keystores (which embed a private key) are
  flagged. A standalone `-----BEGIN CERTIFICATE-----` or `PUBLIC KEY` is public
  and stays benign.
- Detection remains content-only (bytes in, verdict out). No path/extension
  input, no network, no ML, no persisted state.
- All corpus secrets are **synthetic** — well-known example/test values or
  freshly generated throwaway keys. No real credentials, ever.
- Not changing the 4 KiB window, the `0.6` threshold, or `Verdict`'s shape.

## 3. Detector pipeline

`ClassifyBuf` runs detectors in order and returns the highest-confidence
`Verdict`. An empty buffer is non-secret; buffers > 4096 bytes are truncated
(both unchanged).

| # | Detector | Confidence | Notes |
|---|----------|-----------|-------|
| A | PEM private key header (`PEMPrivateKeyRe`) | 1.0 | Existing. Header-only (body may be truncated). Public CERTIFICATE/PUBLIC KEY not matched. |
| B | Provider prefix (Aho-Corasick) → provider regex | 1.0 full / 0.4 prefix-only | Existing, expanded table (§5). |
| C | Generic key/value credential heuristic | 0.8 | New (§4). Catches unknown secrets in env/JSON/YAML/ini. |
| D | PKCS#12 keystore marker | 1.0 | New, best-effort (§6). Dropped if unreliable on the corpus. |

Pass-1 PEM and a full provider-regex match short-circuit at 1.0 as today. C and
D only need to push qualifying files to `>= 0.6`; they do not need to outrank a
1.0 hit.

## 4. Detector C — generic credential heuristic

This is the recall lever for secrets with no known provider prefix (e.g.
`aws_secret_access_key`, a custom `API_TOKEN`, a `password` field in JSON). It
reuses the existing but currently-unwired helpers in `entropy.go` and
`denoise.go`.

### 4.1 Pair extraction

A format-tolerant extractor pulls candidate `(key, value)` pairs from the raw
buffer, covering the two dominant shapes:
- `KEY=VALUE` — `.env`, `.ini`, `.npmrc`, AWS `credentials`.
- `"key": "value"` / `key: value` — JSON and YAML.

Implementation: a single regex that captures an identifier-ish key (letters,
digits, `_`, `-`, `.`) followed by `=` or `:`, then a value that is either
quoted (`"…"` / `'…'`) or a bare run up to whitespace/`,`/`}`. Values are
unquoted before evaluation. The extractor is bounded to the 4 KiB window and
caps the number of pairs examined (e.g. 256) to keep the hot path fast. This is
deliberately a lexical scan, not a real JSON/YAML parser — it must tolerate
truncated/partial documents.

### 4.2 Gating

A pair is flagged as a secret only when **all** of these hold:
1. `SecretishKeyName(key)` is true — the key name implies a credential
   (`token|secret|password|passwd|api[_-]?key|access[_-]?key|client[_-]?secret|auth|credential|private[_-]?key`).
2. The value survives denoising: not `IsPlaceholder`, not `IsBooleanOrNumeric`,
   and not `IsURLWithoutEmbeddedCreds`.
3. `len(value) >= minSecretLen` (default **12**).
4. `ShannonEntropy(value) >= minSecretEntropy` (default **3.0** bits/byte).

On a match: `Verdict{Match: "generic-credential", Value: value, Confidence:
0.8, Reason: "secret-ish key + high-entropy value: " + key}`.

Requiring a secret-ish **key name** as the primary gate (rather than entropy
alone) is what keeps false positives near zero: a high-entropy value under a
benign key — a content hash, UUID, git SHA, lockfile `integrity` field — is not
flagged because its key does not match. Thresholds in 4.2.3–4.2.4 are starting
points; §7 tunes them against the negative corpus.

## 5. Provider table expansion

Add common providers to `prefixes.go` and matching validation regexes to
`patterns.go`, following the existing two-table pattern (literal prefix anchors
+ `^prefix…shape…$` validation regex). Candidate additions (final set validated
against the corpus): Twilio (`SK…`, `AC…`), DigitalOcean (`dop_v1_`), Datadog,
Postmark, Square (`sq0atp-`, `sq0csp-`), Shopify (`shpat_`, `shpss_`), Azure
storage `AccountKey=` base64, GitLab/GitHub/Slack/OpenAI/Stripe/Google/npm/HF/
Sentry/SendGrid (already present). Every added provider gets at least one
positive corpus fixture.

## 6. Detector D — PKCS#12 keystore (best-effort)

`.p12`/`.pfx` files embed a private key and should be secrets. They are
DER-encoded PKCS#12, which is hard to distinguish from other DER (e.g. a DER
certificate) by leading bytes alone. Detector D looks for the PKCS#12 structure
signature within the window — the ASN.1 OID for `pkcs-12` /
`pkcs7-encryptedData` / the `1.2.840.113549.1.12` arc — rather than relying on
the generic `SEQUENCE` prefix. If, against the corpus, this cannot separate
`.p12` keystores from plain DER certificates with acceptable precision, Detector
D is dropped and PKCS#12 coverage is documented as a limit rather than shipping
a flaky matcher. PEM-encoded private keys inside `.pfx`-adjacent files are
already covered by Detector A.

## 7. Test corpus and harness

### 7.1 Layout

```
internal/classify/testdata/corpus/
  positive/        # every file here MUST classify as IsSecret() == true
    aws-credentials.env
    gcp-service-account.json
    kubeconfig.yaml
    npmrc-with-token.npmrc
    id_rsa.pem
    stripe-test.env
    github-pat.env
    jwt.txt
    generic-api-token.json
    ...
  negative/        # every file here MUST classify as IsSecret() == false
    placeholder.env          # changeme / your-token-here / ${VARS}
    public-cert.pem          # -----BEGIN CERTIFICATE-----
    plain-config.json        # ports, log levels, feature flags
    hashes-and-uuids.json    # sha256, git SHA, UUIDs under benign keys
    package-lock-integrity.json
    booleans-numbers.env
    db-url-no-creds.env
    ...
```

All fixtures use synthetic values: AWS example key
(`AKIAIOSFODNN7EXAMPLE` / `wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY`), Stripe
`sk_test_…`, fake-but-correctly-shaped GitHub PATs, a sample JWT, and throwaway
RSA/OpenSSH keys generated for the corpus.

### 7.2 Harness (`internal/classify/corpus_test.go`)

- Walks `testdata/corpus/positive` and `…/negative`, reads each file's first
  `MaxScanBytes` bytes, runs `ClassifyBuf`, and checks `IsSecret()` against the
  directory's expectation.
- On any miss (positive not detected) or false positive (negative flagged), the
  test fails and prints the offending file paths and each one's `Verdict`
  (Match/Confidence/Reason).
- Always prints a precision/recall summary: counts, recall over positives,
  precision over the union, and the false-positive list.
- A small separate table-driven test asserts the exact `Match` label for a
  handful of representative positives (e.g. AWS fixture → `aws-access-key`,
  generic fixture → `generic-credential`) to lock in detector attribution, not
  just the boolean.

### 7.3 Pass criterion

Green = **100% recall on `positive/` and 0 false positives on `negative/`**, and
the label assertions hold. This is the definition of done for the engine work.

## 8. Improvement loop

1. Land the corpus + harness; run against today's engine to capture a baseline
   (expected: providers/PEM pass; most generic and JSON cases miss).
2. Implement Detector C; re-run; tune `minSecretLen`/`minSecretEntropy` so every
   positive is caught without tripping any negative.
3. Expand the provider table (§5) for any provider-specific positives still
   missed; add Detector D (§6) for `.p12`/`.pfx`, or drop it per its fallback.
4. Iterate until §7.3 is green. The corpus is the spec for "good".

## 9. File structure

- `internal/classify/generic.go` — Detector C: pair extractor + gated heuristic;
  the tuning constants `minSecretLen`, `minSecretEntropy`. Reuses
  `entropy.go`/`denoise.go` (no longer test-only).
- `internal/classify/classifier.go` — orchestration only: add C and D to the
  ordered pipeline; remains the thin coordinator.
- `internal/classify/prefixes.go`, `patterns.go` — expanded provider tables.
- `internal/classify/pkcs12.go` — Detector D (only if it survives §6).
- `internal/classify/testdata/corpus/{positive,negative}/**` — fixtures.
- `internal/classify/corpus_test.go` — the corpus harness + label table.

## 10. Limits

- **L-C1.** Detector C gates on a secret-ish key name; a high-entropy secret
  stored under a non-suggestive key (e.g. `"x": "<random>"`) and with no known
  provider prefix is not caught. This is the deliberate precision/recall trade
  that keeps the zero-FP bar achievable on hashes/UUIDs.
- **L-C2.** 4 KiB window: a secret beyond offset 4096 (with a benign head) is
  missed, as everywhere else in scdlp.
- **L-C3.** PKCS#12 detection is best-effort and may be dropped (§6); when
  dropped, `.p12`/`.pfx` rely on path-tier policy, not content classification.
- **L-C4.** The generic extractor is lexical, not a real parser; exotic encodings
  (deeply nested/!escaped JSON, multiline YAML block scalars) may not yield a
  clean value. The provider and PEM detectors still apply to the raw bytes.
- **L-C5.** Detection remains a fixed, deterministic rule set; novel provider
  formats require adding a prefix/pattern (and a fixture).
