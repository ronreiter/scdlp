# scdlp — content-scan auto-allow for benign protected files

**Author:** Ron Reiter
**Date:** 2026-06-04
**Status:** Design accepted, implementation queued

## 1. Goal

Wire the existing 4 KiB secret classifier (`internal/classify`) into the decision
engine so that a file whose path matched a `prompt` glob but whose first 4 KiB
contains **no secret** is allowed through silently, instead of denying-first and
nagging the user with an approval prompt.

The path globs (`~/.aws/**`, `~/.ssh/**`, `**/*.env`, …) are deliberately coarse;
they flag *candidate* secret files by location. A file that lives at such a path
but contains no actual credential is a false positive of that coarse match.
Content-scanning lets us suppress the prompt for those false positives while
still defaulting-deny for files that really do hold secrets.

## 2. Scope and non-goals

- Content scanning runs **only** on files a `prompt` glob already flagged as
  potentially dangerous, and **only** when no explicit allow/deny rule exists for
  the (file, identity) pair. It never runs on `ignore`/`allow`/`block`-policy
  files, on trusted-chain reads, or on files no glob matched.
- A clean scan allows the current open but **persists nothing**. There is no
  auto-created rule, no cache, no schema change. Every open of a benign
  protected file is re-scanned. The only thing that suppresses future scans of a
  file is an *explicit* user-granted allow rule (the existing prompt → "Allow
  Always" flow).
- No changes to the `rules` store, its SQLite schema, or the IPC layer.
- `ActionBlock` files remain a hard block — content scanning does not soften them.

## 3. Why re-scan every time instead of caching

Persisting a path-allow after a clean scan would let an attacker who later writes
a credential into an already-greenlit path bypass inspection (a TOCTOU window).
Re-scanning on every open closes that window: a file that is benign now but gains
a secret later is denied on the very next open.

The cost is a 4 KiB read on each open of an in-scope benign file. This is
acceptable: the `prompt`-glob set is narrow, and after the first read the bytes
are warm in the OS page cache, so the marginal read is cheap relative to the ES
deadline budget. The agent runs as root (System Extension), so it can always
read the head regardless of the calling process's own permissions.

## 4. Design

### 4.1 Engine configuration (`internal/agent/engine.go`)

`agent.Config` gains two fields:

```go
// Classifier runs the 4 KiB secret scan on path-flagged files before
// prompting. Nil ⇒ content scanning is disabled and the engine behaves
// exactly as it did before this feature (deny-first + prompt on unmatched
// in-scope reads).
Classifier *classify.Classifier

// ReadHead returns up to the first 4 KiB of the file at path. Injectable so
// the engine is testable under MockHook without touching disk. Nil ⇒ a
// default reader that opens the path and reads ≤4096 bytes.
ReadHead func(path string) ([]byte, error)
```

`New` installs the default `ReadHead` (open the file, read ≤4096 bytes, close)
when the field is nil. `Classifier` is **not** defaulted — leaving it nil is the
documented off-switch that preserves prior behavior and keeps existing tests
green.

The default reader reads at most `maxScanBytes` (4096) bytes — matching the
classifier's own scan window — and returns whatever it read plus any error. A
zero-byte successful read returns an empty slice and a nil error.

### 4.2 Decision flow (`decideInner`)

The only changed branch is `ActionPrompt`'s `default:` case — reached when a
`prompt` glob matched the path and `Rules.Lookup` returned no rule. Today that
case does: helper-present check → reprompt cooldown → deny-first + publish
prompt. The new logic runs **first**, at the top of that `default:` case:

```
if cfg.Classifier != nil:
    buf, err := readHead(ev.Path)
    if err == nil and not Classifier.ClassifyBuf(buf).IsSecret():
        audited.Verdict = "allow-clean"
        return Allow, audited        // no rule written
    // err != nil (read failed / file vanished)  → fall through (fail safe)
    // secret found                              → fall through
// existing behavior: HelperPresent → cooldown → deny + prompt
```

Decision table for the `default:` case:

| Classifier | Head read | `IsSecret()` | Result |
|---|---|---|---|
| nil | — | — | existing deny-first + prompt |
| set | error | — | existing deny-first + prompt (fail safe) |
| set | ok | false | **Allow**, audit `allow-clean`, no rule |
| set | ok | true | existing deny-first + prompt |

A successfully-read empty file yields `ClassifyBuf([]) → not a secret`, so it is
allowed — it genuinely contains no credential.

All earlier branches of `decideInner` (kill switch, write-only fast-skip,
`ActionIgnore`/`ActionAllow`, identity resolve, trusted chain, `ActionBlock`,
and existing allow/deny rule hits) are unchanged.

### 4.3 Agent wiring (`cmd/scdlp-agent`)

Construct one `classify.New()` at startup (it is safe for concurrent use) and
pass it into the engine `Config.Classifier`. `ReadHead` is left nil to use the
default disk reader.

## 5. Audit and observability

Clean allows are recorded with verdict `allow-clean` and the matched glob in
`MatchedKind`/`FileKey`, so `scdlp tail` / history can distinguish a
content-scan pass from a policy `allow` or a rule-based allow. No new audit
fields are required.

## 6. Performance

- Content scan adds one `open`+`read`(≤4 KiB)+`close` plus a `ClassifyBuf` call
  to the hot path, **only** for `prompt`-flagged files with no existing rule.
- The classifier is the same Aho-Corasick + regex pipeline already benchmarked
  in `internal/classify`; on 4 KiB it is microsecond-scale.
- Subsequent opens of the same benign file re-incur the read, but from the page
  cache. Files with an explicit user allow rule short-circuit before the scan at
  `Rules.Lookup`, as today.

## 7. Testing

Engine tests (`internal/agent/engine_test.go`) using `MockHook` and an injected
`ReadHead`:

- **Benign protected file:** path matches a `prompt` glob, `ReadHead` returns
  bytes with no secret → expect `Allow`, audit verdict `allow-clean`, and assert
  `Rules.Insert` was **never** called.
- **Secret in protected file:** `ReadHead` returns bytes containing a secret
  (e.g. a PEM header or a real AWS-key-shaped token) → expect `Deny` and a
  prompt published on the bus (existing behavior).
- **Read failure:** `ReadHead` returns an error → expect `Deny` + prompt (fail
  safe).
- **Classifier disabled:** `Classifier == nil` → existing deny-first + prompt;
  `ReadHead` is never invoked.
- **Explicit allow still wins:** an allow rule for the (file, identity) returns
  `Allow` at `Rules.Lookup` without invoking `ReadHead`/the classifier.

Reuse the existing classifier unit tests for detection correctness; engine tests
assert only the wiring/branching.

## 8. Limits

- **L-CS1.** A clean scan inspects only the first 4 KiB. A file whose secret
  sits past offset 4096 with a benign head is allowed. This matches the
  classifier's documented scan window and the project's `maxScanBytes` budget;
  the same window is used everywhere else in scdlp.
- **L-CS2.** Stage-1 prefix-only matches score 0.4, below the 0.6 `IsSecret`
  threshold, so a provider prefix with no matching token shape is treated as
  benign and allowed. This is the existing classifier threshold semantics,
  applied unchanged.
- **L-CS3.** Re-scanning every open is intentional (no persisted auto-allow);
  it trades a per-open page-cache read for closing the TOCTOU window described
  in §3.
