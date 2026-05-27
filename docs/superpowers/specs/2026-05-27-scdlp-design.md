# scdlp — supply-chain DLP for macOS

**Author:** Ron Reiter
**Date:** 2026-05-27
**Status:** Design accepted, implementation queued

## 1. Goal

A macOS endpoint agent that prevents supply-chain attacks from reading credentials. The agent hooks every file open with Apple's Endpoint Security Framework (ESF), synchronously classifies the file's first 4 KiB to decide whether it contains secrets, and — for files that do — enforces a per-(file, process-identity) allowlist. Unknown (process, file) pairs are denied immediately; the user is prompted to approve future access.

Stasher already solves a related slice of this problem with macFUSE around `.env` files. scdlp is the kernel-event-driven sibling: any file, any path, any open — not just FUSE-mounted ones.

## 2. Non-goals

- Linux or Windows. macOS-only. (Stasher covers Linux for the FUSE flavor.)
- Cloud control plane, fleet enrollment, central policy push. Single-machine, local-only.
- Detection of secrets being *written* or *exfiltrated over network*. Read-side block only.
- Protection against in-process exploitation of an allowlisted binary (a malicious VS Code extension running inside an allowed `Electron` process is out of scope — same caveat as stasher's L1).
- Detection by behavioral ML, anomaly scoring, or cloud reputation. Deterministic rules only.
- Replacement of stasher. scdlp can coexist; stasher's FUSE view of `.env` files still works because FUSE reads also fire ESF `AUTH_OPEN` events.

## 3. Threat model

| # | Threat | Defended by |
|---|---|---|
| T1 | npm/pip/cargo postinstall reads `~/.aws/credentials` or `~/.ssh/id_*` | Ancestry-chain identity: `node → sh → cat ~/.aws/credentials` does not match the rule for `Terminal → zsh → cat`, denied. |
| T2 | Postinstall script invokes a legitimate signed binary (`aws s3 ls`) to read creds as a confused deputy | Same: identity includes parent chain, so `node → sh → aws` is a different rule than `Terminal → zsh → aws`. |
| T3 | Dropped binary from `/tmp` or `~/Downloads` reads protected file | First read → not on allowlist → DENY + prompt. User sees clearly suspicious origin path and denies. |
| T4 | Known scanner (TruffleHog, Gitleaks) run by an attacker | Same default-deny + prompt. (Compare stasher's hash-based R5; in scdlp the binary path will be unfamiliar to the rule set and trip a prompt.) |
| T5 | Re-opening the same secret file via a syscall that bypasses `open()` | Subscribe to all ES events that yield a vnode and a process — `AUTH_OPEN`, `AUTH_CLONE`, `AUTH_COPYFILE`, `AUTH_RENAME` (destination read), `AUTH_TRUNCATE` (not a read but logged). |
| T6 | Reading via `/dev/diskN` raw to bypass file-level enforcement | **Out of scope** — documented limit. Mitigation guidance: keep FileVault on. |
| T7 | Agent itself tampered with on disk | Agent binary lives in `/Library/SystemExtensions/...` owned by root; ESF System Extension is code-signed and notarized; tamper detection is delegated to macOS Gatekeeper + the System Extension validity check. |
| T8 | Process spoofs its parent by `posix_spawn` with a custom `_posix_spawnattr_setpgroup` etc. | ESF `audit_token_t` is set by the kernel at exec time and cannot be spoofed from user space. We use audit tokens, never `getppid()`. |

### Explicit limits (Lx)

- **L1.** In-process malicious code inside an allowlisted process (malicious VS Code extension, malicious shell function, malicious Python module imported by an allowed Python process) — out of scope.
- **L2.** Reading the file from another user account / via `sudo` to a different uid where the allowlist is empty — first such read prompts; if the user denies, attack stops. If user is the attacker, no protection.
- **L3.** A process that hot-patches itself (PT_TRACE_ME → mprotect → JIT shellcode that calls `read`) is still the same process from ESF's point of view; if it's allowlisted, it can read. Mitigation: keep allowlist scopes narrow.
- **L4.** Symlink races between classification and open: ESF gives us the *resolved* target path in `event.open.file.path`, so a `creat()` → `symlink()` race cannot trick the classifier into looking at one file while the kernel opens another.
- **L5.** macOS will eventually deny the AUTH event automatically if we take longer than `ES_HANDLER_TIMEOUT` (~20 s). We engineer the hot path for P99 < 200 µs.
- **L6.** A new user on first install is going to see a burst of prompts as their legitimate workflows hit canonical secret files. We accept this as the cost of default-deny and provide a "tail prompts" CLI to make it tolerable.
- **L7.** ESF is not available in macOS recovery, Apple Silicon DFU, or on systems where the user has disabled SIP/AMFI. We don't try to protect those modes.
- **L8.** Endpoint Security entitlement (`com.apple.developer.endpoint-security.client`) must be obtained from Apple. Acquisition is out-of-band; spec assumes we have it.

## 4. High-level architecture

Three local processes, one SQLite, XPC between them.

```
┌──────────────────────────── kernel ────────────────────────────┐
│   open() / openat() / clonefile() / copyfile_t / renameat()    │
│                            │                                    │
│                            ▼                                    │
│                      ES subsystem                               │
└──────┬─────────────────────────────────────────────────────────┘
       │ AUTH event, must respond <20s, target <200µs P99
       ▼
┌──────────────────────────────────────────────────────────────────┐
│  scdlp-agent  (System Extension, root, com.apple.…endpoint-sec…) │
│   • es_new_client subscribes to AUTH_OPEN + 4 others             │
│   • ProcessIdentity: exe path + ancestry chain (audit tokens)    │
│   • Decision pipeline:                                           │
│       1. Path-tier protected? (canonical paths, globs)           │
│       2. If not tier-1, content-tier: read first 4 KiB, run      │
│          classifier (ported from stasher/internal/classify)      │
│       3. If protected → SQLite lookup by (file_pattern,          │
│          identity_key)                                           │
│       4. Match ALLOW → respond ALLOW                             │
│       5. Match DENY  → respond DENY, audit                       │
│       6. No match    → respond DENY, emit XPC promptRequest      │
│   • Sole writer of /Library/Application Support/scdlp/rules.db   │
│   • XPC listener io.sentra.scdlp.agent                           │
└─────┬─────────────────────────────────────────▲──────────────────┘
      │ XPC promptRequest                       │ XPC promptDecision,
      │ (file, identity_repr, kind, age)        │ adminCommand,
      │                                         │ tailEvent
      ▼                                         │
┌──────────────────────────────┐    ┌───────────┴───────────────────┐
│  scdlp-helper                 │    │  scdlp-cli                    │
│  (LaunchAgent, user session)  │    │  /usr/local/bin/scdlp         │
│                               │    │                               │
│  • Menubar item with badge    │    │  list / status / tail /       │
│  • macOS notification with    │    │  add / revoke / pause /       │
│    Allow / Allow Always /     │    │  resume / doctor              │
│    Deny  / Deny Always        │    │                               │
│  • Recent-events history view │    │  reads SQLite directly;       │
│  • Pure UI, no DB writes      │    │  writes go via XPC            │
└───────────────────────────────┘    └───────────────────────────────┘
```

### Why agent owns the DB

Single writer, no locking gymnastics. A compromised user-space helper cannot silently flip rules. The CLI follows the same pattern: reads-direct, writes-via-XPC.

## 5. Components in detail

### 5.1 scdlp-agent (System Extension)

**Language.** Go, except the ESF client glue which is a thin C/Objective-C shim (cgo) because `libEndpointSecurity` is C-only. Pattern is well-established (Jamf Protect, CrowdStrike use the same). Helper + CLI are pure Go.

**Bundle.** A `.systemextension` packaged inside the helper's `.app` bundle. Activation via `OSSystemExtensionRequest` (the helper triggers activation on first launch). Apple's published path for non-driver System Extensions.

**ES subscriptions.**

```c
es_event_type_t subs[] = {
    ES_EVENT_TYPE_AUTH_OPEN,
    ES_EVENT_TYPE_AUTH_CLONE,
    ES_EVENT_TYPE_AUTH_COPYFILE,
    ES_EVENT_TYPE_NOTIFY_EXEC,     // for ancestry-chain cache hydration
    ES_EVENT_TYPE_NOTIFY_EXIT,     // for cache eviction
};
```

We also use `es_mute_path` aggressively to ignore the system's own internals (`/System/**`, `/usr/share/**`, `/Library/Caches/com.apple.**`, our own DB, etc.) — this cuts event volume by an order of magnitude.

**Hot path.**

```
on AUTH_OPEN(event):
    path     := event.open.file.path           // already resolved by kernel (L4)
    procExe  := event.process.executable.path
    procTok  := event.process.audit_token
    flags    := event.open.fflag

    // Fast skips
    if flags & O_WRONLY == O_WRONLY && flags & O_RDWR == 0:
        return ALLOW                            // write-only, can't exfiltrate
    if isMuted(path):
        return ALLOW
    if size(path) > 16 MiB && not isPathTier1(path):
        return ALLOW                            // skip large non-canonical files
    if isBinaryByMagic(path):                   // ELF, Mach-O, gzip, JPEG, …
        return ALLOW

    // Tier 1 path match
    protected := isPathTier1(path)

    // Tier 2 content scan if needed
    if not protected:
        buf := pread(path, 4096, 0)
        if classify(buf).IsSecret():
            protected = true

    if not protected:
        return ALLOW

    // Protected. Compute identity.
    id := identity(procExe, ancestry(procTok))   // sha256 of joined chain
    fileKey := canonicalize(path)                // ~/.aws/credentials etc.

    verdict := rulesDB.lookup(fileKey, id)
    switch verdict:
        case ALLOW:        return ALLOW
        case DENY:         audit(deny); return DENY
        case UNKNOWN:
            audit(prompt_emitted)
            xpcSend(promptRequest{file: fileKey, idRepr: humanReadable(id), …})
            return DENY                          // block-then-prompt
```

**Performance targets.**

| Stage | Budget (P99) | How |
|---|---|---|
| Mute check | 5 µs | sorted slice + binary search of \~40 prefixes |
| Tier-1 path match | 10 µs | precompiled glob set, longest-prefix first |
| pread of 4 KiB | 30 µs | already in unified buffer cache 99 % of the time |
| Aho-Corasick over 4 KiB | 20 µs | cloudflare/ahocorasick, identical to stasher |
| Regex validation | 5 µs | hits only on AC matches |
| Identity hash | 15 µs | sha256 of \~6 path segments |
| SQLite point lookup | 50 µs | mmap'd DB, prepared statement, indexed |
| XPC send (async) | 0 (fire-and-forget) | |
| **Total P99** | **\~135 µs** | comfortably under 200 µs |

We benchmark this with a `make bench` target that loops one million synthetic events.

**Process identity.**

```go
type Identity struct {
    Exe       string   // /usr/local/bin/aws
    Chain     []string // ["aws","zsh","Terminal","launchd"]
    Key       [32]byte // sha256("aws|zsh|Terminal|launchd")
}
```

The chain is built from `audit_token_t` via `proc_pidinfo(PROC_PIDT_BSDINFO)` walking up `pbi.pbi_ppid` until pid 1. We cache `(pid, exe)` on `NOTIFY_EXEC` and evict on `NOTIFY_EXIT` so we never hit `proc_pidinfo` for live processes.

Depth limit: 8. Past that we collapse the tail to `…`.

**Rule scopes.** When a user clicks "Allow Always", the helper offers three scope choices:

- *Just this file* — rule key is the exact resolved path.
- *All files like this* — rule key is the canonical category (e.g. `aws-credentials`, `ssh-private-key`, `npm-token`). Categories come from a built-in table; this is what makes the prompt UX bearable.
- *Any ancestry, this binary* — chain is ignored, identity is just exe path. The user is explicitly weakening the rule; the helper warns them.

Combinations of these three knobs give 9 rule shapes, all expressible in the schema below.

### 5.2 scdlp-helper (menubar app)

**Language.** Go + Cocoa via `gioui.org` or `fyne.io`? **No.** Tested, supported macOS-native menubar work in pure Go is brittle. Use a Swift/SwiftUI tiny shell that talks to a Go XPC stub via a Unix socket. Practical compromise — Swift for AppKit/NSStatusBar/UNUserNotificationCenter, Go for logic and XPC payload validation. Less code than people fear: \~600 lines of Swift.

**Functions:**

1. Idle in the menubar with a small lock icon. Badge count = pending events in the last 24 h.
2. Receive XPC `promptRequest`. Show `UNUserNotificationCenter` notification with four buttons (Allow / Allow Always / Deny / Deny Always) and a long-press "Details…" that opens an `NSAlert` with full ancestry and the matched rule kind.
3. On user click, send `promptDecision{ruleSpec, scope}` back to the agent.
4. "Recent activity" window: scrollable list of last N decisions, with filters.
5. "Pause for 1 hour" toggle (sets a temporary global allow with auto-expiry, audit-logged).

**No persistence.** Helper is stateless; all state lives in the agent.

### 5.3 scdlp-cli

`/usr/local/bin/scdlp` — Go binary, statically built, signed (no entitlement needed).

```
scdlp status                          # agent health, counters
scdlp list [--allow|--deny|--pending]
scdlp tail [--since 1h]               # live audit tail
scdlp add  <file-key> <identity-key> {allow|deny}
scdlp revoke <rule-id>
scdlp pause --for 1h                  # same as helper button
scdlp doctor                          # checks ESF entitlement, FDA, helper, DB
scdlp export-audit > audit.jsonl
```

CLI reads SQLite directly for read-only commands. Mutations go through XPC to the agent. Same socket as the helper, anchored on the agent's Team ID + bundle ID.

### 5.4 SQLite schema

`/Library/Application Support/scdlp/rules.db`. Owned by `root:wheel`, mode 0640, group `scdlp` so the helper (running as user) can read for tailing.

```sql
PRAGMA journal_mode = WAL;
PRAGMA synchronous = NORMAL;
PRAGMA foreign_keys = ON;

CREATE TABLE rules (
    id              INTEGER PRIMARY KEY,
    file_key        TEXT NOT NULL,         -- canonical path OR category name
    file_key_kind   TEXT NOT NULL CHECK (file_key_kind IN ('path','category')),
    identity_key    TEXT NOT NULL,         -- hex of sha256(exe|p1|p2|…) OR 'EXE:/abs/path'
    identity_kind   TEXT NOT NULL CHECK (identity_kind IN ('chain','exe-only')),
    verdict         TEXT NOT NULL CHECK (verdict IN ('allow','deny')),
    created_at      INTEGER NOT NULL,
    created_by      TEXT NOT NULL,         -- 'user-prompt' | 'cli' | 'bootstrap'
    expires_at      INTEGER,                -- nullable; for temporary rules
    note            TEXT
);
CREATE UNIQUE INDEX rules_lookup_idx
    ON rules (file_key, file_key_kind, identity_key, identity_kind);

CREATE TABLE audit (
    id              INTEGER PRIMARY KEY,
    ts              INTEGER NOT NULL,
    file_path       TEXT NOT NULL,
    file_key        TEXT NOT NULL,
    file_key_kind   TEXT NOT NULL,
    process_pid     INTEGER NOT NULL,
    process_exe     TEXT NOT NULL,
    process_chain   TEXT NOT NULL,         -- 'aws|zsh|Terminal|launchd'
    identity_key    TEXT NOT NULL,
    verdict         TEXT NOT NULL,         -- 'allow' | 'deny' | 'prompt'
    rule_id         INTEGER,
    matched_kind    TEXT,                  -- 'aws-access-key', 'ssh-private', …
    duration_us     INTEGER
);
CREATE INDEX audit_ts_idx ON audit(ts DESC);

CREATE TABLE meta (
    k TEXT PRIMARY KEY,
    v TEXT NOT NULL
);
-- meta keys: schema_version, install_ts, last_helper_seen, paused_until
```

Lookup order in the agent (one query):

```sql
SELECT verdict, id FROM rules
WHERE (
        (file_key_kind = 'path'     AND file_key = ?)
     OR (file_key_kind = 'category' AND file_key = ?)
   ) AND (
        (identity_kind = 'chain'    AND identity_key = ?)
     OR (identity_kind = 'exe-only' AND identity_key = ?)
   ) AND (expires_at IS NULL OR expires_at > ?)
ORDER BY
   CASE file_key_kind  WHEN 'path' THEN 0 ELSE 1 END,
   CASE identity_kind  WHEN 'chain' THEN 0 ELSE 1 END
LIMIT 1;
```

Most specific match wins (file-path beats category, chain beats exe-only). Deterministic.

### 5.5 Classifier — ported from stasher

Source: `/Users/ronreiter/GitHub/stasher/internal/classify/` — port `prefixes.go`, `patterns.go`, `entropy.go`, `denoise.go`, `verdict.go` verbatim into `scdlp/internal/classify/`. Replace the .env-document-oriented `Classifier.Classify(*envparse.Doc)` with a bytes-oriented `Classifier.ClassifyBuf(buf []byte) Verdict` that:

1. Runs Aho-Corasick on `buf[:4096]`.
2. For each hit, finds the surrounding token (`[A-Za-z0-9_\-./+=]+`) and runs the provider's validation regex.
3. On regex match → return high-confidence verdict.
4. If no provider hit, check for `-----BEGIN ` followed by `PRIVATE KEY-----` within the buffer (gitleaks pattern, not in stasher because .env doesn't carry them) → high-confidence. Implemented as a new `pemPrivateKeyRe` in the ported `patterns.go`, called from `ClassifyBuf` after the AC scan returns no hits.
5. Otherwise return `Verdict{}` (not-a-secret).

We do NOT run stasher's stage-3 entropy heuristic on arbitrary file bytes — too many false positives in compressed/binary content. Path-tier-1 + provider prefixes cover the canonical supply-chain targets without it.

**Tier-1 path patterns** (compiled into the agent binary):

```
~/.aws/credentials, ~/.aws/config
~/.ssh/id_*, ~/.ssh/id_*.pub is NOT a secret (skip)
~/.config/gcloud/credentials.db, ~/.config/gcloud/access_tokens.db,
    ~/.config/gcloud/application_default_credentials.json
~/.config/gh/hosts.yml
~/.npmrc, ~/.yarnrc, ~/.yarnrc.yml
~/.pypirc
~/.docker/config.json
~/.kube/config
~/.netrc
~/.git-credentials
~/Library/Application Support/Google/Chrome/*/Login Data
~/Library/Application Support/Firefox/Profiles/*/logins.json
~/.gnupg/private-keys-v1.d/**
**/.env, **/.env.*  (except .env.example, .env.template, .env.sample)
**/*.pem, **/*.p12, **/*.pfx, **/*.key
**/credentials.json (when classified as service-account by content scan)
```

The expansion of `~` and globbing is done at agent startup against `/Users/*`. Reloaded on `SIGHUP`.

### 5.6 XPC protocol

Single Mach service: `io.sentra.scdlp.agent`. NSXPC-style typed protocol; agent is the listener, helper and CLI are clients. Connections are authenticated by audit-token: the agent verifies the peer's code signature against a pinned Team ID + bundle ID set, rejects everything else.

Messages (proto file at `proto/agent.proto`, encoded with protobuf-go):

```
service Agent {
  rpc PromptRequest(stream PromptEvent) returns (stream PromptDecision); // helper streams
  rpc AddRule(RuleSpec) returns (Ack);                                    // cli + helper
  rpc RevokeRule(RuleID) returns (Ack);                                   // cli
  rpc Pause(Duration) returns (Ack);                                      // cli + helper
  rpc Status(Empty) returns (StatusReport);                               // cli
  rpc TailAudit(Filter) returns (stream AuditEvent);                      // cli + helper
}
```

Why protobuf over NSXPC-typed dictionaries: we want the CLI (pure Go) to share the wire format with the helper (Swift) without writing two encoders.

## 6. UX flows

### 6.1 First-run install

1. User downloads `scdlp.dmg`. Drags `scdlp.app` to `/Applications`.
2. Launches `scdlp.app`. Helper requests System Extension activation; macOS prompts the user → System Settings → Privacy & Security → Allow.
3. Helper requests Full Disk Access. macOS prompts; user grants.
4. Helper installs `/usr/local/bin/scdlp` (privileged helper, one-time auth prompt).
5. Agent starts. Tier-1 path globs expanded. SQLite created and migrated. Status: ENFORCING.
6. Onboarding screen offers a "Suggest initial rules" button → runs a one-shot scan: for every tier-1 path, look at recent `fs_usage` / `log` archive to find which processes opened it in the last 30 days, present them as proposed rules. User clicks "Approve all reasonable" or curates.

### 6.2 Steady state — legitimate access

```
$ aws s3 ls
```

1. `aws` (pid 12345, parent zsh, grandparent Terminal) opens `~/.aws/credentials` for read.
2. Kernel fires `AUTH_OPEN`. Agent handler runs in 90 µs.
3. Tier-1 path match. Identity = `sha256("aws|zsh|Terminal|launchd")`.
4. Rule found: `(category=aws-credentials, identity=chain:abc…) → allow`.
5. Agent returns `ALLOW`. `aws` reads the file. User sees no UI.

### 6.3 Steady state — supply-chain attack

```
$ npm install some-package
```

1. npm runs `node /…/node_modules/some-package/install.js`.
2. The postinstall script does `fs.readFileSync(os.homedir() + '/.aws/credentials')`.
3. Kernel fires `AUTH_OPEN`. Agent handler runs in 110 µs.
4. Tier-1 path match. Identity = `sha256("node|sh|npm|node|zsh|Terminal|launchd")`.
5. Rule NOT found (the legitimate `aws → zsh → Terminal` chain doesn't match).
6. Agent returns `DENY` (`EACCES` to caller). Emits `promptRequest` to helper. Audit logged.
7. Helper raises a macOS notification:

       ⚠ scdlp blocked a secret read
       node (via npm → node → sh → install.js) tried to read ~/.aws/credentials.
       This is the same shape as the Shai-Hulud npm worm.
       [Allow once]  [Allow always]  [Deny always]  [Details…]

8. The script's `readFileSync` throws. The postinstall fails. The attack stops before any plaintext leaves disk.
9. User clicks "Deny always" → permanent rule. Next attempt of the same shape is denied without a prompt.

### 6.4 Edge — new legitimate tool

```
$ devbox shell
```

`devbox` reads `~/.npmrc` (legitimate caching). It's a new binary the user just installed. Tier-1 hits, no rule. Agent denies + prompts. User clicks "Allow always". Permanent rule. `devbox` retries (it does, on `EACCES` to `~/.npmrc` for the cache, falling back is normal) and now succeeds. Net cost: one prompt, one rerun.

## 7. Error handling and failure modes

| Failure | Behavior |
|---|---|
| Agent panics inside AUTH handler | System Extension is auto-restarted by macOS. ES subscription is re-established. During the 2–5 s gap, kernel auto-allows all opens. Logged loud. Considered acceptable: ESF guarantees the same fail-open semantics for every commercial vendor. |
| SQLite locked / corrupted | Agent flips to "fail-safe" mode: denies all opens to tier-1 paths until admin runs `scdlp doctor --repair`. Communicated via menubar badge. |
| Helper not running (user logged out, helper crashed) | Agent keeps denying unknowns. Audit shows them. On helper resume, helper drains pending audit entries and notifies user in a "while you were away" summary. |
| Disk full when writing audit | Audit ring-buffers. Latest 100 k events retained, older dropped. Counter exposed via `scdlp status`. |
| ESF entitlement revoked by Apple | Agent fails to start. Helper notifies user with a "scdlp is disabled" badge + URL to reinstall. No silent failure. |
| Clock skew (NTP adjusts time backward) | Audit timestamps are monotonic-then-wall-clock; rules' `expires_at` uses wall clock + bounded slop (5 min) so a skew can't accidentally activate a deny rule. |
| Path with non-UTF-8 bytes | We store raw bytes in `audit.file_path` as percent-encoded; rules' `file_key` is normalized to NFC. Both supported. |

## 8. Testing strategy

- **Unit (`go test ./...`)** — classifier port, identity-key hashing, rule-lookup precedence, path-glob compilation, mute set, fast-skip predicates.
- **Integration with stub ESF** — a fake `es_client_t` that feeds canned events into the handler; assert decisions and XPC calls. Lives in `internal/agent/handler_test.go`.
- **End-to-end (signed binary, real ESF)** — `e2e/` package, must be run on a Mac with the dev entitlement, drives the real `scdlp.app`:
  - `e2e/shaihulud_test.go` — port from stasher: drop a fake `node_modules/x/install.js` that reads `~/.aws/credentials`, run with `npm install ./x`, assert agent emits DENY and audit row.
  - `e2e/legit_test.go` — pretend `aws sts get-caller-identity`, assert ALLOW once the rule is seeded.
  - `e2e/perf_test.go` — 100 k synthetic opens, assert P99 < 200 µs.
- **Property tests** — `quick.Check` over identity hashing (chain reordering ⇒ different hash; same chain ⇒ same hash).
- **Fuzz** — `go test -fuzz` on the classifier byte interface; corpus seeded from stasher's `testdata/classifier/`.

## 9. Out-of-band requirements

- Apple Developer ID, Apple ID, signing keys.
- `com.apple.developer.endpoint-security.client` entitlement (requested from Apple via the developer.apple.com form). Without it the System Extension cannot register.
- Notarization Apple ID + app-specific password for `notarytool`.
- A signing config doc at `docs/signing.md` (gitignored secrets), created during install.

## 10. Repo layout

```
scdlp/
├── cmd/
│   ├── scdlp-agent/             // wrapper that loads the System Extension
│   └── scdlp/                   // CLI
├── extension/
│   ├── ScdlpExtension/          // Swift+C System Extension target (Xcode project)
│   │   ├── Extension.entitlements
│   │   ├── Info.plist
│   │   └── main.m               // ESF C glue
│   └── shared-go-bridge/        // libscdlp_agent.a built from internal/agent
├── helper/
│   └── ScdlpHelper/             // Swift menubar app
├── internal/
│   ├── agent/                   // Go decision engine, called from C glue via cgo
│   ├── audit/
│   ├── classify/                // ported from stasher
│   ├── identity/                // ancestry + hashing
│   ├── pathrules/               // tier-1 glob set
│   ├── rules/                   // SQLite store
│   ├── xpcproto/                // protobuf gen
│   └── ipc/                     // Unix-socket XPC wrapper for Go side
├── proto/agent.proto
├── e2e/
├── docs/
│   └── superpowers/
│       ├── specs/2026-05-27-scdlp-design.md
│       └── plans/               // populated by writing-plans skill next
├── Makefile
├── go.mod
└── README.md
```

## 11. Open questions deferred to v2

- Encrypted at-rest of `~/.aws/credentials` (the stasher angle) — orthogonal; can coexist.
- Fleet management, central rule push.
- Linux/Windows.
- Touch ID confirmation for high-stakes prompts.
- Per-user rules (currently single-user assumed; multi-user Mac will share rules.db).
- Snapshot/restore of rules (`scdlp export` / `scdlp import`).

## 12. Known follow-ups from the v1 core implementation

The v1 core landed via plan `docs/superpowers/plans/2026-05-27-scdlp-v1-core.md`. The following items from §4–§7 were intentionally deferred and must be addressed before any production ship:

- **IPC peer authentication.** §5.6 calls for the agent to verify the peer's audit token against pinned Team ID + bundle ID. The current implementation uses a Unix socket at `os.TempDir()/scdlp.sock` with mode `0660` and no peer check. Any local process running as the same user can `Dial` it and add allow-rules. This is acceptable for the pre-ESF MockHook era; it is **not** acceptable once real opens are being blocked. Track as a v1.1 must-fix.
- **`scdlp doctor` and `scdlp pause`** (§5.3) — listed as required CLI subcommands; not yet implemented. v1 has `status / list / add / revoke / tail` only. Both are shell-thin over the existing IPC.
- **Audit retention.** §7 requires the audit table to ring-buffer at 100 k rows. v1 has no cap, no trim trigger, no counter in `status`. Add a trigger or a periodic vacuum task.
- **`meta` table.** §5.4 defines `meta(k, v)` with keys `schema_version`, `install_ts`, `last_helper_seen`, `paused_until`. Created by the migration but never written or read. Wire up at least `install_ts` and `schema_version` so future migrations have a hook.
- **Mach XPC vs. Unix socket.** §4 and §5.6 assume Mach XPC with `io.sentra.scdlp.agent`. v1 ships Unix-socket length-prefixed JSON. When the Swift helper lands it will need either an NSXPC bridge or a Unix-socket client; the protocol is already shape-compatible with both.

---

End of spec.
