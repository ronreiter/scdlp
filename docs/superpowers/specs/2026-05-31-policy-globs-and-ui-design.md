# scdlp glob policy + control UI — design

**Status:** approved 2026-05-31. Replaces the name-substring scope with a
glob→action policy, and adds a menu-bar window showing history / policy / rules.

## 1. Policy model (`internal/config`)

`config.json`:
```json
{"policy": [
  {"glob": "*.env*",             "action": "prompt"},
  {"glob": "*/.aws/credentials", "action": "prompt"},
  {"glob": "*/Caches/*",         "action": "allow"},
  {"glob": "*/evil/*",           "action": "block"}
]}
```
- `PolicyEntry{Glob string, Action string}`; `Action` ∈ `prompt | allow | block`.
- **First match wins** (ordered). No match → `Ignore` (allow, not inspected, not audited).
- **Matching:** for each entry, a path matches if `doublestar.Match(glob, fullPath)` **or** `doublestar.Match(glob, base(fullPath))`. So `*.env*` matches any `.env*` basename; `*/.aws/credentials` matches by path tail.
- `Match(path) Action` returns `prompt|allow|block|ignore`.
- **Default** (no `policy` key): prompt on `*.env*`, `*/.aws/credentials`, `*/.aws/config`, `*/.ssh/id_*`, `*/.npmrc`, `*/.git-credentials`. Legacy `scan_name_substrings` is migrated to `**/*<s>*` → prompt.

## 2. Engine (`internal/agent`)
`decideInner` consults the policy first:
- `ignore` → Allow, no audit.
- `allow`  → Allow, audit verdict "allow".
- `block`  → Deny, audit verdict "block".
- `prompt` → current flow: rules lookup → allow/deny rule, else deny-first + publish prompt (helper-present gating + allow-first fallback unchanged).
- Policy is swappable at runtime: `Engine.SetPolicy(config.Config)` guarded by a mutex; `decideInner` reads under it.

## 3. Control channel (`internal/control`)
World-writable dir `…/scdlp/control/` (0777, created by extension):
- `policy.json` — the live policy. The extension polls it (250 ms); on change it
  validates and calls `Engine.SetPolicy`. The UI writes it to edit policy.
- `commands/` — command files the UI drops; the extension applies + deletes:
  - `revoke-<ruleID>.cmd` → `rules.Revoke(id)`.
- History & rules are **read-only** for the UI: it opens `audit.db` / `rules.db`
  directly (both world-readable).
- *Security:* world-writable control = same single-user trust model as the
  prompt spool. XPC + peer audit-token validation is the hardening follow-up.

## 4. UI (`helper/`, Swift/AppKit)
🛡 menu → "Open scdlp…" → `NSWindow` with an `NSTabView`:
- **History** — `NSTableView` (Time, Verdict, File, Process) from `audit.db`
  (newest first; refresh on a GCD timer). Read via the `sqlite3 -json` CLI.
- **Policy** — editable rows (Glob, Action popup) + Add/Remove/Move; **Save**
  writes `control/policy.json`.
- **Rules** — remembered per-process rules from `rules.db`, each with **Revoke**
  (writes `control/commands/revoke-<id>.cmd`).
The existing prompt alert + heartbeat are unchanged.

## 5. Testing
- Go: policy parse/default/migration; `Match` (full-path vs basename, first-match,
  ignore); engine allow/block/prompt per policy; `SetPolicy` swap; control dir
  applies a policy.json change + a revoke command.
- Swift UI verified live (notarized install).

## Build order
1. config policy model + Match (TDD).
2. engine: policy-driven decisions + SetPolicy (TDD).
3. internal/control: policy watcher + command applier (TDD); wire into scdlp-agent.
4. helper UI window (History/Policy/Rules).
5. deploy once (incl. the prior flood-fix + e2e de-flake), verify.
