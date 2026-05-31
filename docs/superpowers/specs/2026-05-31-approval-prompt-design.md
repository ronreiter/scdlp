# scdlp approval prompt + menu bar app — design

**Status:** approved 2026-05-31. Goal: `cat spaceforge/.env` by an unrecognized
process is **blocked**, a **popup** appears, and the user's choice is remembered.

## Scope decisions (from Ron)

- **Name-based scan scope (configurable).** Only files whose name contains a
  configured substring are inspected. Default `["env"]`. Everything else is
  allowed instantly with no inspection. Config at
  `/Library/Application Support/scdlp/config.json`:
  `{"scan_name_substrings":["env"]}`. Read at startup; missing → default.
- **Deny-first.** The first access by an unrecognized process to an in-scope
  file is **denied immediately** (the `open()` fails) and the popup is fired
  asynchronously. The user's choice writes a rule; the next access honors it.
  No holding the open / no kernel-deadline race.

## Components

### 1. Config (`internal/config`)
- `type Config struct { ScanNameSubstrings []string }`
- `Load(path string) Config` — JSON; defaults to `["env"]` when absent/empty.
- Case-insensitive substring match on the file's base name.

### 2. Engine scope gate (`internal/agent`)
- `decideInner`: after the write-only fast-allow, if the base name does **not**
  contain any configured substring → return `Allow` (out of scope, no audit).
- In-scope files: look up `(identity, category)` rules as today.
  - allow rule → Allow; deny rule → Deny.
  - **unknown → Deny (deny-first) + publish a `PromptEvent`** carrying a stable
    request id, identity keys, path, and category.
- Category for an in-scope file = matched path-rule category if any, else
  `"env-file"`.
- Monitor-only remains available (`--monitor`) for a non-blocking fallback when
  no helper is present; prompt mode is the default when the helper is expected.

### 3. Prompt spool (`internal/promptspool`)
Transport between the root extension and the user-session menu bar app via a
shared dir `…/scdlp/prompts/` (created group-writable for `admin`).
- **Writer:** drains the `PromptBus`; writes `<id>.req` JSON
  (`id, ts, pid, exe, human_chain, path, category, identity_key, exe_only_key`).
- **Reply watcher:** watches for `<id>.reply` JSON
  (`decision: allow|deny, scope: once|always`); on `always`, inserts a rule into
  `rules.db` (allow or deny, keyed by identity + category); deletes the pair.
- Replies for `once` create no rule (the deny-first already happened; the user
  re-runs to retry under the new rule, or it stays denied).
- *Security:* spool is filesystem-trust only — acceptable for a single-user
  Mac. **Follow-up:** replace with XPC + peer audit-token validation.

### 4. `scdlp-helper` menu bar app (Swift)
- LaunchAgent in the user GUI session (auto-start); bundled inside `scdlp.app`.
- Watches `…/scdlp/prompts/` (FSEvents); for each `.req`, shows an alert:
  *"‹exe› (via ‹chain›) wants to read ‹path› — ‹category›."* with
  **Allow / Deny** and an **Always** checkbox; writes `<id>.reply`.
- `NSStatusItem` menu: status (extension alive?), recent decisions, edit scan
  list, pause, quit — the "control & visibility" ask.

## End-to-end flow
1. `cat spaceforge/.env` → AUTH_OPEN; name contains "env" → in scope.
2. No rule for (cat-chain, env-file) → **Deny** (cat: "Operation not permitted")
   + publish prompt → spool `.req`.
3. Helper pops the alert → user clicks **Always allow** → `.reply` →
   watcher inserts an allow rule.
4. `cat spaceforge/.env` again → rule matches → **Allow**.

## Testing
- Go: config defaults/parse; scope gate (in/out of scope); deny-first publishes
  a prompt; spool writer emits a well-formed `.req`; reply watcher inserts the
  right rule. (All unit-testable.)
- The ES response + Swift UI are verified via the local notarized install
  (`dev-cycle.sh`) + launching the helper.

## Build order
1. config + scope gate (Go, tests).
2. promptspool writer + reply→rule watcher (Go, tests).
3. wire into `cmd/scdlp-agent` (prompt mode).
4. `scdlp-helper` Swift app + bundle + LaunchAgent.
5. sign/notarize, install, verify the popup end-to-end.
