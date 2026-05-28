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

The project uses [`go-task`](https://taskfile.dev). Install once with `brew install go-task`.

```bash
task build
# Terminal A
task run:mock
# Terminal B
task cli:status
task cli:tail
./bin/scdlp --socket /tmp/scdlp.sock add \
    --file-key aws-credentials --file-kind category \
    --identity-key abc --identity-kind chain --verdict allow
./bin/scdlp --socket /tmp/scdlp.sock list
./bin/scdlp --socket /tmp/scdlp.sock revoke 1
```

Today the daemon is wired to a `MockHook`, so no real opens are intercepted; the e2e test in `e2e/shaihulud_test.go` exercises the same machinery end-to-end against synthetic events.

## ESF backend (lives in `internal/hook/esf_*` and `extension/`, `host/`)

As of the ESF plan, the System Extension exists in the repo:

- `internal/hook/esf_glue.{h,c}` — cgo glue around `libEndpointSecurity`.
- `internal/hook/esf_darwin.go` — Go `Hook` implementation; bridges ES events
  into the decision engine.
- `extension/` — System Extension bundle metadata (Info.plist + entitlements)
  + `build.sh` that compiles the Go agent and assembles the
  `Scdlp.systemextension`.
- `host/` — minimal Swift activator app (`main.swift`) and bundle metadata.
- `Makefile` targets `extension`, `host`, `bundle`, `activate`, `deactivate`.

What is still out-of-band:

1. The `com.apple.developer.endpoint-security.client` entitlement from Apple
   (`docs/signing.example.md`).
2. A Developer ID signing identity.
3. Notarization if you intend to distribute the .app.

Without (1) and (2), the bundle builds and installs but `es_new_client` returns
`ERR_NOT_ENTITLED` at runtime. To exercise ESF before the entitlement is
granted, see `docs/dev-mode.md`.
