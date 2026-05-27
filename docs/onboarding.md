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
