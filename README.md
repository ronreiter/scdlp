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

We use [`go-task`](https://taskfile.dev) instead of make. Install once with
`brew install go-task`, then:

```bash
task               # show available tasks
task build         # builds bin/scdlp-agent and bin/scdlp
```

## Run

In one terminal:

```bash
task run:mock      # daemon with MockHook (no real opens intercepted)
```

In another:

```bash
task cli:status
task cli:tail
./bin/scdlp list
```

See `docs/onboarding.md` for a full walkthrough including the in-process Shai-Hulud reenactment test.

## Test

```bash
task test          # unit + e2e
task bench         # decision-path microbenchmark
```

## Real-kernel mode (ESF)

The `scdlp-agent` binary supports a `--hook=esf` flag that subscribes to the
macOS Endpoint Security framework instead of the in-process MockHook. To use
it you need:

1. The `com.apple.developer.endpoint-security.client` entitlement granted by
   Apple to your Team ID (see `docs/signing.example.md`), OR
2. A SIP-relaxed dev Mac (see `docs/dev-mode.md`).

For path #2, scdlp ships dev-mode helpers:

```bash
task nvram:status              # show current SIP + boot-args
task nvram:init-dev-mode       # set the AMFI/CS boot-args (sudo, restart after)
task systemextensions:dev-on   # allow extensions outside /Applications
task doctor                    # one-shot state dump
```

Once one of the two paths is set up:

```bash
task bundle                    # build extension + host .app (ad-hoc signed by default)
task install                   # cp to /Applications + lsregister
task activate                  # request macOS to install the extension
```

System Settings prompts you to approve the System Extension and grant Full
Disk Access. After approval, real `open()` calls flow through scdlp's
decision engine and the existing CLI (`scdlp status`, `scdlp tail`, …)
reflects live decisions.

```bash
task deactivate                # remove the extension
task nvram:revert              # clear dev-mode boot-args (restart after)
```

## License

MIT.
