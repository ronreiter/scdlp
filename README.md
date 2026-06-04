<p align="center">
  <img src="docs/shield.svg" width="96" height="96" alt="SCDLP shield logo">
</p>

<h1 align="center">Supply Chain DLP (SCDLP)</h1>

<p align="center"><strong>Anti-supply-chain DLP for macOS.</strong></p>

<p align="center">
  🌐 <a href="https://ronreiter.github.io/scdlp/">Website</a> &nbsp;·&nbsp;
  ⬇️ <a href="https://github.com/ronreiter/scdlp/releases/latest/download/scdlp.dmg">Download scdlp.dmg</a> &nbsp;·&nbsp;
  📦 <a href="https://github.com/ronreiter/scdlp/releases">Releases</a>
</p>

SCDLP is a signed macOS **Endpoint Security system extension** that watches every file open and blocks unknown processes from reading your credentials — `.env` files, cloud keys (AWS/GCP/Azure), SSH/GPG keys, package-manager and git tokens, kubeconfigs — with a Little-Snitch-style allow/deny prompt. It defeats the npm/pip/cargo postinstall pattern that reads `~/.aws/credentials`, `~/.ssh/id_*`, `~/.npmrc`, etc., and stops chatty AI agents from sweeping up your secrets.

A menu-bar app provides the approval prompts and a dashboard (History · Policy · Trusted Apps · Rules), plus a one-click kill switch.

Sibling project: [`stasher`](https://github.com/ronreiter/stasher) — the FUSE-based flavor with hardware-bound encryption around `.env` files.

## Architecture

See `docs/superpowers/specs/2026-05-27-scdlp-design.md`.

Three local processes:

- **`scdlp-agent`** — daemon, owns the SQLite at `~/.scdlp/`, runs the decision pipeline.
- **`scdlp`** — CLI, talks to the daemon over a Unix socket.
- **scdlp-helper** — Swift menu-bar app: approval prompts + dashboard (History / Policy / Trusted Apps / Rules) + kill switch.

## Classification engine

Before scdlp prompts you about a file, it asks one question: *does this file
actually contain a secret?* That check is the classifier in
`internal/classify`. Its only entry point on the decision path is
`Classifier.ClassifyBuf`, which inspects the first **4 KiB** of a file
(`classify.MaxScanBytes`) and returns a `Verdict{Match, Value, Confidence,
Reason}`. The engine reduces that to a single boolean — `Verdict.IsSecret()`,
defined as `Confidence >= 0.6`.

The classifier is built once (`classify.New()`), is immutable, and is safe for
concurrent use. At construction it flattens every known provider prefix into a
single [Aho-Corasick](https://en.wikipedia.org/wiki/Aho%E2%80%93Corasick_algorithm)
automaton, so all prefixes are matched in one linear pass regardless of how many
providers are configured.

Provider knowledge lives in two parallel tables:

- `prefixes.go` — cheap literal anchors per provider (`AKIA…` AWS, `ghp_` /
  `github_pat_` GitHub, `xoxb-` Slack, `sk-` / `sk-proj-` OpenAI, `sk_live_`
  Stripe, `AIza` Google, `npm_`, `hf_`, `eyJ` JWT, …).
- `patterns.go` — a full validation regex per provider (e.g. AWS
  `^(AKIA|ASIA|…)[A-Z0-9]{16}$`), plus `PEMPrivateKeyRe` for private-key headers.

`ClassifyBuf` runs a short pipeline over the buffer:

1. **Empty guard.** An empty buffer is "not a secret" (this is why a zero-byte
   protected file is allowed). Anything longer than 4 KiB is truncated.
2. **PEM private keys.** A single regex matches the `-----BEGIN … PRIVATE
   KEY-----` header → `Confidence 1.0`. It triggers on the header alone, because
   a large key's body can be cut off by the 4 KiB window.
3. **Provider tokens (two stages).**
   - *Anchor:* the Aho-Corasick pass reports which prefixes occur. No prefix →
     "not a secret" (the fast path for ordinary config files).
   - *Validate:* for each prefix hit, the surrounding token is extracted and run
     against that provider's regex. A full match → `Confidence 1.0` (returns
     immediately). A prefix with no well-formed token → a weak `Confidence 0.4`.

The highest-confidence finding wins. Because the prompt threshold is `0.6`, only
a **well-formed** credential (or a PEM header) blocks: a bare prefix appearing in
prose (`sk-`, `AKIA…` with the wrong shape) scores `0.4` and is treated as
benign. This deliberately trades recall for a low false-positive rate — a false
"secret" means an unnecessary prompt.

The engine uses the result like this: a path that matched a `prompt` glob but
whose first 4 KiB is **not** a secret is a false positive of the coarse path
rule, so it is allowed silently (audit verdict `allow-clean`); a secret, or a
file whose head can't be read, falls through to deny-first + prompt. See
`docs/superpowers/specs/2026-06-04-content-scan-allow-design.md`.

Properties: deterministic (no entropy scoring, ML, or network — same bytes always
yield the same verdict), microsecond-scale on 4 KiB (which is what lets it run on
the synchronous Endpoint Security decision path), and bounded to a fixed provider
list. A secret type with no prefix entry, a credential past the 4 KiB window, or a
malformed-but-real token will read as benign.

> Note: `internal/classify` also ships value-level heuristics carried over from
> [`stasher`](https://github.com/ronreiter/stasher) — Shannon entropy
> (`entropy.go`), secret-ish key names, and placeholder/URL/boolean denoisers
> (`denoise.go`). These are exercised by tests but are **not** wired into
> `ClassifyBuf`; scdlp's buffer scan is purely prefix-anchored regex + PEM.

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
