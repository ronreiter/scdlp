#!/usr/bin/env bash
# Compile + run the headless PromptQueue tests (helper/promptqueue_tests.swift).
# No Cocoa, no app bundle — just the pure prompt-dedup logic.
set -euo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"
BIN="$(mktemp -d)/pqtest"

swiftc "$REPO/helper/promptqueue.swift" "$REPO/helper/promptqueue_tests.swift" -o "$BIN"
"$BIN"
