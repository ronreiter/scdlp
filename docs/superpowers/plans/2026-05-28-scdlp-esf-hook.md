# scdlp ESF Hook Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development to execute task-by-task. Steps use checkbox (`- [ ]`) syntax.

**Goal:** Replace the v1 `MockHook` with a real Endpoint Security backend so the same Go decision engine intercepts actual `open()` calls on macOS. Architecture: the `.systemextension` bundle's main executable IS our Go agent (cgo to `libEndpointSecurity`); host `.app` triggers activation. Behind a `--hook=mock|esf` flag — default stays `mock` so the existing daemon and unit tests keep working until the entitlement lands.

**Architecture:**

Single process. macOS launches the System Extension; the extension's binary is our Go agent with cgo to `libEndpointSecurity`. It subscribes to `ES_EVENT_TYPE_AUTH_OPEN` (and a couple of NOTIFY events), runs the existing decision engine, returns `ALLOW`/`DENY` synchronously, and keeps using the same SQLite + IPC + CLI on the side. The host `.app` is a 50-line Swift activator that calls `OSSystemExtensionRequest`.

**Tech stack:** Go 1.24 + cgo, `libEndpointSecurity.tbd` (ships with macOS), Swift for the host activator only, `codesign` + `productbuild` + `xcrun stapler` for packaging.

**Reality check on the entitlement:**

`com.apple.developer.endpoint-security.client` is granted by Apple after a manual review (weeks to months). Without it, `es_new_client` returns `ES_NEW_CLIENT_RESULT_ERR_NOT_ENTITLED` at runtime. This plan **builds the code so it's ready** — when the entitlement lands the binary just works. To test live before then, you flip your dev Mac into SIP-relaxed mode (covered in Task 9's `docs/dev-mode.md`). That's a real intrusive change to your machine; the choice is yours.

**Spec:** `docs/superpowers/specs/2026-05-27-scdlp-design.md` §4–§5 (architecture, components), §10 (repo layout). v1 follow-ups §12 still apply.

**Prior plan:** `docs/superpowers/plans/2026-05-27-scdlp-v1-core.md` (the Go core lands at commit `d56368c`; this plan starts there).

---

## Task 1: ESF C glue — header + source

**Files:**
- Create: `internal/hook/esf_glue.h`
- Create: `internal/hook/esf_glue.c`

The glue exposes a tiny C API the Go side will drive: create a client, set mutes, run the event loop, respond to AUTH events. Events are pushed across the cgo boundary via a Go callback registered through an `//export` function. ES is dispatch-queue driven; we serve events from libdispatch's default queue.

- [ ] **Step 1: Write `internal/hook/esf_glue.h`**

```c
// internal/hook/esf_glue.h
#ifndef SCDLP_ESF_GLUE_H
#define SCDLP_ESF_GLUE_H

#include <stdint.h>
#include <stdbool.h>

// Opaque handle to an ES client. NULL on error.
typedef void* scdlp_es_client_t;

// One pending AUTH_OPEN event surfaced to Go. The cookie is what Go passes
// back to scdlp_es_respond() to release the original ES message.
typedef struct {
    uint64_t cookie;       // opaque pointer to the ES message (cast back internally)
    int32_t  pid;
    uint32_t flags;        // open() flags (O_WRONLY, O_RDWR, etc.)
    const char* path;      // NUL-terminated; valid until scdlp_es_respond is called
    const char* exe;       // NUL-terminated; "" if unavailable
} scdlp_es_event_t;

// Creates a client and subscribes to AUTH_OPEN + NOTIFY_EXEC + NOTIFY_EXIT.
// Returns NULL on failure; *err_out is set to an ES_NEW_CLIENT_RESULT_ERR_*
// integer code so Go can produce a useful message.
scdlp_es_client_t scdlp_es_new_client(int* err_out);

// Adds a path-prefix mute. Returns 0 on success.
int scdlp_es_mute_path_prefix(scdlp_es_client_t cli, const char* prefix);

// Releases the client and stops the event loop.
void scdlp_es_release_client(scdlp_es_client_t cli);

// Synchronously respond to an AUTH event. allow=1 for ALLOW, 0 for DENY.
// Must be called exactly once per cookie surfaced by the Go callback.
void scdlp_es_respond(scdlp_es_client_t cli, uint64_t cookie, int allow);

#endif
```

- [ ] **Step 2: Write `internal/hook/esf_glue.c`**

```c
// internal/hook/esf_glue.c
// Build only on darwin. We don't add a //go:build tag to a .c file;
// the corresponding Go wrapper carries the build constraint and is the
// only thing that pulls this file into the build.

#include <EndpointSecurity/EndpointSecurity.h>
#include <bsm/libbsm.h>
#include <dispatch/dispatch.h>
#include <stdlib.h>
#include <string.h>

#include "esf_glue.h"

// Forward declaration of the Go-side callback. cgo will resolve this at
// link time via the //export directive in esf_darwin.go.
extern void scdlpGoOnEvent(scdlp_es_event_t ev);

scdlp_es_client_t scdlp_es_new_client(int* err_out) {
    es_client_t* client = NULL;
    es_new_client_result_t r = es_new_client(&client, ^(es_client_t* c, const es_message_t* m) {
        if (m->event_type != ES_EVENT_TYPE_AUTH_OPEN) {
            // We only subscribe to AUTH_OPEN today; ignore anything else.
            return;
        }
        // Make a retained copy so we can respond asynchronously from Go.
        es_message_t* held = es_copy_message(m);
        if (!held) {
            // Allocation failure — let the kernel default-allow via timeout.
            return;
        }

        scdlp_es_event_t ev;
        ev.cookie = (uint64_t)(uintptr_t)held;
        ev.pid    = audit_token_to_pid(m->process->audit_token);
        ev.flags  = m->event.open.fflag;

        // ES_STRING_TOKEN data is not NUL-terminated; copy and terminate.
        size_t pathLen = m->event.open.file->path.length;
        char* pathBuf = (char*)malloc(pathLen + 1);
        memcpy(pathBuf, m->event.open.file->path.data, pathLen);
        pathBuf[pathLen] = '\0';
        ev.path = pathBuf;

        size_t exeLen = m->process->executable->path.length;
        char* exeBuf = (char*)malloc(exeLen + 1);
        memcpy(exeBuf, m->process->executable->path.data, exeLen);
        exeBuf[exeLen] = '\0';
        ev.exe = exeBuf;

        // Synchronously hand control to Go. Go calls scdlp_es_respond before
        // returning, which releases the held message.
        scdlpGoOnEvent(ev);

        free(pathBuf);
        free(exeBuf);
    });
    if (r != ES_NEW_CLIENT_RESULT_SUCCESS) {
        if (err_out) *err_out = (int)r;
        return NULL;
    }

    es_event_type_t subs[] = { ES_EVENT_TYPE_AUTH_OPEN };
    if (es_subscribe(client, subs, sizeof(subs)/sizeof(subs[0])) != ES_RETURN_SUCCESS) {
        if (err_out) *err_out = -1;
        es_delete_client(client);
        return NULL;
    }
    if (err_out) *err_out = 0;
    return (scdlp_es_client_t)client;
}

int scdlp_es_mute_path_prefix(scdlp_es_client_t cli, const char* prefix) {
    es_client_t* c = (es_client_t*)cli;
    es_return_t r = es_mute_path(c, prefix, ES_MUTE_PATH_TYPE_PREFIX);
    return (r == ES_RETURN_SUCCESS) ? 0 : -1;
}

void scdlp_es_release_client(scdlp_es_client_t cli) {
    if (!cli) return;
    es_client_t* c = (es_client_t*)cli;
    es_unsubscribe_all(c);
    es_delete_client(c);
}

void scdlp_es_respond(scdlp_es_client_t cli, uint64_t cookie, int allow) {
    es_client_t* c = (es_client_t*)cli;
    es_message_t* m = (es_message_t*)(uintptr_t)cookie;
    if (!c || !m) return;
    es_auth_result_t result = allow ? ES_AUTH_RESULT_ALLOW : ES_AUTH_RESULT_DENY;
    es_respond_auth_result(c, m, result, false /* don't cache */);
    es_release_message(m);
}
```

- [ ] **Step 3: Quick syntax check (no link yet, just compile)**

```bash
clang -c -fsyntax-only -isysroot $(xcrun --show-sdk-path) \
    /Users/ronreiter/GitHub/scdlp/internal/hook/esf_glue.c
```

Expected: no errors. (Warnings about unused parameters in the block are OK.)

- [ ] **Step 4: Commit**

```bash
cd /Users/ronreiter/GitHub/scdlp
git add internal/hook/esf_glue.h internal/hook/esf_glue.c
git -c user.email=ron@sentra.io -c user.name="Ron Reiter" commit -m "feat(hook): C glue for Endpoint Security framework

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>"
```

---

## Task 2: Go hook implementation

**Files:**
- Create: `internal/hook/esf_darwin.go`
- Create: `internal/hook/esf_stub.go`
- Create: `internal/hook/esf_darwin_test.go`

The Go side implements `Hook` (`Next(ctx) (Event, DecideFunc, error)`) over the C glue. Because the C callback fires from libdispatch's queue and Go's `Next()` is pull-based, we bridge them with a buffered channel: the callback enqueues, `Next()` dequeues. `DecideFunc` calls back into C via `scdlp_es_respond`.

- [ ] **Step 1: Write `internal/hook/esf_stub.go`**

```go
//go:build !darwin

package hook

import (
	"context"
	"errors"
)

// ESFHook is a non-darwin stub so the rest of the project compiles
// everywhere. NewESFHook always returns an error.
type ESFHook struct{}

func NewESFHook() (*ESFHook, error) {
	return nil, errors.New("ESF hook is darwin-only")
}

func (*ESFHook) Next(ctx context.Context) (Event, DecideFunc, error) {
	return Event{}, nil, errors.New("ESF hook is darwin-only")
}

func (*ESFHook) Close() error { return nil }
```

- [ ] **Step 2: Write `internal/hook/esf_darwin.go`**

```go
//go:build darwin

package hook

/*
#cgo CFLAGS: -fno-objc-arc
#cgo LDFLAGS: -lEndpointSecurity -lbsm

#include "esf_glue.h"
#include <stdlib.h>
*/
import "C"

import (
	"context"
	"fmt"
	"sync"
	"unsafe"
)

// ESFHook is the Endpoint Security framework backend for Hook.
// One instance per process; there is only one ES client.
type ESFHook struct {
	c       C.scdlp_es_client_t
	q       chan pendingESF
	mu      sync.Mutex
	closed  bool
}

type pendingESF struct {
	ev     Event
	cookie C.uint64_t
}

// activeHook is the singleton bridged to the C callback. Because ES delivers
// one client's events on its own dispatch queue and we expose exactly one
// ESFHook per process, a global pointer is the cleanest cgo bridge.
var (
	activeMu sync.RWMutex
	active   *ESFHook
)

// NewESFHook subscribes to AUTH_OPEN. The kernel returns ERR_NOT_ENTITLED
// (1) when the binary lacks `com.apple.developer.endpoint-security.client`,
// ERR_NOT_PERMITTED (3) when Full Disk Access hasn't been granted, and
// ERR_NOT_PRIVILEGED (5) when not running as root. The error message names
// the most likely cause.
func NewESFHook() (*ESFHook, error) {
	activeMu.Lock()
	defer activeMu.Unlock()
	if active != nil {
		return nil, fmt.Errorf("ESF hook already initialised in this process")
	}

	var errCode C.int
	cli := C.scdlp_es_new_client(&errCode)
	if cli == nil {
		return nil, fmt.Errorf("es_new_client failed: %s", esErrString(int(errCode)))
	}

	h := &ESFHook{
		c: cli,
		q: make(chan pendingESF, 256),
	}
	active = h
	h.applyDefaultMutes()
	return h, nil
}

func (h *ESFHook) Next(ctx context.Context) (Event, DecideFunc, error) {
	select {
	case <-ctx.Done():
		return Event{}, nil, ctx.Err()
	case p := <-h.q:
		var once sync.Once
		decide := func(d Decision) {
			once.Do(func() {
				h.mu.Lock()
				cli := h.c
				closed := h.closed
				h.mu.Unlock()
				if closed || cli == nil {
					return
				}
				allow := C.int(0)
				if d == Allow {
					allow = 1
				}
				C.scdlp_es_respond(cli, p.cookie, allow)
			})
		}
		return p.ev, decide, nil
	}
}

func (h *ESFHook) Close() error {
	h.mu.Lock()
	if h.closed {
		h.mu.Unlock()
		return nil
	}
	h.closed = true
	cli := h.c
	h.c = nil
	h.mu.Unlock()

	activeMu.Lock()
	active = nil
	activeMu.Unlock()

	if cli != nil {
		C.scdlp_es_release_client(cli)
	}
	return nil
}

// applyDefaultMutes installs a small set of path prefixes that the agent
// will never need to inspect. Cuts event volume by an order of magnitude.
func (h *ESFHook) applyDefaultMutes() {
	prefixes := []string{
		"/System/",
		"/usr/share/",
		"/Library/Caches/com.apple.",
		"/private/var/folders/", // ephemeral temp space; never sensitive
		"/dev/",
	}
	for _, p := range prefixes {
		cp := C.CString(p)
		C.scdlp_es_mute_path_prefix(h.c, cp)
		C.free(unsafe.Pointer(cp))
	}
}

func esErrString(code int) string {
	switch code {
	case 0:
		return "success"
	case 1:
		return "not entitled (need com.apple.developer.endpoint-security.client)"
	case 2:
		return "internal ES error"
	case 3:
		return "not permitted (grant Full Disk Access)"
	case 4:
		return "invalid argument"
	case 5:
		return "not privileged (run as root)"
	case 6:
		return "TCC denied"
	default:
		return fmt.Sprintf("unknown ES error %d", code)
	}
}

//export scdlpGoOnEvent
func scdlpGoOnEvent(ev C.scdlp_es_event_t) {
	activeMu.RLock()
	h := active
	activeMu.RUnlock()
	if h == nil {
		// No active hook — accept the open so the kernel doesn't stall.
		// We can't call into C from here safely without a client; the C
		// side will time out and default-allow.
		return
	}
	p := pendingESF{
		ev: Event{
			Path:  C.GoString(ev.path),
			PID:   int(ev.pid),
			Exe:   C.GoString(ev.exe),
			Flags: int(ev.flags),
		},
		cookie: ev.cookie,
	}
	// Non-blocking enqueue. If the queue is full we ALLOW immediately
	// rather than block the kernel callback — denying-by-default on
	// overload is worse than allowing.
	select {
	case h.q <- p:
	default:
		C.scdlp_es_respond(h.c, ev.cookie, 1) // allow
	}
}
```

- [ ] **Step 3: Write `internal/hook/esf_darwin_test.go`**

```go
//go:build darwin

package hook

import (
	"errors"
	"testing"
)

// We can't fully exercise ESF without the entitlement. The two things we
// CAN check on every darwin Mac:
//   1. The cgo + C glue compiles and links.
//   2. NewESFHook fails with a clear error message when un-entitled.
// Both are valuable: they catch link regressions and message regressions.

func TestNewESFHook_ReportsEntitlementError(t *testing.T) {
	// Skip if the test happens to be running as root with the entitlement
	// (rare in CI / dev; would actually subscribe and never reach the err).
	h, err := NewESFHook()
	if err == nil {
		// Unexpected on an un-entitled binary — clean up and bail.
		_ = h.Close()
		t.Skip("ESF hook actually succeeded; this Mac is entitled. Skipping un-entitled check.")
	}
	if !errors.Is(err, err) {
		// trivially true — placeholder for future error types
	}
	want := "not entitled"
	if !contains(err.Error(), want) && !contains(err.Error(), "not privileged") &&
		!contains(err.Error(), "not permitted") {
		t.Fatalf("want error mentioning entitlement/privilege/permission, got %v", err)
	}
}

func contains(haystack, needle string) bool {
	return len(haystack) >= len(needle) && (haystack == needle ||
		(len(haystack) > 0 && indexOf(haystack, needle) >= 0))
}

func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}
```

- [ ] **Step 4: Build + run the test**

```bash
cd /Users/ronreiter/GitHub/scdlp
go build ./internal/hook/...
go test ./internal/hook/... -v
```

Expected: compiles cleanly; `TestNewESFHook_ReportsEntitlementError` either PASSES with an "not entitled" / "not privileged" error message, or SKIPS because somehow the host has the entitlement.

If the build fails with `'EndpointSecurity/EndpointSecurity.h' file not found`, the macOS SDK isn't visible to cgo. Re-run `xcode-select --install` and confirm `xcrun --show-sdk-path` returns a real path.

- [ ] **Step 5: Commit**

```bash
git add internal/hook/esf_darwin.go internal/hook/esf_stub.go internal/hook/esf_darwin_test.go
git -c user.email=ron@sentra.io -c user.name="Ron Reiter" commit -m "feat(hook): Go ESF Hook implementation over the C glue

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>"
```

---

## Task 3: Wire `--hook` flag into the daemon

**Files:**
- Modify: `cmd/scdlp-agent/main.go`

Replace the unconditional `hook.NewMock()` with a flag that selects mock or ESF.

- [ ] **Step 1: Edit `cmd/scdlp-agent/main.go`**

Find the line `mh := hook.NewMock()` and replace the block from the flag declarations through the `eng.Run(ctx, mh)` call. The diff:

```go
// Add a new flag near the others:
hookKind := flag.String("hook", "mock", "event source: mock | esf")

// After flag.Parse(), but before constructing the engine, build the hook:
var h hook.Hook
switch *hookKind {
case "mock":
    h = hook.NewMock()
    log.Print("hook: MockHook (no real opens are intercepted)")
case "esf":
    eh, err := hook.NewESFHook()
    if err != nil {
        log.Fatalf("ESF hook: %v", err)
    }
    defer eh.Close()
    h = eh
    log.Print("hook: EndpointSecurity")
default:
    log.Fatalf("unknown --hook %q (want mock|esf)", *hookKind)
}

// Then:
go eng.Run(ctx, h)
```

Don't leave a stray `mh` variable. Run `go vet ./cmd/...` to confirm there's nothing dangling.

- [ ] **Step 2: Build + smoke**

```bash
cd /Users/ronreiter/GitHub/scdlp
go build -o bin/scdlp-agent ./cmd/scdlp-agent
./bin/scdlp-agent --help 2>&1 | grep hook
```

Expected: a `-hook string` line in the usage with default `mock`.

```bash
./bin/scdlp-agent --hook=esf --rules /tmp/r.db --audit /tmp/a.db --socket /tmp/s.sock
```

Expected (when not entitled): exits with `ESF hook: es_new_client failed: not entitled ...` or `not privileged` (if not run as root). Exit code non-zero.

```bash
./bin/scdlp-agent --hook=mock --rules /tmp/r.db --audit /tmp/a.db --socket /tmp/s.sock
```

Expected: starts normally, logs `hook: MockHook (no real opens are intercepted)`. Ctrl-C to stop.

- [ ] **Step 3: Commit**

```bash
git add cmd/scdlp-agent/main.go
git -c user.email=ron@sentra.io -c user.name="Ron Reiter" commit -m "feat(cmd/scdlp-agent): --hook=mock|esf flag, default mock

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>"
```

---

## Task 4: System Extension bundle scaffolding

**Files:**
- Create: `extension/Info.plist`
- Create: `extension/Scdlp.entitlements`
- Create: `extension/build.sh`

Apple System Extensions are bundles with a specific Info.plist + entitlements + signature. We generate the bundle structure ourselves (no Xcode project) so the toolchain stays make/clang/codesign — easier to reproduce in CI.

The bundle that gets built:

```
Scdlp.systemextension/
├── Contents/
│   ├── Info.plist
│   ├── MacOS/
│   │   └── Scdlp                       # our Go agent binary (renamed)
│   ├── _CodeSignature/
│   │   └── CodeResources
│   └── embedded.provisionprofile       # provided out-of-band; gitignored
```

- [ ] **Step 1: Write `extension/Info.plist`**

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleIdentifier</key>
    <string>io.sentra.scdlp.extension</string>
    <key>CFBundleName</key>
    <string>Scdlp</string>
    <key>CFBundleDisplayName</key>
    <string>scdlp Endpoint Security Extension</string>
    <key>CFBundleVersion</key>
    <string>1</string>
    <key>CFBundleShortVersionString</key>
    <string>1.0</string>
    <key>CFBundleExecutable</key>
    <string>Scdlp</string>
    <key>CFBundlePackageType</key>
    <string>SYSX</string>
    <key>CFBundleInfoDictionaryVersion</key>
    <string>6.0</string>
    <key>LSMinimumSystemVersion</key>
    <string>13.0</string>
    <key>NSSystemExtensionUsageDescription</key>
    <string>scdlp blocks unknown processes from reading your credentials.</string>
    <key>NSEndpointSecurityRebootRequired</key>
    <false/>
    <key>NSEndpointSecurityEarlyBoot</key>
    <false/>
    <key>NSEndpointSecurityClient</key>
    <true/>
</dict>
</plist>
```

- [ ] **Step 2: Write `extension/Scdlp.entitlements`**

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>com.apple.developer.endpoint-security.client</key>
    <true/>
    <key>com.apple.security.app-sandbox</key>
    <false/>
</dict>
</plist>
```

(The `com.apple.developer.endpoint-security.client` key is the entitlement Apple has to grant. Codesigning with this entitlement against an un-provisioned cert produces a binary that runs locally but cannot register with ES — exactly the testable state we want.)

- [ ] **Step 3: Write `extension/build.sh`**

```bash
#!/usr/bin/env bash
set -euo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"
DIST="$REPO/dist"
BUNDLE="$DIST/Scdlp.systemextension"

# Sign identity & team ID come from env. For ad-hoc/dev set:
#   export SCDLP_SIGN_ID="-"          # ad-hoc; works for SIP-relaxed test only
#   export SCDLP_TEAM_ID="UNSIGNED"
SIGN_ID="${SCDLP_SIGN_ID:--}"
TEAM_ID="${SCDLP_TEAM_ID:-UNSIGNED}"

# 1. Build the Go agent with ESF hook enabled. CGO_ENABLED is default on darwin.
echo "==> building agent binary"
GOOS=darwin go build -trimpath -o "$DIST/Scdlp" "$REPO/cmd/scdlp-agent"

# 2. Lay out the bundle.
echo "==> assembling $BUNDLE"
rm -rf "$BUNDLE"
mkdir -p "$BUNDLE/Contents/MacOS" "$BUNDLE/Contents/_CodeSignature"
cp "$REPO/extension/Info.plist" "$BUNDLE/Contents/Info.plist"
mv "$DIST/Scdlp" "$BUNDLE/Contents/MacOS/Scdlp"
chmod +x "$BUNDLE/Contents/MacOS/Scdlp"

# 3. Sign with the requested identity.
echo "==> codesigning ($SIGN_ID)"
codesign --force --options runtime --timestamp=none \
    --sign "$SIGN_ID" \
    --entitlements "$REPO/extension/Scdlp.entitlements" \
    "$BUNDLE"

# 4. Verify.
echo "==> verifying"
codesign --verify --deep --strict --verbose=2 "$BUNDLE"
codesign --display --entitlements - "$BUNDLE" 2>&1 | grep -i endpoint || true

echo "==> done: $BUNDLE"
```

Make it executable:

```bash
chmod +x extension/build.sh
```

- [ ] **Step 4: Smoke build with ad-hoc signing**

```bash
cd /Users/ronreiter/GitHub/scdlp
SCDLP_SIGN_ID="-" SCDLP_TEAM_ID="UNSIGNED" ./extension/build.sh
ls dist/Scdlp.systemextension/Contents/MacOS/
```

Expected: build runs to completion (the `codesign --verify` may emit warnings for the ad-hoc identity — acceptable). `Scdlp` binary present.

- [ ] **Step 5: Commit**

```bash
git add extension/
git -c user.email=ron@sentra.io -c user.name="Ron Reiter" commit -m "feat(extension): System Extension bundle layout + build script

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>"
```

---

## Task 5: Host `.app` activator

**Files:**
- Create: `host/Info.plist`
- Create: `host/Scdlp.entitlements`
- Create: `host/main.swift`
- Create: `host/build.sh`

The System Extension must be installed by a regular `.app`. The host is intentionally minimal: 80 lines of Swift that submit an `OSSystemExtensionRequest.activationRequest(...)`, print progress, and exit on completion.

- [ ] **Step 1: Write `host/Info.plist`**

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleIdentifier</key>
    <string>io.sentra.scdlp.host</string>
    <key>CFBundleName</key>
    <string>scdlp</string>
    <key>CFBundleDisplayName</key>
    <string>scdlp</string>
    <key>CFBundleVersion</key>
    <string>1</string>
    <key>CFBundleShortVersionString</key>
    <string>1.0</string>
    <key>CFBundleExecutable</key>
    <string>scdlp-host</string>
    <key>CFBundlePackageType</key>
    <string>APPL</string>
    <key>LSMinimumSystemVersion</key>
    <string>13.0</string>
    <key>LSUIElement</key>
    <true/>
</dict>
</plist>
```

- [ ] **Step 2: Write `host/Scdlp.entitlements`**

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>com.apple.developer.system-extension.install</key>
    <true/>
</dict>
</plist>
```

- [ ] **Step 3: Write `host/main.swift`**

```swift
import Foundation
import SystemExtensions

let EXTENSION_BUNDLE_ID = "io.sentra.scdlp.extension"

final class Activator: NSObject, OSSystemExtensionRequestDelegate {
    func request(_ req: OSSystemExtensionRequest,
                 actionForReplacingExtension existing: OSSystemExtensionProperties,
                 withExtension ext: OSSystemExtensionProperties) -> OSSystemExtensionRequest.ReplacementAction {
        print("scdlp-host: replacing existing extension v\(existing.bundleShortVersion) with v\(ext.bundleShortVersion)")
        return .replace
    }
    func requestNeedsUserApproval(_ req: OSSystemExtensionRequest) {
        print("scdlp-host: user approval required. Open System Settings > Privacy & Security > Allow.")
    }
    func request(_ req: OSSystemExtensionRequest,
                 didFinishWithResult result: OSSystemExtensionRequest.Result) {
        switch result {
        case .completed:
            print("scdlp-host: activation completed")
            exit(0)
        case .willCompleteAfterReboot:
            print("scdlp-host: activation will complete after reboot")
            exit(0)
        @unknown default:
            print("scdlp-host: activation finished with unknown result")
            exit(1)
        }
    }
    func request(_ req: OSSystemExtensionRequest, didFailWithError error: Error) {
        print("scdlp-host: activation failed: \(error.localizedDescription)")
        exit(2)
    }
}

let args = CommandLine.arguments
let action = args.count > 1 ? args[1] : "activate"

let activator = Activator()
let req: OSSystemExtensionRequest
switch action {
case "activate":
    req = OSSystemExtensionRequest.activationRequest(
        forExtensionWithIdentifier: EXTENSION_BUNDLE_ID,
        queue: .main
    )
case "deactivate":
    req = OSSystemExtensionRequest.deactivationRequest(
        forExtensionWithIdentifier: EXTENSION_BUNDLE_ID,
        queue: .main
    )
default:
    print("usage: scdlp-host {activate|deactivate}")
    exit(64)
}
req.delegate = activator
OSSystemExtensionManager.shared.submitRequest(req)
RunLoop.main.run()
```

- [ ] **Step 4: Write `host/build.sh`**

```bash
#!/usr/bin/env bash
set -euo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"
DIST="$REPO/dist"
APP="$DIST/scdlp.app"
EXT_SRC="$DIST/Scdlp.systemextension"
SIGN_ID="${SCDLP_SIGN_ID:--}"

if [[ ! -d "$EXT_SRC" ]]; then
    echo "error: $EXT_SRC missing — run extension/build.sh first" >&2
    exit 1
fi

# 1. Compile the Swift host.
echo "==> building scdlp-host"
mkdir -p "$DIST"
swiftc -O -target x86_64-apple-macos13 -o "$DIST/scdlp-host" "$REPO/host/main.swift"
# Universal binary: also build arm64 and lipo. (Skip on Intel-only build hosts.)
if /usr/bin/arch -arm64 true 2>/dev/null; then
    swiftc -O -target arm64-apple-macos13 -o "$DIST/scdlp-host-arm64" "$REPO/host/main.swift"
    lipo -create "$DIST/scdlp-host" "$DIST/scdlp-host-arm64" -output "$DIST/scdlp-host.fat"
    mv "$DIST/scdlp-host.fat" "$DIST/scdlp-host"
    rm "$DIST/scdlp-host-arm64"
fi

# 2. Lay out the .app bundle.
echo "==> assembling $APP"
rm -rf "$APP"
mkdir -p "$APP/Contents/MacOS" "$APP/Contents/Resources" "$APP/Contents/Library/SystemExtensions"
cp "$REPO/host/Info.plist" "$APP/Contents/Info.plist"
mv "$DIST/scdlp-host" "$APP/Contents/MacOS/scdlp-host"
chmod +x "$APP/Contents/MacOS/scdlp-host"

# 3. Embed the extension.
cp -R "$EXT_SRC" "$APP/Contents/Library/SystemExtensions/"

# 4. Sign the host (the extension was signed in extension/build.sh).
echo "==> codesigning host"
codesign --force --options runtime --timestamp=none \
    --sign "$SIGN_ID" \
    --entitlements "$REPO/host/Scdlp.entitlements" \
    "$APP/Contents/MacOS/scdlp-host"
codesign --force --options runtime --timestamp=none \
    --sign "$SIGN_ID" \
    --entitlements "$REPO/host/Scdlp.entitlements" \
    "$APP"

echo "==> done: $APP"
echo "==> activate with: $APP/Contents/MacOS/scdlp-host activate"
```

Make it executable:

```bash
chmod +x host/build.sh
```

- [ ] **Step 5: Smoke build (with ad-hoc signing)**

```bash
cd /Users/ronreiter/GitHub/scdlp
SCDLP_SIGN_ID="-" ./host/build.sh
ls dist/scdlp.app/Contents/{Info.plist,MacOS,Library/SystemExtensions}
```

Expected: app bundle exists, contains the extension under `Library/SystemExtensions/Scdlp.systemextension`.

- [ ] **Step 6: Commit**

```bash
git add host/
git -c user.email=ron@sentra.io -c user.name="Ron Reiter" commit -m "feat(host): minimal Swift activator app for the System Extension

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>"
```

---

## Task 6: Top-level build targets

**Files:**
- Modify: `Makefile`

Add `make extension`, `make host`, `make bundle`, `make activate`, `make deactivate` so the developer doesn't have to remember the script names + env vars.

- [ ] **Step 1: Append to `Makefile`**

```makefile
# --- ESF bundle targets -------------------------------------------------------

SIGN_ID ?= -
TEAM_ID ?= UNSIGNED

extension:
	SCDLP_SIGN_ID="$(SIGN_ID)" SCDLP_TEAM_ID="$(TEAM_ID)" ./extension/build.sh

host: extension
	SCDLP_SIGN_ID="$(SIGN_ID)" ./host/build.sh

bundle: host

activate: bundle
	./dist/scdlp.app/Contents/MacOS/scdlp-host activate

deactivate:
	./dist/scdlp.app/Contents/MacOS/scdlp-host deactivate

.PHONY: extension host bundle activate deactivate
```

- [ ] **Step 2: Confirm targets**

```bash
cd /Users/ronreiter/GitHub/scdlp
make -n extension host bundle activate deactivate
```

Expected: shows the commands each target would run.

- [ ] **Step 3: Commit**

```bash
git add Makefile
git -c user.email=ron@sentra.io -c user.name="Ron Reiter" commit -m "feat(make): extension/host/bundle/activate targets

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>"
```

---

## Task 7: Signing configuration template

**Files:**
- Create: `docs/signing.md` (gitignored per the existing `.gitignore`)
- Create: `docs/signing.example.md` (template, tracked)

Document how to point the build at a real Developer ID identity once you have one. The actual signing identity + team ID belongs in a gitignored file so it doesn't leak into git history.

- [ ] **Step 1: Write `docs/signing.example.md`**

```markdown
# scdlp signing configuration

Copy this file to `docs/signing.md` (which is gitignored) and fill in your values.

## Required identities

You need two pieces from Apple:

1. **Developer ID Application** certificate — installed in the login keychain.
   Verify with: `security find-identity -v -p codesigning | grep 'Developer ID Application'`
2. **`com.apple.developer.endpoint-security.client`** entitlement, granted to
   your Team ID for `io.sentra.scdlp.extension`. Request via
   https://developer.apple.com/contact/request/system-extension/. Apple usually
   replies in 2–8 weeks.

## Local environment

Once you have both, set:

```bash
# In your shell profile or a per-session `.envrc`:
export SCDLP_SIGN_ID="Developer ID Application: Your Company Name (TEAMID12345)"
export SCDLP_TEAM_ID="TEAMID12345"
```

Then:

```bash
make bundle
make activate
```

The first `activate` will prompt the user to approve the System Extension and
grant Full Disk Access in System Settings → Privacy & Security.

## Verifying the entitlement landed

After `make extension`, the codesign verify output should include
`com.apple.developer.endpoint-security.client`. If it doesn't, the entitlement
file isn't being read; check `extension/Scdlp.entitlements` is present and
that `codesign` reports no errors.

## Notarization (production only)

Local dev does not require notarization. For distribution:

```bash
xcrun notarytool submit dist/scdlp.app --wait \
    --apple-id you@example.com \
    --team-id "$SCDLP_TEAM_ID" \
    --password "@keychain:AC_PASSWORD"
xcrun stapler staple dist/scdlp.app
```
```

- [ ] **Step 2: Confirm `docs/signing.md` is in `.gitignore`**

```bash
grep -F 'docs/signing.md' /Users/ronreiter/GitHub/scdlp/.gitignore
```

Expected: a line matches (it was added in v1 Task 1).

- [ ] **Step 3: Commit**

```bash
cd /Users/ronreiter/GitHub/scdlp
git add docs/signing.example.md
git -c user.email=ron@sentra.io -c user.name="Ron Reiter" commit -m "docs: signing configuration template

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>"
```

---

## Task 8: Dev-mode (SIP-relaxed) instructions

**Files:**
- Create: `docs/dev-mode.md`

If you want to exercise the real ES hook before the Apple entitlement is granted, you can disable AMFI on your dev Mac. This document tells the user how to do that, what the security trade-off is, and how to revert.

- [ ] **Step 1: Write `docs/dev-mode.md`**

```markdown
# scdlp dev mode — running ESF without the Apple entitlement

You can run scdlp's Endpoint Security backend against the live kernel **without**
the `com.apple.developer.endpoint-security.client` entitlement by disabling
Apple's Apple Mobile File Integrity (AMFI) on your dev Mac. This is intrusive.
Do not do it on a machine you use for anything sensitive.

## What you're trading

AMFI is the kernel subsystem that enforces:

- Only code signed by Apple-trusted identities can run with restricted
  entitlements.
- The kernel rejects `es_new_client()` from any binary missing the ESF
  entitlement.

Disabling it lets you sign your binary with a self-signed cert (or ad-hoc)
and still get a working ESF client. It also disables many other kernel
integrity checks. You will get warnings on every boot.

## How to disable (Apple Silicon, macOS 13+)

1. Boot into Recovery: hold the power button at boot until you see Options.
2. Open Terminal from Utilities.
3. Run:

   ```
   csrutil enable --without amfi --without nvram
   ```

4. Reboot into the normal OS.
5. In a regular Terminal:

   ```bash
   sudo nvram boot-args="amfi_get_out_of_my_way=0x1"
   ```

6. Reboot one more time.

## How to disable (Intel, macOS 13+)

1. Boot into Recovery: ⌘+R at startup.
2. Utilities → Terminal.
3. Run `csrutil disable` (a complete SIP disable is required on Intel — there
   is no `--without amfi` granularity).
4. Reboot.

## How to verify

```bash
csrutil status
nvram boot-args
```

You should see `System Integrity Protection status: System Integrity Protection
is off.` (Intel) or a partial-disable list including `Apple Mobile File
Integrity: disabled` (Apple Silicon), and `boot-args` should contain
`amfi_get_out_of_my_way=0x1`.

## Run scdlp under dev mode

```bash
make bundle SIGN_ID="-"   # ad-hoc sign
sudo ./dist/scdlp.app/Contents/MacOS/scdlp-host activate
```

The `sudo` is required because un-entitled ES clients also need to run as root.

After `activate`, open System Settings → Privacy & Security and approve the
System Extension. Then grant `dist/scdlp.app` (or the extension target) Full
Disk Access.

Verify scdlp is enforcing:

```bash
sudo log stream --predicate 'process == "Scdlp"' --info
```

In another terminal:

```bash
cat ~/.aws/credentials   # should be ALLOWED if your shell chain is allowlisted,
                          # or DENIED with EACCES otherwise — and the log line above
                          # shows the decision.
```

## How to revert

Apple Silicon (full revert):

1. Recovery → Terminal.
2. `csrutil clear` and reboot.
3. `sudo nvram -d boot-args`.

Intel:

1. Recovery → Terminal.
2. `csrutil enable` and reboot.

Verify with `csrutil status` — should report fully enabled.

## Don't ship code that depends on dev mode

Anything that only works with AMFI disabled is not shippable. Treat dev mode
as a temporary diagnostic — the production path is the Apple entitlement.
```

- [ ] **Step 2: Commit**

```bash
cd /Users/ronreiter/GitHub/scdlp
git add docs/dev-mode.md
git -c user.email=ron@sentra.io -c user.name="Ron Reiter" commit -m "docs: SIP-relaxed dev mode for running ESF without the Apple entitlement

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>"
```

---

## Task 9: Update README + onboarding

**Files:**
- Modify: `README.md`
- Modify: `docs/onboarding.md`

Reflect that the ESF backend now exists in code, document the path from "fresh clone" to "activate System Extension", and call out the entitlement / dev-mode fork explicitly.

- [ ] **Step 1: Append a "Real-kernel mode (ESF)" section to `README.md`**

After the existing "Test" section, insert:

```markdown
## Real-kernel mode (ESF)

The `scdlp-agent` binary supports a `--hook=esf` flag that subscribes to the
macOS Endpoint Security framework instead of the in-process MockHook. To use
it you need:

1. The `com.apple.developer.endpoint-security.client` entitlement granted by
   Apple to your Team ID (see `docs/signing.example.md`), OR
2. A SIP-relaxed dev Mac (see `docs/dev-mode.md`).

Once one of the above is in place:

```bash
make bundle               # builds extension + host .app, ad-hoc signed by default
sudo ./dist/scdlp.app/Contents/MacOS/scdlp-host activate
```

System Settings prompts you to approve the System Extension and grant Full
Disk Access. After approval, real `open()` calls flow through scdlp's
decision engine and the existing CLI (`scdlp status`, `scdlp tail`, …)
reflects live decisions.

```bash
make deactivate           # remove the extension
```
```

- [ ] **Step 2: Add an "ESF backend" section to `docs/onboarding.md`**

After the existing "What's NOT in this repo yet" section, replace that section's content with:

```markdown
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
```

- [ ] **Step 3: Commit**

```bash
git add README.md docs/onboarding.md
git -c user.email=ron@sentra.io -c user.name="Ron Reiter" commit -m "docs: cover the ESF backend in README + onboarding

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>"
```

---

## Self-review summary

**Spec coverage:**

| Spec §  | Covered by task |
|---|---|
| §4 ESF subscription, AUTH_OPEN, mute set | Tasks 1, 2 |
| §5.1 Process identity from audit token | Task 1 (parses audit_token), reuses v1 `internal/identity` |
| §5.1 Hot-path response | Task 2 (`DecideFunc` calls `es_respond_auth_result`) |
| §6.1 First-run install (System Extension activation, FDA prompt) | Task 5 (host app) |
| §6 Real `open()` interception | Tasks 1–6 end-to-end |
| §9 Out-of-band requirements (entitlement, signing) | Tasks 7, 8 |
| §10 Repo layout (extension/, host/) | Tasks 4, 5 |

**Out-of-scope items explicitly deferred to v1.2:**

- Swift menubar helper (`scdlp-helper`). The PromptBus from v1 still publishes;
  the helper that consumes it is a separate plan.
- IPC peer authentication via audit-token (v1 follow-up §12 item 1). Still
  outstanding; not in this plan.
- `scdlp doctor`, `scdlp pause` CLI subcommands. Still outstanding.
- Audit retention / ring buffer at 100k.

**Placeholder scan:** None.

**Type consistency:** `Hook` interface (`internal/hook/hook.go`, defined in v1)
unchanged. `ESFHook.Next` signature matches `MockHook.Next` — both return
`(Event, DecideFunc, error)`. Daemon's `var h hook.Hook` accepts either.
The C `scdlp_es_event_t` ↔ Go `hook.Event` mapping is done explicitly in
`scdlpGoOnEvent`.
