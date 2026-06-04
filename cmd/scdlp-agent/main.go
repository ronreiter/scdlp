// Command scdlp-agent runs the daemon: IPC server + decision engine + hook.
//
// Two launch contexts:
//
//  1. Manual CLI: defaults to --hook=mock, state under $HOME/.scdlp, socket
//     under $TMPDIR, log to stderr. Suitable for `task run:mock`.
//  2. System Extension (launched by sysextd): detected by checking whether
//     the executable path lives under /Library/SystemExtensions/. In that
//     case --hook=esf, state under /Library/Application Support/scdlp/,
//     IPC socket disabled (the sysextd sandbox blocks Unix-socket binds),
//     and log writes go to <stateDir>/extension.log since stderr is dropped.
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/ronreiter/scdlp/internal/agent"
	"github.com/ronreiter/scdlp/internal/audit"
	"github.com/ronreiter/scdlp/internal/classify"
	"github.com/ronreiter/scdlp/internal/config"
	"github.com/ronreiter/scdlp/internal/control"
	"github.com/ronreiter/scdlp/internal/hook"
	"github.com/ronreiter/scdlp/internal/ipc"
	"github.com/ronreiter/scdlp/internal/promptspool"
	"github.com/ronreiter/scdlp/internal/rules"
)

func main() {
	inSysExt := runningInSystemExtension()
	defaultDir := defaultStateDir(inSysExt)
	defaultHook := "mock"
	defaultSock := defaultSocketPath()
	defaultHome := os.Getenv("HOME")
	if inSysExt {
		defaultHook = "esf"
		defaultSock = "" // sandbox blocks /tmp socket bind
		if defaultHome == "" || defaultHome == "/var/root" {
			defaultHome = consoleUserHome()
		}
	}

	rulesPath := flag.String("rules", filepath.Join(defaultDir, "rules.db"), "rules DB path")
	auditPath := flag.String("audit", filepath.Join(defaultDir, "audit.db"), "audit DB path")
	sockPath := flag.String("socket", defaultSock, "IPC socket path (empty = disabled)")
	home := flag.String("home", defaultHome, "user home dir for path-rule expansion")
	hookKind := flag.String("hook", defaultHook, "event source: mock | esf")
	// Monitor-only logs/audits decisions but never denies. The default is now
	// false: with the approval prompt in place, unknown in-scope reads are
	// denied (deny-first) and a popup is raised. Pass --monitor to observe
	// without enforcing.
	monitorOnly := flag.Bool("monitor", false, "monitor-only: log/audit decisions but never deny")
	flag.Parse()

	// The glob policy lives in the world-writable control dir so the menu bar
	// app can edit it; it's the single source of truth (loaded here, watched
	// for live edits below). Falls back to the default policy when absent.
	controlDir := filepath.Join(defaultDir, "control")
	policyPath := filepath.Join(controlDir, "policy.json")
	scanCfg := config.Load(policyPath)

	if err := os.MkdirAll(filepath.Dir(*rulesPath), 0o750); err != nil {
		// stderr may be /dev/null in sysextd; best-effort.
		fmt.Fprintln(os.Stderr, "mkdir state:", err)
	}

	if inSysExt {
		if err := setupSysExtLogging(defaultDir); err != nil {
			fmt.Fprintln(os.Stderr, "log setup:", err)
		}
		log.Printf("scdlp-agent (system extension) starting; exe=%s home=%s state=%s",
			selfExe(), *home, defaultDir)
	}

	r, err := rules.Open(*rulesPath)
	if err != nil {
		log.Fatalf("open rules: %v", err)
	}
	defer r.Close()
	a, err := audit.Open(*auditPath)
	if err != nil {
		log.Fatalf("open audit: %v", err)
	}
	defer a.Close()

	bus := agent.NewPromptBus(64)
	eng := agent.New(agent.Config{
		Homes: []string{*home}, Rules: r, Audit: a, Bus: bus,
		MonitorOnly: *monitorOnly,
		Scope:       scanCfg,
		// Content tier: scan the first 4 KiB of prompt-flagged files; benign
		// ones are allowed without a prompt (ReadHead defaults to disk).
		Classifier: classify.New(),
		// Use the process logger (redirected to extension.log under sysextd)
		// rather than the engine's stderr default, which sysextd discards —
		// otherwise decision/monitor/panic logs would be invisible.
		Logger: log.Default(),
	})
	if *monitorOnly {
		log.Print("monitor-only mode: decisions are logged/audited but never enforced")
	}

	// Prompt spool: bridges blocked accesses to the user-session menu bar app.
	spool, err := promptspool.New(filepath.Join(defaultDir, "prompts"), r, log.Default())
	if err != nil {
		log.Printf("prompt spool unavailable: %v (prompts will only be logged)", err)
	}
	// Fail open when no prompt helper is alive to approve denials.
	if spool != nil {
		eng.SetHelperPresent(spool.HelperAlive)
	}

	// Control channel: the menu bar app edits control/policy.json (watched →
	// live SetPolicy) and drops revoke commands (applied to the rule store).
	ctl, err := control.New(controlDir, scanCfg, eng, r, log.Default())
	if err != nil {
		log.Printf("control channel unavailable: %v", err)
	} else {
		ctl.SetExportSources(a, r) // publish history.json + rules.json for the UI
	}
	log.Printf("policy: %d glob rule(s) active", len(scanCfg.Policy))

	if *sockPath != "" {
		be := newBackend(r, a)
		srv := ipc.NewServer(*sockPath, be)
		if err := srv.Start(); err != nil {
			log.Printf("ipc start failed: %v (continuing without IPC)", err)
		} else {
			defer srv.Stop()
			log.Printf("ipc listening on %s", *sockPath)
		}
	}
	log.Printf("scdlp-agent up: rules=%s audit=%s home=%s hook=%s",
		*rulesPath, *auditPath, *home, *hookKind)

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
		log.Print("hook: EndpointSecurity (subscribed)")
		// Heartbeat: periodically log throughput + deadline-budget counters so
		// we can see whether the agent is keeping up, whether the C deadline
		// timer is having to default events, and how much response headroom the
		// kernel actually gives us. Interval is short by default so we get at
		// least one sample even if the process is short-lived; override with
		// SCDLP_HEARTBEAT_SEC.
		hbSec := 5
		if v := os.Getenv("SCDLP_HEARTBEAT_SEC"); v != "" {
			if n, err := strconv.Atoi(v); err == nil && n > 0 {
				hbSec = n
			}
		}
		go func() {
			t := time.NewTicker(time.Duration(hbSec) * time.Second)
			defer t.Stop()
			for range t.C {
				s := eh.Stats()
				log.Printf("esf stats: seen=%d agent=%d deadlineDefault=%d queueFull=%d respondErr=%d queue=%d/%d budget(last/min)=%.0f/%.0fms",
					s.Seen, s.AgentDecided, s.DeadlineDefault, s.QueueFull, s.RespondError,
					s.QueueDepth, s.QueueCap,
					float64(s.LastDeadlineNs)/1e6, float64(s.MinDeadlineNs)/1e6)
			}
		}()
	default:
		log.Fatalf("unknown --hook %q (want mock|esf)", *hookKind)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() {
		for p := range bus.C() {
			log.Printf("PROMPT file=%s category=%s pid=%d identity=%s",
				p.FilePath, p.Category, p.PID, p.HumanIdentity)
			if spool != nil {
				if _, err := spool.Write(promptspool.Request{
					PID: p.PID, Exe: p.Exe, HumanChain: p.HumanIdentity,
					Path: p.FilePath, Category: p.Category,
					IdentityKey: p.IdentityKey, ExeOnlyKey: p.ExeOnlyKey,
				}); err != nil {
					log.Printf("spool write: %v", err)
				}
			}
		}
	}()
	if spool != nil {
		go spool.Watch(ctx) // apply replies (write rules on "always")
	}
	if ctl != nil {
		go ctl.Watch(ctx) // live policy edits + revoke commands
	}

	go eng.Run(ctx, h)

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)
	<-stop
	log.Print("scdlp-agent shutting down")
}

func runningInSystemExtension() bool {
	exe, err := os.Executable()
	if err != nil {
		return false
	}
	return strings.Contains(exe, "/Library/SystemExtensions/")
}

func selfExe() string {
	exe, _ := os.Executable()
	return exe
}

func defaultStateDir(inSysExt bool) string {
	if u := os.Getenv("SCDLP_STATE_DIR"); u != "" {
		return u
	}
	if inSysExt {
		return "/Library/Application Support/scdlp"
	}
	return filepath.Join(os.Getenv("HOME"), ".scdlp")
}

func defaultSocketPath() string {
	if u := os.Getenv("SCDLP_SOCKET"); u != "" {
		return u
	}
	return filepath.Join(os.TempDir(), "scdlp.sock")
}

// setupSysExtLogging redirects log output to a file under stateDir so we can
// see what the System Extension is doing — sysextd discards stderr.
func setupSysExtLogging(stateDir string) error {
	if err := os.MkdirAll(stateDir, 0o750); err != nil {
		return err
	}
	f, err := os.OpenFile(
		filepath.Join(stateDir, "extension.log"),
		os.O_CREATE|os.O_APPEND|os.O_WRONLY,
		0o640,
	)
	if err != nil {
		return err
	}
	log.SetOutput(f)
	log.SetFlags(log.LstdFlags | log.Lmicroseconds | log.Lshortfile)
	return nil
}

// consoleUserHome resolves the real interactive user's home dir when we're
// running as root via sysextd. Picks the first non-system entry under /Users;
// good enough for single-user dev Macs.
func consoleUserHome() string {
	entries, err := os.ReadDir("/Users")
	if err != nil {
		return ""
	}
	for _, e := range entries {
		if e.IsDir() && !strings.HasPrefix(e.Name(), ".") && e.Name() != "Shared" {
			return "/Users/" + e.Name()
		}
	}
	return ""
}
