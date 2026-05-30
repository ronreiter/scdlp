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
	"strings"
	"syscall"

	"github.com/ronreiter/scdlp/internal/agent"
	"github.com/ronreiter/scdlp/internal/audit"
	"github.com/ronreiter/scdlp/internal/hook"
	"github.com/ronreiter/scdlp/internal/ipc"
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
		defaultSock = ""                // sandbox blocks /tmp socket bind
		if defaultHome == "" || defaultHome == "/var/root" {
			defaultHome = consoleUserHome()
		}
	}

	rulesPath := flag.String("rules", filepath.Join(defaultDir, "rules.db"), "rules DB path")
	auditPath := flag.String("audit", filepath.Join(defaultDir, "audit.db"), "audit DB path")
	sockPath := flag.String("socket", defaultSock, "IPC socket path (empty = disabled)")
	home := flag.String("home", defaultHome, "user home dir for path-rule expansion")
	hookKind := flag.String("hook", defaultHook, "event source: mock | esf")
	flag.Parse()

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
	})

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
	default:
		log.Fatalf("unknown --hook %q (want mock|esf)", *hookKind)
	}

	go func() {
		for p := range bus.C() {
			log.Printf("PROMPT file=%s category=%s pid=%d identity=%s",
				p.FilePath, p.Category, p.PID, p.HumanIdentity)
		}
	}()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
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
