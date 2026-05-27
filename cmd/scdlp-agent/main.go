// Command scdlp-agent runs the daemon: IPC server + decision engine + hook.
// Use --hook=mock (default) for development or --hook=esf for real Endpoint
// Security interception (requires entitlement/root).
package main

import (
	"context"
	"flag"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"github.com/ronreiter/scdlp/internal/agent"
	"github.com/ronreiter/scdlp/internal/audit"
	"github.com/ronreiter/scdlp/internal/hook"
	"github.com/ronreiter/scdlp/internal/ipc"
	"github.com/ronreiter/scdlp/internal/rules"
)

func main() {
	defaultDir := defaultStateDir()
	rulesPath := flag.String("rules", filepath.Join(defaultDir, "rules.db"), "rules DB path")
	auditPath := flag.String("audit", filepath.Join(defaultDir, "audit.db"), "audit DB path")
	sockPath := flag.String("socket", defaultSocketPath(), "IPC socket path")
	home := flag.String("home", os.Getenv("HOME"), "user home dir for path-rule expansion")
	hookKind := flag.String("hook", "mock", "event source: mock | esf")
	flag.Parse()

	_ = os.MkdirAll(filepath.Dir(*rulesPath), 0o755)
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

	be := newBackend(r, a)
	srv := ipc.NewServer(*sockPath, be)
	if err := srv.Start(); err != nil {
		log.Fatalf("ipc start: %v", err)
	}
	defer srv.Stop()
	log.Printf("scdlp-agent up: socket=%s rules=%s audit=%s", *sockPath, *rulesPath, *auditPath)

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

	// Drain prompts to stderr; the Swift helper will subscribe over IPC later.
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

func defaultStateDir() string {
	if u := os.Getenv("SCDLP_STATE_DIR"); u != "" {
		return u
	}
	return filepath.Join(os.Getenv("HOME"), ".scdlp")
}

func defaultSocketPath() string {
	if u := os.Getenv("SCDLP_SOCKET"); u != "" {
		return u
	}
	return filepath.Join(os.TempDir(), "scdlp.sock")
}
