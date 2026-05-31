package agent

import (
	"os"
	"path/filepath"
	"sort"
	"testing"
	"time"

	"github.com/ronreiter/scdlp/internal/audit"
	"github.com/ronreiter/scdlp/internal/hook"
	"github.com/ronreiter/scdlp/internal/identity"
	"github.com/ronreiter/scdlp/internal/rules"
)

func BenchmarkDecide_Tier1Deny(b *testing.B) {
	home := b.TempDir()
	creds := filepath.Join(home, ".env")
	_ = os.WriteFile(creds, []byte("AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI\n"), 0o600)

	dir := b.TempDir()
	r, _ := rules.Open(filepath.Join(dir, "rules.db"))
	a, _ := audit.Open(filepath.Join(dir, "audit.db"))
	defer r.Close()
	defer a.Close()
	bus := NewPromptBus(64)
	eng := New(Config{
		Homes: []string{home}, Rules: r, Audit: a, Bus: bus,
		Resolver: fakeBenchResolver{},
	})
	ev := hook.Event{Path: creds, PID: 1234}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = eng.Decide(ev)
	}
}

type fakeBenchResolver struct{}

func (fakeBenchResolver) Resolve(pid int) (identity.Identity, error) {
	id := identity.Identity{Exe: "/usr/bin/node",
		Chain: []string{"/usr/bin/node", "/bin/sh", "/usr/local/bin/npm"}}
	id.Compute()
	return id, nil
}

func TestDecide_P99UnderBudget(t *testing.T) {
	// The decision path must be fast relative to the ES response deadline
	// (seconds). This guards against gross regressions on real hardware (~90µs
	// p99 locally), but shared CI runners have unpredictable latency, so skip
	// the sub-millisecond assertion there.
	if os.Getenv("CI") != "" {
		t.Skip("latency assertion is unreliable on shared CI runners")
	}
	home := t.TempDir()
	creds := filepath.Join(home, ".env")
	_ = os.WriteFile(creds, []byte("AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI\n"), 0o600)

	dir := t.TempDir()
	r, _ := rules.Open(filepath.Join(dir, "rules.db"))
	a, _ := audit.Open(filepath.Join(dir, "audit.db"))
	defer r.Close()
	defer a.Close()
	bus := NewPromptBus(64)
	eng := New(Config{
		Homes: []string{home}, Rules: r, Audit: a, Bus: bus,
		Resolver: fakeBenchResolver{},
	})

	const N = 5000
	ev := hook.Event{Path: creds, PID: 1234}
	durs := make([]time.Duration, 0, N)
	for i := 0; i < N; i++ {
		start := time.Now()
		_ = eng.Decide(ev)
		durs = append(durs, time.Since(start))
	}
	sort.Slice(durs, func(i, j int) bool { return durs[i] < durs[j] })
	p99 := durs[(99*N)/100]
	t.Logf("p50=%v p95=%v p99=%v", durs[N/2], durs[(95*N)/100], p99)
	if p99 > time.Millisecond {
		t.Fatalf("p99 too slow: %v", p99)
	}
}
