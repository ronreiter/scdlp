package identity

import "testing"

func TestCompute_DeterministicKey(t *testing.T) {
	a := Identity{
		Exe:   "/usr/local/bin/aws",
		Chain: []string{"/usr/local/bin/aws", "/bin/zsh", "/Applications/Utilities/Terminal.app/Contents/MacOS/Terminal", "/sbin/launchd"},
	}
	a.Compute()
	if a.KeyHex == "" {
		t.Fatal("KeyHex empty")
	}

	b := Identity{
		Exe:   a.Exe,
		Chain: append([]string{}, a.Chain...),
	}
	b.Compute()
	if a.KeyHex != b.KeyHex {
		t.Fatalf("same input should produce same key, got %q vs %q", a.KeyHex, b.KeyHex)
	}
}

func TestCompute_OrderMatters(t *testing.T) {
	a := Identity{
		Exe:   "/usr/local/bin/aws",
		Chain: []string{"/usr/local/bin/aws", "/bin/zsh"},
	}
	a.Compute()
	b := Identity{
		Exe:   "/usr/local/bin/aws",
		Chain: []string{"/bin/zsh", "/usr/local/bin/aws"},
	}
	b.Compute()
	if a.KeyHex == b.KeyHex {
		t.Fatal("reversed chain should produce different key")
	}
}

func TestCompute_ExeOnlyKey(t *testing.T) {
	a := Identity{Exe: "/usr/local/bin/aws"}
	a.Compute()
	if a.ExeOnlyKey == "" {
		t.Fatal("ExeOnlyKey empty")
	}
}

func TestCompute_TruncatedAtMaxDepth(t *testing.T) {
	chain := make([]string, 20)
	for i := range chain {
		chain[i] = "/x"
	}
	a := Identity{Exe: "/x", Chain: chain}
	a.Compute()
	if len(a.HumanChain()) > MaxDepth+1 {
		t.Fatalf("HumanChain depth %d exceeds MaxDepth+1=%d", len(a.HumanChain()), MaxDepth+1)
	}
}
