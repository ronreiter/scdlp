// Package identity computes a stable per-process identity key from the
// executable path and the ancestry chain of parents up to launchd.
package identity

import (
	"crypto/sha256"
	"encoding/hex"
	"path/filepath"
	"strings"
)

// MaxDepth bounds the ancestry chain captured in the identity. Past this
// depth the tail is collapsed and the identity is the same regardless of
// what's beyond.
const MaxDepth = 8

// Identity is a process's stable, hashable identity for the allowlist.
type Identity struct {
	PID        int      // runtime PID — not part of the key, audit only
	Exe        string   // absolute executable path
	Chain      []string // index 0 is self, last is the nearest ancestor we walked to
	KeyHex     string   // sha256 of normalized chain
	ExeOnlyKey string   // sha256 of just Exe (for exe-only allow rules)
}

// Compute fills KeyHex and ExeOnlyKey from Exe + Chain. Idempotent.
func (i *Identity) Compute() {
	chain := i.Chain
	if len(chain) > MaxDepth {
		chain = chain[:MaxDepth]
	}
	h := sha256.New()
	for n, c := range chain {
		if n > 0 {
			h.Write([]byte{0})
		}
		h.Write([]byte(c))
	}
	i.KeyHex = hex.EncodeToString(h.Sum(nil))

	eh := sha256.Sum256([]byte("EXE:" + i.Exe))
	i.ExeOnlyKey = "EXE:" + hex.EncodeToString(eh[:])
}

// HumanChain returns a short, readable representation of the chain for UI/audit.
func (i *Identity) HumanChain() []string {
	out := make([]string, 0, len(i.Chain)+1)
	for n, c := range i.Chain {
		if n >= MaxDepth {
			out = append(out, "…")
			break
		}
		out = append(out, filepath.Base(c))
	}
	return out
}

// HumanChainStr joins HumanChain with " ← ".
func (i *Identity) HumanChainStr() string {
	return strings.Join(i.HumanChain(), " ← ")
}
