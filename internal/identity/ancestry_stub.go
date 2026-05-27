//go:build !darwin

package identity

import (
	"errors"
	"os"
)

// Resolve walks the ancestry chain for pid up to MaxDepth.
// On non-darwin platforms this is a stub used for CI portability.
func Resolve(pid int) (Identity, error) {
	exe, err := os.Executable()
	if err != nil {
		return Identity{}, err
	}
	id := Identity{PID: pid, Exe: exe, Chain: []string{exe}}
	id.Compute()
	return id, errors.New("identity.Resolve: stub on non-darwin")
}
