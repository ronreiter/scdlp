//go:build !darwin

package hook

import (
	"context"
	"errors"
)

type ESFHook struct{}

func NewESFHook() (*ESFHook, error) {
	return nil, errors.New("ESF hook is darwin-only")
}

func (*ESFHook) Next(ctx context.Context) (Event, DecideFunc, error) {
	return Event{}, nil, errors.New("ESF hook is darwin-only")
}

func (*ESFHook) Stats() ESFStats { return ESFStats{} }

func (*ESFHook) Close() error { return nil }
