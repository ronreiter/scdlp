//go:build darwin

package hook

import (
	"strings"
	"testing"
)

func TestNewESFHook_ReportsEntitlementError(t *testing.T) {
	h, err := NewESFHook()
	if err == nil {
		_ = h.Close()
		t.Skip("ESF hook actually succeeded; this Mac is entitled. Skipping un-entitled check.")
	}
	msg := err.Error()
	if !strings.Contains(msg, "not entitled") &&
		!strings.Contains(msg, "not privileged") &&
		!strings.Contains(msg, "not permitted") &&
		!strings.Contains(msg, "TCC denied") {
		t.Fatalf("want error mentioning entitlement/privilege/permission/TCC, got %v", err)
	}
}
