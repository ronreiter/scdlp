package classify

import "testing"

func TestIsPlaceholder(t *testing.T) {
	yes := []string{
		"changeme", "CHANGEME", "xxx", "your-token-here", "<your-key>",
		"${SOMETHING}", "${MY_VAR}", "todo", "TODO", "fixme", "placeholder",
	}
	for _, v := range yes {
		if !IsPlaceholder(v) {
			t.Errorf("IsPlaceholder(%q) = false, want true", v)
		}
	}
	no := []string{"AKIA0123456789ABCDEF", "kJ8sP2qLmX7vR9nT5aBcDeFgHiJk", "real-looking-value"}
	for _, v := range no {
		if IsPlaceholder(v) {
			t.Errorf("IsPlaceholder(%q) = true, want false", v)
		}
	}
}

func TestIsURLWithoutEmbeddedCreds(t *testing.T) {
	yes := []string{
		"https://api.example.com/v1",
		"http://localhost:8080",
		"postgres://localhost/db",
	}
	for _, v := range yes {
		if !IsURLWithoutEmbeddedCreds(v) {
			t.Errorf("IsURLWithoutEmbeddedCreds(%q) = false, want true", v)
		}
	}
	no := []string{
		"postgres://user:secret@host/db",
		"https://user:pass@example.com",
	}
	for _, v := range no {
		if IsURLWithoutEmbeddedCreds(v) {
			t.Errorf("IsURLWithoutEmbeddedCreds(%q) = true, want false", v)
		}
	}
}

func TestIsBooleanOrNumeric(t *testing.T) {
	yes := []string{"true", "false", "TRUE", "FALSE", "yes", "no", "1", "0", "42", "3.14"}
	for _, v := range yes {
		if !IsBooleanOrNumeric(v) {
			t.Errorf("IsBooleanOrNumeric(%q) = false, want true", v)
		}
	}
	no := []string{"info", "AKIA0123", "abc123"}
	for _, v := range no {
		if IsBooleanOrNumeric(v) {
			t.Errorf("IsBooleanOrNumeric(%q) = true, want false", v)
		}
	}
}
