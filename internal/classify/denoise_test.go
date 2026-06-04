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

func TestIsHashOrUUID(t *testing.T) {
	yes := []string{
		"9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08", // sha256 (64 hex)
		"a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0",                         // sha1 (40 hex)
		"5d41402abc4b2a76b9719d911017c592",                                 // md5 (32 hex)
		"550e8400-e29b-41d4-a716-446655440000",                             // uuid
	}
	for _, v := range yes {
		if !IsHashOrUUID(v) {
			t.Errorf("want IsHashOrUUID(%q)=true", v)
		}
	}
	no := []string{
		"wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", // base64-ish secret (has / and mixed)
		"SK0123456789abcdef0123456789abcdef",       // 34 chars, not a digest length
		"Xb9Kfated2QmZ1pR7sVn0LwYc4Hh6Tj8",         // mixed-base token
		"hello-world",
	}
	for _, v := range no {
		if IsHashOrUUID(v) {
			t.Errorf("want IsHashOrUUID(%q)=false", v)
		}
	}
}
