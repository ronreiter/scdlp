package classify

import (
	"math"
	"testing"
)

func TestEntropyZeroForEmpty(t *testing.T) {
	if got := ShannonEntropy(""); got != 0 {
		t.Errorf("ShannonEntropy(\"\") = %v, want 0", got)
	}
}

func TestEntropyLowForRepeats(t *testing.T) {
	if got := ShannonEntropy("aaaaaaaa"); got != 0 {
		t.Errorf("ShannonEntropy(repeat) = %v, want 0", got)
	}
}

func TestEntropyHighForRandomBase64(t *testing.T) {
	value := "kJ8sP2qLmX7vR9nT5aBcDeFgHiJkLmNoPqRsTuVwXyZ"
	got := ShannonEntropy(value)
	if got < 4.5 {
		t.Errorf("ShannonEntropy(random-ish) = %v, want >=4.5", got)
	}
}

func TestEntropyOfNumericIsLow(t *testing.T) {
	got := ShannonEntropy("01234567890123456789")
	if got > 3.5 {
		t.Errorf("ShannonEntropy(digits) = %v, want <3.5", got)
	}
}

// silence unused-import error on math if not used elsewhere
var _ = math.Sqrt

func TestSecretishKeyName(t *testing.T) {
	yes := []string{
		"API_KEY", "AUTH_TOKEN", "DB_PASSWORD", "CLIENT_SECRET",
		"PRIVATE_KEY", "ACCESS_KEY_ID", "credentials", "Slack_API_Key",
	}
	for _, k := range yes {
		if !SecretishKeyName(k) {
			t.Errorf("SecretishKeyName(%q) = false, want true", k)
		}
	}
	no := []string{
		"NODE_ENV", "LOG_LEVEL", "PORT", "PATH", "HOSTNAME", "DEBUG", "TIMEZONE",
	}
	for _, k := range no {
		if SecretishKeyName(k) {
			t.Errorf("SecretishKeyName(%q) = true, want false", k)
		}
	}
}
