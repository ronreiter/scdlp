package classify

import "testing"

func TestEveryProviderHasAPattern(t *testing.T) {
	for name := range ProviderPrefixes {
		if _, ok := ProviderPatterns[name]; !ok {
			t.Errorf("provider %q has prefixes but no validation pattern", name)
		}
	}
}

func TestKnownGoodValuesMatchPatterns(t *testing.T) {
	cases := []struct {
		provider, value string
	}{
		{"aws-access-key", "AKIA0123456789ABCDEF"},
		{"github-pat", "ghp_" + strRepeat("A", 36)},
		{"slack-bot", "xoxb-123456789012-1234567890123-" + strRepeat("a", 24)},
		{"openai", "sk-" + strRepeat("A", 48)},
		{"stripe-live", "sk_live_" + strRepeat("a", 24)},
		{"google-api", "AIza" + strRepeat("A", 35)},
		{"npm-token", "npm_" + strRepeat("A", 36)},
		{"jwt", "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"},
	}
	for _, c := range cases {
		p := ProviderPatterns[c.provider]
		if p == nil {
			t.Errorf("no pattern for %s", c.provider)
			continue
		}
		if !p.MatchString(c.value) {
			t.Errorf("%s: pattern did not match %q", c.provider, c.value)
		}
	}
}

func TestKnownBadValuesDoNotMatchPatterns(t *testing.T) {
	cases := []struct {
		provider, value string
	}{
		{"aws-access-key", "AKIAtooshort"},
		{"github-pat", "ghp_short"},
		{"openai", "sk-tiny"},
	}
	for _, c := range cases {
		p := ProviderPatterns[c.provider]
		if p != nil && p.MatchString(c.value) {
			t.Errorf("%s: pattern unexpectedly matched %q", c.provider, c.value)
		}
	}
}

func strRepeat(s string, n int) string {
	out := make([]byte, 0, len(s)*n)
	for i := 0; i < n; i++ {
		out = append(out, s...)
	}
	return string(out)
}
