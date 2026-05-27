package classify

import "testing"

func TestProviderPrefixesNonEmpty(t *testing.T) {
	if len(ProviderPrefixes) == 0 {
		t.Fatal("ProviderPrefixes is empty")
	}
	mustHave := []string{
		"aws-access-key",
		"github-pat",
		"slack-bot",
		"openai",
		"stripe-live",
		"google-api",
		"npm-token",
		"jwt",
	}
	for _, name := range mustHave {
		if _, ok := ProviderPrefixes[name]; !ok {
			t.Errorf("ProviderPrefixes missing %q", name)
		}
	}
}
