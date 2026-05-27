package classify

// ProviderPrefixes maps a logical provider name to the set of literal byte
// prefixes that identify a credential of that kind.
var ProviderPrefixes = map[string][]string{
	"aws-access-key": {"AKIA", "ASIA", "AGPA", "AIDA", "AROA", "AIPA", "ANPA", "ANVA", "ASCA"},
	"github-pat":     {"ghp_", "gho_", "ghu_", "ghs_", "ghr_", "github_pat_"},
	"gitlab-token":   {"glpat-", "glptt-", "gloas-"},
	"slack-bot":      {"xoxb-", "xoxa-", "xoxp-", "xoxr-", "xoxs-", "xoxe.xoxb-", "xapp-"},
	"openai":         {"sk-proj-", "sk-ant-", "sk-"},
	"stripe-live":    {"sk_live_", "pk_live_", "rk_live_", "whsec_"},
	"stripe-test":    {"sk_test_", "pk_test_"},
	"google-api":     {"AIza", "ya29."},
	"npm-token":      {"npm_"},
	"huggingface":    {"hf_"},
	"sentry":         {"sntrys_", "sntryu_"},
	"sendgrid":       {"SG."},
	"jwt":            {"eyJ"},
}

// AllPrefixes returns every literal prefix in a single flat slice.
func AllPrefixes() []string {
	var out []string
	for _, pp := range ProviderPrefixes {
		out = append(out, pp...)
	}
	return out
}

// ProviderForPrefix returns the logical provider name for a given literal
// prefix. Returns "" if not found.
func ProviderForPrefix(p string) string {
	for name, pp := range ProviderPrefixes {
		for _, x := range pp {
			if x == p {
				return name
			}
		}
	}
	return ""
}
