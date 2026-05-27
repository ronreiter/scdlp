package classify

import "regexp"

// ProviderPatterns maps provider name to a compiled validation regex used in
// stage-2 to confirm that a stage-1 prefix hit looks like a full credential.
var ProviderPatterns = map[string]*regexp.Regexp{
	"aws-access-key": regexp.MustCompile(`^(AKIA|ASIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASCA)[A-Z0-9]{16}$`),
	"github-pat":     regexp.MustCompile(`^(ghp_|gho_|ghu_|ghs_|ghr_|github_pat_)[A-Za-z0-9_]{36,251}$`),
	"gitlab-token":   regexp.MustCompile(`^(glpat-|glptt-|gloas-)[A-Za-z0-9_\-]{20,}$`),
	"slack-bot":      regexp.MustCompile(`^xox[abprs]-[A-Za-z0-9-]{10,}$|^xapp-[A-Za-z0-9-]{10,}$|^xoxe\.xoxb-[A-Za-z0-9-]{10,}$`),
	"openai":         regexp.MustCompile(`^(sk-proj-|sk-ant-|sk-)[A-Za-z0-9_\-]{20,}$`),
	"stripe-live":    regexp.MustCompile(`^(sk_live_|pk_live_|rk_live_|whsec_)[A-Za-z0-9]{16,}$`),
	"stripe-test":    regexp.MustCompile(`^(sk_test_|pk_test_)[A-Za-z0-9]{16,}$`),
	"google-api":     regexp.MustCompile(`^(AIza[0-9A-Za-z_\-]{35}|ya29\.[0-9A-Za-z_\-]{20,})$`),
	"npm-token":      regexp.MustCompile(`^npm_[A-Za-z0-9]{30,}$`),
	"huggingface":    regexp.MustCompile(`^hf_[A-Za-z0-9]{30,}$`),
	"sentry":         regexp.MustCompile(`^sntr[ysu]_[A-Za-z0-9]{30,}$`),
	"sendgrid":       regexp.MustCompile(`^SG\.[A-Za-z0-9_\-]{20,}\.[A-Za-z0-9_\-]{20,}$`),
	"jwt":            regexp.MustCompile(`^eyJ[A-Za-z0-9_\-]+\.eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+$`),
}
