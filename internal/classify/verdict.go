// Package classify decides whether values in a .env document look like
// real credentials.
package classify

// Verdict is the classifier's per-value result. Confidence is in [0, 1].
// Match is empty when the value did not match anything; otherwise it is
// a short token identifying what matched (e.g. "aws-access-key",
// "github-pat", "high-entropy").
type Verdict struct {
	Key        string
	Value      string
	Match      string
	Confidence float32
	Reason     string
}

// IsSecret reports whether the verdict crosses the default threshold.
func (v Verdict) IsSecret() bool {
	return v.Confidence >= 0.6
}
