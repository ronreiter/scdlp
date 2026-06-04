package classify

import "regexp"

// minSecretLen and minSecretEntropy gate the generic key/value detector. A
// flagged value must be at least this long and this random (Shannon entropy,
// bits/byte). Tuned against testdata/corpus.
const (
	minSecretLen     = 12
	minSecretEntropy = 3.0
)

// kvPair is a candidate key/value extracted from the buffer.
type kvPair struct {
	key   string
	value string
}

// pairRe captures key/value pairs in the two dominant shapes:
//
//	KEY=VALUE             (env, ini, npmrc, aws credentials)
//	"key": "value"        (json) and  key: value  (yaml)
//
// It is a lexical scan, not a parser — it must tolerate truncated documents.
// The value must begin on the same line as the key ([ \t]* after the separator,
// not \s*) so that YAML mapping-parent keys (e.g. "user:" with no inline value)
// are skipped and their nested children are extracted correctly instead.
var pairRe = regexp.MustCompile(
	`(?m)["']?([A-Za-z0-9_.\-]+)["']?\s*[:=][ \t]*(?:"([^"]*)"|'([^']*)'|([^\s,}]+))`)

// extractPairs pulls candidate (key, value) pairs from buf, capped for the hot path.
func extractPairs(buf []byte) []kvPair {
	const maxPairs = 256
	ms := pairRe.FindAllSubmatch(buf, maxPairs)
	out := make([]kvPair, 0, len(ms))
	for _, m := range ms {
		val := string(m[2])
		if val == "" {
			val = string(m[3])
		}
		if val == "" {
			val = string(m[4])
		}
		out = append(out, kvPair{key: string(m[1]), value: val})
	}
	return out
}

// classifyGeneric flags a secret when a secret-ish key carries a high-entropy,
// non-placeholder value. The key-name gate keeps false positives off hashes/UUIDs.
func classifyGeneric(buf []byte) Verdict {
	for _, p := range extractPairs(buf) {
		if !SecretishKeyName(p.key) {
			continue
		}
		if p.value == "" || len(p.value) < minSecretLen {
			continue
		}
		if IsPlaceholder(p.value) || IsBooleanOrNumeric(p.value) || IsURLWithoutEmbeddedCreds(p.value) {
			continue
		}
		if ShannonEntropy(p.value) < minSecretEntropy {
			continue
		}
		return Verdict{
			Key:        p.key,
			Value:      p.value,
			Match:      "generic-credential",
			Confidence: 0.8,
			Reason:     "secret-ish key + high-entropy value: " + p.key,
		}
	}
	return Verdict{Reason: "no generic credential"}
}
