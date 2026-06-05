package classify

import (
	"bytes"
	"regexp"

	"github.com/cloudflare/ahocorasick"
)

// indexBytes returns the index of needle in haystack, or -1 if not found.
func indexBytes(haystack, needle []byte) int {
	return bytes.Index(haystack, needle)
}

// MaxScanBytes is the per-file content-scan window. Files longer than this
// are scanned only up to this offset.
const MaxScanBytes = 4096

// tokenRe is the surrounding-token shape we extract around each Aho-Corasick
// hit. Matches the longest run of bytes that could form a credential token.
var tokenRe = regexp.MustCompile(`[A-Za-z0-9_\-./+=]+`)

// Classifier runs the bytes-oriented secret-detection pipeline.
type Classifier struct {
	ac          *ahocorasick.Matcher
	allPrefixes []string
}

// New returns a Classifier ready to use. Safe for concurrent use.
func New() *Classifier {
	all := AllPrefixes()
	return &Classifier{
		ac:          ahocorasick.NewStringMatcher(all),
		allPrefixes: all,
	}
}

// ClassifyBuf returns a Verdict for the supplied buffer. Only the first
// MaxScanBytes are inspected. Returns the highest-confidence finding.
// Falls back to a generic key/value + entropy heuristic for secrets without a known provider prefix.
func (c *Classifier) ClassifyBuf(buf []byte) Verdict {
	if len(buf) == 0 {
		return Verdict{Reason: "empty"}
	}
	if len(buf) > MaxScanBytes {
		buf = buf[:MaxScanBytes]
	}

	// Pass 1: PEM private-key header — single regex, very cheap.
	if PEMPrivateKeyRe.Match(buf) {
		return Verdict{
			Match:      "pem-private-key",
			Confidence: 1.0,
			Reason:     "PEM private key header",
		}
	}

	// Pass 2: Aho-Corasick provider-prefix scan.
	hits := c.ac.Match(buf)
	if len(hits) == 0 {
		if g := classifyGeneric(buf); g.IsSecret() {
			return g
		}
		return Verdict{Reason: "no provider prefix"}
	}

	// For each hit, find the credential token starting at the prefix and run
	// the provider regex against it.
	var best Verdict
	for _, hitIdx := range hits {
		prefix := c.allPrefixes[hitIdx]
		provider := ProviderForPrefix(prefix)
		if provider == "" {
			continue
		}
		pat := ProviderPatterns[provider]
		if pat == nil {
			continue
		}
		// Find all occurrences of the prefix in buf and extract the token
		// starting at each occurrence.
		search := buf
		offset := 0
		for {
			idx := indexBytes(search, []byte(prefix))
			if idx < 0 {
				break
			}
			// Extract the token starting at the prefix position.
			tok := tokenRe.Find(search[idx:])
			if tok != nil {
				if pat.Match(tok) {
					return Verdict{
						Match:      provider,
						Value:      string(tok),
						Confidence: 1.0,
						Reason:     "stage-2 regex match: " + provider,
					}
				}
				if best.Confidence < 0.5 {
					best = Verdict{
						Match:      provider,
						Value:      string(tok),
						Confidence: 0.4,
						Reason:     "stage-1 prefix only: " + prefix,
					}
				}
			}
			search = search[idx+len(prefix):]
			offset += idx + len(prefix)
		}
	}
	// Detector C: generic key/value + entropy. Only needed when the provider
	// stage did not already yield a confident (>= 0.6) finding.
	if !best.IsSecret() {
		if g := classifyGeneric(buf); g.IsSecret() {
			return g
		}
	}
	if best.Match == "" {
		best.Reason = "prefix matched, no token"
	}
	return best
}
