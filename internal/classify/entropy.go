package classify

import (
	"math"
	"regexp"
)

// ShannonEntropy returns the Shannon entropy of s measured in bits per byte.
// Empty string returns 0.
func ShannonEntropy(s string) float64 {
	if len(s) == 0 {
		return 0
	}
	var counts [256]int
	for i := 0; i < len(s); i++ {
		counts[s[i]]++
	}
	n := float64(len(s))
	var h float64
	for _, c := range counts {
		if c == 0 {
			continue
		}
		p := float64(c) / n
		h -= p * math.Log2(p)
	}
	return h
}

// secretishKeyNameRe matches env var keys whose name suggests a secret.
var secretishKeyNameRe = regexp.MustCompile(`(?i)(token|secret|password|passwd|api[_\-]?key|access[_\-]?key|client[_\-]?secret|auth|credential|private[_\-]?key)`)

// SecretishKeyName reports whether the variable's name looks like it should
// hold a credential.
func SecretishKeyName(key string) bool {
	return secretishKeyNameRe.MatchString(key)
}
