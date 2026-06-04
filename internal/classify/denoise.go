package classify

import (
	"net/url"
	"regexp"
	"strconv"
	"strings"
)

var placeholderRe = regexp.MustCompile(`(?i)^(changeme|xxx+|your[\-_]?(token|secret|key|password)[\-_]?here?|todo|fixme|placeholder|example)$`)

// uuidRe matches a canonical UUID (8-4-4-4-12 hex).
var uuidRe = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)

// hexDigestRe matches a bare hex string of a common digest length (md5/sha1/sha256).
var hexDigestRe = regexp.MustCompile(`^(?:[0-9a-fA-F]{32}|[0-9a-fA-F]{40}|[0-9a-fA-F]{64})$`)

// IsHashOrUUID reports whether v is a structured identifier — a canonical UUID
// or a bare hex digest (32/40/64 hex) — rather than a credential. These are
// commonly stored under secret-ish key names (token hashes, key fingerprints,
// correlation IDs) but are not themselves secrets. Tradeoff: a credential that
// happens to be exactly UUID- or hex-digest-shaped and has no known provider
// prefix will be treated as benign by the generic detector.
func IsHashOrUUID(v string) bool {
	return uuidRe.MatchString(v) || hexDigestRe.MatchString(v)
}

var anglePlaceholderRe = regexp.MustCompile(`^<[^>]+>$`)

// dollarPlaceholderRe matches ${VAR} and also ${VAR (without closing brace),
// because pair-extracting regexes that stop at '}' produce the truncated form.
var dollarPlaceholderRe = regexp.MustCompile(`^\$\{[A-Za-z_][A-Za-z0-9_]*\}?$`)

// IsPlaceholder reports whether the value is one of the common documentation
// placeholders that should never be treated as a real secret.
func IsPlaceholder(v string) bool {
	if placeholderRe.MatchString(v) {
		return true
	}
	if anglePlaceholderRe.MatchString(v) {
		return true
	}
	if dollarPlaceholderRe.MatchString(v) {
		return true
	}
	return false
}

// IsURLWithoutEmbeddedCreds reports whether v parses as a URL whose userinfo
// component does NOT carry credentials.
func IsURLWithoutEmbeddedCreds(v string) bool {
	if !strings.Contains(v, "://") {
		return false
	}
	u, err := url.Parse(v)
	if err != nil {
		return false
	}
	if u.User == nil {
		return true
	}
	if _, hasPass := u.User.Password(); hasPass {
		return false
	}
	return true
}

// IsBooleanOrNumeric reports whether the value is one of the common boolean
// strings or a parseable number — never a credential.
func IsBooleanOrNumeric(v string) bool {
	switch strings.ToLower(v) {
	case "true", "false", "yes", "no", "on", "off":
		return true
	}
	if _, err := strconv.ParseFloat(v, 64); err == nil {
		return true
	}
	return false
}
