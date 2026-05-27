package classify

import (
	"net/url"
	"regexp"
	"strconv"
	"strings"
)

var placeholderRe = regexp.MustCompile(`(?i)^(changeme|xxx+|your[\-_]?(token|secret|key|password)[\-_]?here?|todo|fixme|placeholder|example)$`)
var anglePlaceholderRe = regexp.MustCompile(`^<[^>]+>$`)
var dollarPlaceholderRe = regexp.MustCompile(`^\$\{[A-Za-z_][A-Za-z0-9_]*\}$`)

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
