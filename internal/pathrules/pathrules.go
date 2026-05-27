// Package pathrules holds the tier-1 sensitive-path matcher.
package pathrules

import (
	"strings"

	"github.com/bmatcuk/doublestar/v4"
)

// rule pairs a glob with the logical category name returned on match.
type rule struct {
	glob string
	cat  string
}

// Defaults is the built-in tier-1 ruleset.
var Defaults = []rule{
	{"{HOME}/.aws/credentials", "aws-credentials"},
	{"{HOME}/.aws/config", "aws-credentials"},
	{"{HOME}/.ssh/id_*", "ssh-private-key"},
	{"{HOME}/.config/gcloud/credentials.db", "gcloud-credentials"},
	{"{HOME}/.config/gcloud/access_tokens.db", "gcloud-credentials"},
	{"{HOME}/.config/gcloud/application_default_credentials.json", "gcloud-credentials"},
	{"{HOME}/.config/gh/hosts.yml", "gh-token"},
	{"{HOME}/.npmrc", "npm-token"},
	{"{HOME}/.yarnrc", "npm-token"},
	{"{HOME}/.yarnrc.yml", "npm-token"},
	{"{HOME}/.pypirc", "pypi-token"},
	{"{HOME}/.docker/config.json", "docker-credentials"},
	{"{HOME}/.kube/config", "kube-credentials"},
	{"{HOME}/.netrc", "netrc"},
	{"{HOME}/.git-credentials", "git-credentials"},
	{"{HOME}/.gnupg/private-keys-v1.d/**", "gpg-private-key"},
	{"{HOME}/Library/Application Support/Google/Chrome/*/Login Data", "browser-credentials"},
	{"{HOME}/Library/Application Support/Firefox/Profiles/*/logins.json", "browser-credentials"},
	{"**/.env", "dotenv"},
	{"**/.env.*", "dotenv"},
	{"**/*.pem", "pem-file"},
	{"**/*.p12", "pem-file"},
	{"**/*.pfx", "pem-file"},
	{"**/*.key", "pem-file"},
}

// Skips: paths that look sensitive but aren't. Checked before Defaults.
var Skips = []string{
	"{HOME}/.ssh/*.pub",
	"**/.env.example",
	"**/.env.template",
	"**/.env.sample",
}

// Matcher is a compiled rule set against a fixed list of home directories.
type Matcher struct {
	skips []string
	rules []rule
}

// NewWithDefaults compiles the built-in rules for the supplied home dirs.
func NewWithDefaults(homes []string) *Matcher {
	expand := func(in string) []string {
		if !strings.Contains(in, "{HOME}") {
			return []string{in}
		}
		out := make([]string, 0, len(homes))
		for _, h := range homes {
			out = append(out, strings.ReplaceAll(in, "{HOME}", h))
		}
		return out
	}
	m := &Matcher{}
	for _, s := range Skips {
		m.skips = append(m.skips, expand(s)...)
	}
	for _, r := range Defaults {
		for _, g := range expand(r.glob) {
			m.rules = append(m.rules, rule{glob: g, cat: r.cat})
		}
	}
	return m
}

// Match reports whether the absolute path falls under a tier-1 rule and
// the category of that rule. Returns (false, "") when not protected by path.
func (m *Matcher) Match(absPath string) (bool, string) {
	for _, s := range m.skips {
		if ok, _ := doublestar.PathMatch(s, absPath); ok {
			return false, ""
		}
	}
	for _, r := range m.rules {
		if ok, _ := doublestar.PathMatch(r.glob, absPath); ok {
			return true, r.cat
		}
	}
	return false, ""
}
