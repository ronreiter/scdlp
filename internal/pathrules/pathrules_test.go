package pathrules

import "testing"

func TestMatcher_AWSCredentials(t *testing.T) {
	m := NewWithDefaults([]string{"/Users/alice"})
	matched, cat := m.Match("/Users/alice/.aws/credentials")
	if !matched || cat != "aws-credentials" {
		t.Fatalf("want (true, aws-credentials), got (%v, %q)", matched, cat)
	}
}

func TestMatcher_SSHPrivateKey(t *testing.T) {
	m := NewWithDefaults([]string{"/Users/alice"})
	matched, cat := m.Match("/Users/alice/.ssh/id_ed25519")
	if !matched || cat != "ssh-private-key" {
		t.Fatalf("want (true, ssh-private-key), got (%v, %q)", matched, cat)
	}
}

func TestMatcher_SSHPublicKeySkipped(t *testing.T) {
	m := NewWithDefaults([]string{"/Users/alice"})
	matched, _ := m.Match("/Users/alice/.ssh/id_ed25519.pub")
	if matched {
		t.Fatal("public keys must not match")
	}
}

func TestMatcher_DotEnv(t *testing.T) {
	m := NewWithDefaults([]string{"/Users/alice"})
	matched, cat := m.Match("/Users/alice/code/myapp/.env")
	if !matched || cat != "dotenv" {
		t.Fatalf("want (true, dotenv), got (%v, %q)", matched, cat)
	}
}

func TestMatcher_DotEnvExampleSkipped(t *testing.T) {
	m := NewWithDefaults([]string{"/Users/alice"})
	for _, p := range []string{
		"/Users/alice/code/myapp/.env.example",
		"/Users/alice/code/myapp/.env.template",
		"/Users/alice/code/myapp/.env.sample",
	} {
		if matched, _ := m.Match(p); matched {
			t.Fatalf("%s must not match", p)
		}
	}
}

func TestMatcher_MultipleHomes(t *testing.T) {
	m := NewWithDefaults([]string{"/Users/alice", "/Users/bob"})
	for _, p := range []string{
		"/Users/alice/.npmrc",
		"/Users/bob/.npmrc",
	} {
		matched, cat := m.Match(p)
		if !matched || cat != "npm-token" {
			t.Fatalf("%s want (true, npm-token), got (%v, %q)", p, matched, cat)
		}
	}
}

func TestMatcher_UnrelatedPath(t *testing.T) {
	m := NewWithDefaults([]string{"/Users/alice"})
	matched, _ := m.Match("/etc/hosts")
	if matched {
		t.Fatal("unrelated path must not match")
	}
}

func TestMatcher_PEMAnywhere(t *testing.T) {
	m := NewWithDefaults([]string{"/Users/alice"})
	matched, cat := m.Match("/Users/alice/work/secrets/server.pem")
	if !matched || cat != "pem-file" {
		t.Fatalf("want (true, pem-file), got (%v, %q)", matched, cat)
	}
}
