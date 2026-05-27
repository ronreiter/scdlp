package classify

import "testing"

func TestClassifyBuf_AWSKey(t *testing.T) {
	buf := []byte("aws_access_key_id = AKIAIOSFODNN7EXAMPLE\n")
	v := New().ClassifyBuf(buf)
	if !v.IsSecret() {
		t.Fatalf("expected AWS key to be a secret, got %+v", v)
	}
	if v.Match != "aws-access-key" {
		t.Fatalf("expected match=aws-access-key, got %q", v.Match)
	}
}

func TestClassifyBuf_GitHubPAT(t *testing.T) {
	buf := []byte("# .npmrc\n//npm.pkg.github.com/:_authToken=ghp_abcdefghijklmnopqrstuvwxyz0123456789\n")
	v := New().ClassifyBuf(buf)
	if v.Match != "github-pat" {
		t.Fatalf("expected match=github-pat, got %q (verdict=%+v)", v.Match, v)
	}
}

func TestClassifyBuf_PEMPrivateKey(t *testing.T) {
	buf := []byte("-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA…\n")
	v := New().ClassifyBuf(buf)
	if !v.IsSecret() {
		t.Fatalf("expected PEM private key to be a secret, got %+v", v)
	}
	if v.Match != "pem-private-key" {
		t.Fatalf("expected match=pem-private-key, got %q", v.Match)
	}
}

func TestClassifyBuf_Empty(t *testing.T) {
	v := New().ClassifyBuf(nil)
	if v.IsSecret() {
		t.Fatalf("empty buffer should not be a secret, got %+v", v)
	}
}

func TestClassifyBuf_PlainText(t *testing.T) {
	buf := []byte("# config file\nhost = example.com\nport = 5432\n")
	v := New().ClassifyBuf(buf)
	if v.IsSecret() {
		t.Fatalf("plain config should not be a secret, got %+v", v)
	}
}

func TestClassifyBuf_PlaceholderIgnored(t *testing.T) {
	buf := []byte("aws_access_key_id = AKIAYOURKEYHEREXXXX\n")
	v := New().ClassifyBuf(buf)
	if v.Match == "aws-access-key" && v.Confidence >= 0.6 {
		t.Fatalf("placeholder AKIA should not regex-validate as high confidence, got %+v", v)
	}
}

func TestClassifyBuf_SentryToken(t *testing.T) {
	cases := map[string]string{
		"sntrys_": "SENTRY_AUTH_TOKEN=sntrys_abcdefghijklmnopqrstuvwxyz0123456789\n",
		"sntryu_": "SENTRY_USER_AUTH_TOKEN=sntryu_abcdefghijklmnopqrstuvwxyz0123456789\n",
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			v := New().ClassifyBuf([]byte(body))
			if v.Match != "sentry" {
				t.Fatalf("want match=sentry, got %+v", v)
			}
			if !v.IsSecret() {
				t.Fatalf("want IsSecret true, got %+v", v)
			}
		})
	}
}

func TestClassifyBuf_TruncatedAt4K(t *testing.T) {
	junk := make([]byte, 8192)
	for i := range junk {
		junk[i] = 'x'
	}
	tail := []byte("AKIAIOSFODNN7EXAMPLE")
	buf := append(junk, tail...)
	v := New().ClassifyBuf(buf)
	if v.IsSecret() {
		t.Fatalf("key beyond 4 KiB window should not be detected, got %+v", v)
	}
}
