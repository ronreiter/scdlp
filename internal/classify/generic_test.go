package classify

import "testing"

func TestExtractPairs_EnvAndJSON(t *testing.T) {
	buf := []byte("API_TOKEN=s3cr3t-LONG-random-VALUE-9f8a7b6c5d\n" +
		"db_password: yamlSecretValue123456\n" +
		`{"client_secret": "abcDEF123456ghiJKL789mno", "port": 8080}`)
	pairs := extractPairs(buf)
	got := map[string]string{}
	for _, p := range pairs {
		got[p.key] = p.value
	}
	if got["API_TOKEN"] != "s3cr3t-LONG-random-VALUE-9f8a7b6c5d" {
		t.Fatalf("env pair not extracted: %q", got["API_TOKEN"])
	}
	if got["client_secret"] != "abcDEF123456ghiJKL789mno" {
		t.Fatalf("json pair not extracted: %q", got["client_secret"])
	}
	if got["db_password"] != "yamlSecretValue123456" {
		t.Fatalf("yaml pair not extracted: %q", got["db_password"])
	}
}

func TestClassifyGeneric_FlagsSecretishHighEntropy(t *testing.T) {
	v := classifyGeneric([]byte("API_TOKEN=s3cr3t-LONG-random-VALUE-9f8a7b6c5d\n"))
	if !v.IsSecret() {
		t.Fatalf("secret-ish key with high-entropy value must be a secret, got %+v", v)
	}
	if v.Match != "generic-credential" {
		t.Fatalf("want match generic-credential, got %q", v.Match)
	}
}

func TestClassifyGeneric_IgnoresBenignKey(t *testing.T) {
	v := classifyGeneric([]byte(`{"sha256": "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"}`))
	if v.IsSecret() {
		t.Fatalf("benign key must not flag, got %+v", v)
	}
}

func TestClassifyGeneric_IgnoresPlaceholderAndBool(t *testing.T) {
	for _, in := range []string{
		"API_KEY=changeme\n",
		"SECRET=${MY_SECRET}\n",
		"PASSWORD=your-password-here\n",
		"AUTH_ENABLED=true\n",
		"TOKEN=<your-token>\n",
	} {
		if v := classifyGeneric([]byte(in)); v.IsSecret() {
			t.Fatalf("placeholder/bool must not flag: %q -> %+v", in, v)
		}
	}
}

func TestClassifyGeneric_IgnoresShortValue(t *testing.T) {
	if v := classifyGeneric([]byte("token=abc\n")); v.IsSecret() {
		t.Fatalf("short value must not flag, got %+v", v)
	}
}

func TestExtractPairs_NestedYAMLSkipsParentKey(t *testing.T) {
	buf := []byte("users:\n- name: admin\n  user:\n    token: kFh9Lm2Qp7Rt4Vx1Zc6Bn3Ws8Yd0Ja5Ke\n")
	got := map[string]string{}
	for _, p := range extractPairs(buf) {
		got[p.key] = p.value
	}
	if got["token"] != "kFh9Lm2Qp7Rt4Vx1Zc6Bn3Ws8Yd0Ja5Ke" {
		t.Fatalf("nested token not extracted: %q (pairs=%v)", got["token"], got)
	}
	// The mapping-parent key `user:` has no inline value, so it must not appear
	// as a pair at all (it must not swallow the child `token:` as its value).
	if v, exists := got["user"]; exists {
		t.Fatalf("parent key user must not appear in pairs, got value %q", v)
	}
}
