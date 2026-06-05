package classify

import (
	"os"
	"path/filepath"
	"testing"
)

// readHead returns up to MaxScanBytes bytes of the file, mirroring what the
// agent's default reader feeds ClassifyBuf.
func readHead(t *testing.T, path string) []byte {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("open %s: %v", path, err)
	}
	defer f.Close()
	buf := make([]byte, MaxScanBytes)
	n, _ := f.Read(buf)
	return buf[:n]
}

// corpusFiles lists the regular files under testdata/corpus/<bucket>.
func corpusFiles(t *testing.T, bucket string) []string {
	t.Helper()
	root := filepath.Join("testdata", "corpus", bucket)
	var out []string
	err := filepath.Walk(root, func(p string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() {
			out = append(out, p)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk %s: %v", root, err)
	}
	return out
}

func TestCorpus_PositivesAndNegatives(t *testing.T) {
	c := New()

	var posTotal, posHit, negTotal, falsePos int
	var missed, flagged []string

	for _, p := range corpusFiles(t, "positive") {
		posTotal++
		v := c.ClassifyBuf(readHead(t, p))
		if v.IsSecret() {
			posHit++
		} else {
			missed = append(missed, p)
		}
	}
	for _, p := range corpusFiles(t, "negative") {
		negTotal++
		v := c.ClassifyBuf(readHead(t, p))
		if v.IsSecret() {
			falsePos++
			flagged = append(flagged, p+"  =>  "+v.Match+" ("+v.Reason+")")
		}
	}

	recall := 1.0
	if posTotal > 0 {
		recall = float64(posHit) / float64(posTotal)
	}
	tp := posHit
	precision := 1.0
	if tp+falsePos > 0 {
		precision = float64(tp) / float64(tp+falsePos)
	}
	t.Logf("corpus: positives=%d hit=%d (recall=%.3f)  negatives=%d falsePos=%d (precision=%.3f)",
		posTotal, posHit, recall, negTotal, falsePos, precision)

	for _, m := range missed {
		t.Errorf("MISS (positive not detected): %s", m)
	}
	for _, f := range flagged {
		t.Errorf("FALSE POSITIVE (negative flagged): %s", f)
	}
}

func TestCorpus_DetectorLabels(t *testing.T) {
	c := New()
	cases := map[string]string{ // file under testdata/corpus/positive → expected Match
		"aws-access-key.env":     "aws-access-key",
		"generic-api-token.json": "generic-credential",
		"id_rsa.pem":             "pem-private-key",
	}
	for file, want := range cases {
		p := "testdata/corpus/positive/" + file
		v := c.ClassifyBuf(readHead(t, p))
		if v.Match != want {
			t.Errorf("%s: want Match %q, got %q (reason=%q)", file, want, v.Match, v.Reason)
		}
	}
}
