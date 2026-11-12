package out

import (
	"encoding/base64"
	"strings"
	"sync"
	"testing"
)

// O10: a value komando read from outside its vault (env:, file:, a cloud
// secret manager) is hidden like a vault value, in every form, and adding
// one while output is masked is safe.
func TestAddValueHidesIt(t *testing.T) {
	p := &Printer{Secrets: func() map[string]string { return map[string]string{"db": "vault-value-1234"} }}
	const v = "outside-value-5678"
	var wg sync.WaitGroup
	for range 4 {
		wg.Add(2)
		go func() { defer wg.Done(); p.AddValue(v) }()
		go func() { defer wg.Done(); _ = p.Redact("x " + v) }()
	}
	wg.Wait()
	got := p.Redact("a=" + v + " b=" + base64.StdEncoding.EncodeToString([]byte(v)) + " c=vault-value-1234")
	if strings.Contains(got, "outside-value") || got != "a="+Hidden+" b="+Hidden+" c=[secret:db]" {
		t.Fatalf("Redact: %q", got)
	}
	if j := string(p.redactJSON([]byte(`{"v":"` + v + `"}`))); strings.Contains(j, v) {
		t.Fatalf("JSON: %s", j)
	}
	// a vault value keeps its name; a short value is not hidden
	p.AddValue("vault-value-1234")
	p.AddValue("abc")
	if got := p.Redact("vault-value-1234 abc"); got != "[secret:db] abc" {
		t.Fatalf("known or short value: %q", got)
	}
	s := p.NewValueScanner()
	_, _ = s.Write([]byte("zz " + v))
	if !s.Found() {
		t.Fatal("the scanner does not see an added value")
	}
}
