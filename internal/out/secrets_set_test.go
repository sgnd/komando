package out

import (
	"sync"
	"testing"
)

// SetSecrets after the printer was used loads the new values on next use
// and forgets the old ones; a value AddValue hid on its own stays. It is
// safe beside AddValue from another goroutine (run with -race).
func TestSetSecretsAfterUse(t *testing.T) {
	p := &Printer{Secrets: func() map[string]string { return map[string]string{"old": "old-value-111"} }}
	if p.Redact("old-value-111") != "[secret:old]" {
		t.Fatal("the first Secrets was not hidden")
	}
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for range 200 {
			p.AddValue("added-value-333")
		}
	}()
	for range 200 {
		p.SetSecrets(func() map[string]string { return map[string]string{"new": "new-value-222"} })
		_ = p.Redact("x")
	}
	wg.Wait()
	if got := p.Redact("new-value-222 old-value-111 added-value-333"); got != "[secret:new] old-value-111 "+Hidden {
		t.Errorf("after SetSecrets: %q", got)
	}
	p.SetSecrets(nil)
	if got := p.Redact("new-value-222"); got != "new-value-222" {
		t.Errorf("SetSecrets(nil) kept the vault's values: %q", got)
	}
}
