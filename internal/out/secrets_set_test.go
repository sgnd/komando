package out

import (
	"encoding/base64"
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

// A value AddValue hid first that the vault then holds is a vault value:
// it shows under the vault's name, and HoldsVaultValue sees it.
func TestAddValueThenVault(t *testing.T) {
	const v = "shared-value-4321"
	p := &Printer{}
	p.AddValue(v)
	if p.HoldsVaultValue("x " + v) {
		t.Fatal("a value only AddValue hid counts as the vault's")
	}
	p.SetSecrets(func() map[string]string { return map[string]string{"db": v} })
	if !p.HoldsVaultValue("x " + v) {
		t.Error("HoldsVaultValue misses a vault value AddValue hid first")
	}
	if got := p.Redact("a=" + v + " b=" + base64.StdEncoding.EncodeToString([]byte(v))); got != "a=[secret:db] b=[secret:db]" {
		t.Errorf("Redact: %q", got)
	}
	p.forgetAdded()
	if got := p.Redact(v); got != "[secret:db]" {
		t.Errorf("the next command forgot a vault value: %q", got)
	}
}
