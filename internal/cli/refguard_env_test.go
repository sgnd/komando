package cli

import (
	"testing"

	"github.com/sgnd/komando/internal/engine"
	"github.com/sgnd/komando/internal/vault"
)

// O3: an AI agent's env: reference to the password of a secret store is
// refused for every variable komando takes out of its environment
// (vault.UnlockVars, BAO_TOKEN included) and KOMANDO_VAULT_PASS; other
// variables, and a person, stay allowed.
func TestRefGuardEnvUnlockVars(t *testing.T) {
	t.Cleanup(resetApproval)
	c := newCall()
	c.caller = engine.Caller{Kind: engine.Agent, Agent: "Claude Code"}
	active.Store(c)
	for _, n := range append([]string{"KOMANDO_VAULT_PASS"}, vault.UnlockVars...) {
		if e := toErr(refGuard("env", n)); e == nil || e.Code != "SENSITIVE_FILE" {
			t.Errorf("agent env:%s: %v", n, e)
		}
	}
	if err := refGuard("env", "DB_PASSWORD"); err != nil {
		t.Errorf("agent env:DB_PASSWORD: %v", err)
	}
	c = newCall()
	active.Store(c)
	if err := refGuard("env", "BAO_TOKEN"); err != nil {
		t.Errorf("person env:BAO_TOKEN: %v", err)
	}
}
