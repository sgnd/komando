package cli

import (
	"strings"
	"testing"

	"github.com/sgnd/komando/internal/vault"
)

// O10: a password komando reads from env:, file:, op://, bw://, kdbx:,
// vault: or a cloud secret manager is hidden in its output from then on,
// like a value from its own vault.
func TestResolvedValueHiddenInOutput(t *testing.T) {
	noAgent(t)
	t.Cleanup(tcl.out.Reset) // the next test's command starts without it
	const v = "pw-from-the-environment-4821"
	t.Setenv("O10_DB_PASSWORD", v)
	got, err := vault.Resolve("env:O10_DB_PASSWORD")
	if err != nil || got != v {
		t.Fatalf("Resolve: %q %v", got, err)
	}
	if s := tcl.out.Redact("server said: auth failed for " + v); strings.Contains(s, v) {
		t.Fatalf("output shows the value: %q", s)
	}
}
