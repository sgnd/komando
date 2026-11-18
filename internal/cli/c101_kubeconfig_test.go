package cli

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sgnd/komando/internal/store"
)

// The files a kubeconfig names are read under the same rule as the
// kubeconfig: an AI agent's import never copies komando's own folder
// into the vault.
func TestKubeconfigFilesAreGuarded(t *testing.T) {
	invHome(t)
	mustRun(t, "host", "add", "web1", "u@10.0.0.1") // the store exists
	own := filepath.Join(store.Home(), "store.db")
	if _, err := os.Stat(own); err != nil {
		t.Fatalf("no store file to point at: %v", err)
	}
	for _, field := range []string{"certificate-authority", "client-certificate", "client-key"} {
		cluster, user := "    server: https://k.example.com", "    token: test-token-abcdef"
		if field == "certificate-authority" {
			cluster += "\n    certificate-authority: " + own
		} else {
			user += "\n    " + field + ": " + own
		}
		kc := "apiVersion: v1\nkind: Config\ncurrent-context: prod\nclusters:\n- name: prod\n  cluster:\n" + cluster +
			"\nusers:\n- name: prod\n  user:\n" + user + "\ncontexts:\n- name: prod\n  context: {cluster: prod, user: prod}\n"
		p := filepath.Join(t.TempDir(), "kubeconfig")
		os.WriteFile(p, []byte(kc), 0o600)
		asAgent(t, false, false)
		_, e := cliRun(t, "import", "kubeconfig", p)
		if e == nil || e.Code != "SENSITIVE_FILE" {
			t.Errorf("%s: want SENSITIVE_FILE, got %+v", field, e)
		}
		if d, _ := cliRun(t, "conn", "list"); d != nil && strings.Contains(strings.ToLower(toJSON(d)), "prod") {
			t.Errorf("%s: a conn was made: %v", field, d)
		}
	}
}

func toJSON(v any) string { b, _ := json.Marshal(v); return string(b) }
