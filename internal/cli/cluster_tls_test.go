package cli

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Importing a context that skips the server's certificate check says so:
// its login token goes to whoever answers at that address.
func TestImportKubeconfigNotesInsecureTLS(t *testing.T) {
	invHome(t)
	kc := "apiVersion: v1\nkind: Config\ncurrent-context: lab\nclusters:\n- name: lab\n  cluster:\n    server: https://10.255.255.1:6443\n    insecure-skip-tls-verify: true\n" +
		"users:\n- name: lab\n  user:\n    token: test-token-abcdef\ncontexts:\n- name: lab\n  context:\n    cluster: lab\n    user: lab\n"
	p := filepath.Join(t.TempDir(), "kubeconfig")
	if err := os.WriteFile(p, []byte(kc), 0o600); err != nil {
		t.Fatal(err)
	}
	d, e := cliRun(t, "import", "kubeconfig", p)
	if e != nil {
		t.Fatalf("%s %s", e.Code, e.Message)
	}
	if b, _ := json.Marshal(d); !strings.Contains(string(b), "insecure-skip-tls-verify") {
		t.Errorf("no note about the skipped certificate check: %s", b)
	}
}
