package cli

import (
	"os"
	"path/filepath"
	"testing"
)

// C113 (d): a kubeconfig an AI agent imports may not name a file from a
// credential store other than ~/.kube (an SSH key, ~/.aws, ...): import
// would copy it into the vault. A client key in ~/.kube still imports.
func TestKubeconfigNamedFilesForAgent(t *testing.T) {
	invHome(t)
	home, _ := os.UserHomeDir()
	mk := func(rel, body string) string {
		p := filepath.Join(home, rel)
		os.MkdirAll(filepath.Dir(p), 0o700)
		os.WriteFile(p, []byte(body), 0o600)
		return p
	}
	sshKey := mk(".ssh/id_ed25519", "not a real key\n")
	awsFile := mk(".aws/credentials", "[default]\n")
	kubeKey := mk(".kube/certs/client.key", "not a real key either\n")
	kubeCrt := mk(".kube/certs/client.crt", "not a real cert\n")
	kc := func(key, crt string) string {
		p := filepath.Join(t.TempDir(), "kubeconfig")
		os.WriteFile(p, []byte("apiVersion: v1\nkind: Config\ncurrent-context: prod\nclusters:\n- name: prod\n  cluster:\n    server: https://k.example.com\n"+
			"users:\n- name: prod\n  user:\n    client-key: "+key+"\n    client-certificate: "+crt+"\ncontexts:\n- name: prod\n  context: {cluster: prod, user: prod}\n"), 0o600)
		return p
	}
	asAgent(t, false, false)
	for name, key := range map[string]string{"ssh key": sshKey, "aws file": awsFile} {
		if _, e := cliRun(t, "import", "kubeconfig", kc(key, kubeCrt)); e == nil || e.Code != "SENSITIVE_FILE" {
			t.Errorf("%s: want SENSITIVE_FILE, got %+v", name, e)
		}
	}
	if _, e := cliRun(t, "import", "kubeconfig", kc(kubeKey, kubeCrt)); e != nil && e.Code == "SENSITIVE_FILE" {
		t.Errorf("a client key in ~/.kube: %+v", e)
	}
}
