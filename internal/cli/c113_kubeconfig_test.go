package cli

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/sgnd/komando/internal/testhome"
)

// C113 (d): a kubeconfig an AI agent imports may not name a file from a
// credential store other than ~/.kube (an SSH key, ~/.aws, ...): import
// would copy it into the vault. A client key in ~/.kube still imports.
func TestKubeconfigNamedFilesForAgent(t *testing.T) {
	invHome(t)
	home, _ := os.UserHomeDir()
	mk := func(rel, body string) string {
		p := testhome.Path(t, filepath.Join(home, rel))
		os.MkdirAll(filepath.Dir(p), 0o700)
		os.WriteFile(p, []byte(body), 0o600)
		return p
	}
	sshKey := mk(".ssh/id_ed25519", "not a real key\n")
	awsFile := mk(".aws/credentials", "[default]\n")
	kubeKey := mk(".kube/certs/client.key", "not a real key either\n")
	kubeCrt := mk(".kube/certs/client.crt", "not a real cert\n")
	kc := func(key, crt string) string {
		p := testhome.Path(t, filepath.Join(t.TempDir(), "kubeconfig"))
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

// Second review: a link or hard link in ~/.kube to an SSH key, and
// ~/.kube itself a link, are decided by the file they reach.
func TestKubeconfigLinksIntoSSH(t *testing.T) {
	invHome(t)
	home, _ := os.UserHomeDir()
	ssh, kube := testhome.Path(t, filepath.Join(home, ".ssh")), testhome.Path(t, filepath.Join(home, ".kube"))
	os.MkdirAll(ssh, 0o700)
	key := filepath.Join(ssh, "id_ed25519")
	os.WriteFile(key, []byte("not a real key\n"), 0o600)
	os.MkdirAll(kube, 0o700)
	sym := filepath.Join(kube, "key")
	os.Symlink(key, sym)
	hard := filepath.Join(kube, "hard")
	os.Link(key, hard)
	crt := filepath.Join(kube, "client.crt")
	os.WriteFile(crt, []byte("not a real cert\n"), 0o600)
	asAgent(t, false, false)
	for name, p := range map[string]string{"symlink": sym, "hard link": hard} {
		if _, err := readKubeRefFile(tcl, p); err == nil {
			t.Errorf("%s in ~/.kube to an SSH key was read", name)
		}
	}
	if _, err := readKubeRefFile(tcl, crt); err != nil {
		t.Errorf("a plain file in ~/.kube: %v", err)
	}
}

// C136: on a file system that ignores case, ~/.KUBE is ~/.kube, so a key
// there still imports; ~/.SSH stays refused.
func TestKubeconfigKubeDirCase(t *testing.T) {
	invHome(t)
	home, _ := os.UserHomeDir()
	saved := caseFoldFS
	caseFoldFS = true
	t.Cleanup(func() { caseFoldFS = saved })
	asAgent(t, false, false)
	if why := kubeRefSecret(tcl, filepath.Join(home, ".KUBE", "certs", "client.key")); why != "" {
		t.Errorf("~/.KUBE/certs/client.key refused: %s", why)
	}
	if why := kubeRefSecret(tcl, filepath.Join(home, ".SSH", "id_ed25519")); why == "" {
		t.Error("~/.SSH/id_ed25519 was let through")
	}
}
