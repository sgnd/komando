package cli

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh/agent"

	"github.com/sgnd/komando/internal/store"
)

// On a sealed home, OpenSSH needs files komando keeps sealed: an agent is
// refused, a person gets a private known_hosts copy, and a sealed key
// stops it with a hint to use komando shell.
func TestSSHCommandSealedHome(t *testing.T) {
	setHome(t, t.TempDir())
	for _, a := range agentVars {
		t.Setenv(a.env, "")
		resetApproval()
		os.Unsetenv(a.env)
		resetApproval()
	}
	mustRun(t, "host", "add", "web1", "deploy@10.0.0.1")
	d := mustRun(t, "host", "ssh-command", "web1")
	cmd, _ := d["command"].(string)
	i := strings.Index(cmd, "UserKnownHostsFile=")
	if i < 0 || strings.Contains(cmd, store.Path("known_hosts")) {
		t.Fatalf("command %q", cmd)
	}
	kh := strings.TrimRight(strings.Fields(cmd[i+len("UserKnownHostsFile="):])[0], "'") // a Windows path is quoted
	if fi, err := os.Stat(kh); err != nil || runtime.GOOS != "windows" && fi.Mode().Perm() != 0o600 {
		t.Fatalf("known_hosts copy %s: %v", kh, err)
	}

	mustRun(t, "key", "gen", "k1")
	mustRun(t, "host", "edit", "web1", "--key", "k1")
	t.Setenv("SSH_AUTH_SOCK", "")
	if _, e := invRun(t, "host", "ssh-command", "web1"); e == nil || e.Code != "SSH_AGENT_NEEDED" || !strings.Contains(e.Hint, "komando shell") {
		t.Fatalf("sealed key, no ssh-agent: %+v", e)
	}

	t.Setenv("KOMANDO_AGENT", "1")
	resetApproval()
	t.Cleanup(resetApproval)
	if _, e := invRun(t, "host", "ssh-command", "web1"); e == nil || e.Code != "NEEDS_PERSON" {
		t.Fatalf("agent: %+v", e)
	}
}

// config show and doctor name the sealed store on a sealed home.
func TestSealedConfigAndDoctor(t *testing.T) {
	invHome(t)
	mustRun(t, "host", "add", "web1", "deploy@10.0.0.1")
	c := mustRun(t, "config", "show")
	files := c["files"].(map[string]any)
	for _, k := range []string{"state", "vault", "known_hosts", "audit"} {
		if files[k] != store.Path(store.StoreFile) {
			t.Errorf("files.%s = %v", k, files[k])
		}
	}
	d, _ := invRun(t, "doctor")
	found := false
	sec, _ := d["security"].([]any)
	for _, ch := range sec {
		m := ch.(map[string]any)
		if m["name"] == "security:vault" && strings.Contains(m["detail"].(string), store.StoreFile) {
			found = true
		}
	}
	if !found {
		t.Errorf("doctor does not name the store: %v", sec)
	}
}

// Accepting an old copy is for a person at a terminal.
func TestAcceptOldCopyNeedsAPerson(t *testing.T) {
	invHome(t)
	t.Setenv("KOMANDO_AGENT", "1")
	resetApproval()
	t.Cleanup(resetApproval)
	if _, e := invRun(t, "doctor", "--accept-old-copy"); e == nil || e.Code != "NEEDS_PERSON" {
		t.Fatalf("agent: %+v", e)
	}
}

// recordingAgent is an in-process ssh-agent that keeps what it was given.
type recordingAgent struct {
	agent.ExtendedAgent
	added []agent.AddedKey
}

func (r *recordingAgent) Add(k agent.AddedKey) error {
	r.added = append(r.added, k)
	return r.ExtendedAgent.Add(k)
}

// A key komando made goes to the running ssh-agent for an hour, and the
// ssh line picks it by its public key: no file ever holds the private key.
func TestSSHCommandSealedKeyGoesToAgent(t *testing.T) {
	invHome(t)
	ring := &recordingAgent{ExtendedAgent: agent.NewKeyring().(agent.ExtendedAgent)}
	saved := openAgent
	openAgent = func(*call) (agent.ExtendedAgent, string, func(), error) {
		return ring, "/tmp/agent.sock", func() {}, nil
	}
	t.Cleanup(func() { openAgent = saved })

	mustRun(t, "key", "gen", "k1")
	mustRun(t, "host", "add", "bastion", "ops@10.0.0.9", "--key", "k1")
	mustRun(t, "host", "add", "web1", "deploy@10.0.0.1", "--key", "k1", "--via", "bastion")
	d := mustRun(t, "host", "ssh-command", "web1")
	cmd, _ := d["command"].(string)
	if !strings.Contains(cmd, "IdentityAgent=/tmp/agent.sock") || !strings.Contains(cmd, "IdentitiesOnly=yes") {
		t.Fatalf("command %q", cmd)
	}
	if len(ring.added) != 1 { // one key, though two hops use it
		t.Fatalf("agent got %d keys", len(ring.added))
	}
	if k := ring.added[0]; k.LifetimeSecs != agentLifetime || k.Comment != "komando:k1" {
		t.Fatalf("added %+v", k)
	}
	ids, _ := ring.List()
	if len(ids) != 1 {
		t.Fatalf("agent holds %d keys", len(ids))
	}
	argv, _ := d["argv"].([]any)
	var pub string
	for i, a := range argv {
		if a == "-i" {
			pub = argv[i+1].(string)
		}
	}
	b, err := os.ReadFile(pub)
	if err != nil || !strings.HasPrefix(string(b), ids[0].Type()+" ") {
		t.Fatalf("public key file %s: %q %v", pub, b, err)
	}
	ents, _ := os.ReadDir(filepath.Dir(pub))
	for _, e := range ents {
		c, _ := os.ReadFile(filepath.Join(filepath.Dir(pub), e.Name()))
		if strings.Contains(string(c), "PRIVATE KEY") {
			t.Fatalf("%s holds a private key", e.Name())
		}
	}
	if !strings.Contains(auditText(t), "agent_keys") {
		t.Error("handing a key to the ssh-agent was not audited")
	}
}
