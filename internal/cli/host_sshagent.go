package cli

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"runtime"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"

	"github.com/sgnd/komando/internal/out"
	"github.com/sgnd/komando/internal/store"
)

// A key komando made lives sealed in the store and is never written to a
// file. For OpenSSH, `host ssh-command` hands it to the ssh-agent that is
// already running, for agentLifetime only; the printed ssh line picks it
// out by its public key (not a secret) in the private temporary folder
// that holds the pinned host keys.

// agentLifetime is how long the running ssh-agent keeps a key komando gave it.
const agentLifetime = 3600

// openAgent connects to the ssh-agent this shell uses; tests swap it.
var openAgent = func() (agent.ExtendedAgent, string, func(), error) {
	sock := os.Getenv("SSH_AUTH_SOCK")
	if sock == "" || runtime.GOOS == "windows" {
		return nil, "", nil, errNoAgent()
	}
	c, err := net.Dial("unix", sock)
	if err != nil {
		return nil, "", nil, errNoAgent()
	}
	return agent.NewClient(c), sock, func() { c.Close() }, nil
}

func errNoAgent() error {
	return out.Errf(out.ExitUsage, "SSH_AGENT_NEEDED",
		"start one with `eval \"$(ssh-agent)\"` and run this again, or use `komando shell SERVER`, which logs in with the key itself",
		"a key komando made is sealed in its store and never written to a file, so OpenSSH gets it from a running ssh-agent, and none was found (SSH_AUTH_SOCK)")
}

// agentKeys gives the running ssh-agent each sealed key the hops log in
// with, and returns the ssh options for each such key: its public key in
// dir and the agent's socket. Hops with other keys are not in the map.
func agentKeys(st *store.State, hops []*store.Host, dir string) (map[string][]string, error) {
	var keys []*store.Key
	seen := map[string]bool{}
	for _, h := range hops {
		if k, ok := st.Keys[h.Key]; ok && h.Identity == "" && store.SealedKey(k) && !seen[k.Name] {
			seen[k.Name] = true
			keys = append(keys, k)
		}
	}
	if len(keys) == 0 {
		return nil, nil
	}
	ag, sock, done, err := openAgent()
	if err != nil {
		return nil, err
	}
	defer done()
	opts := map[string][]string{}
	var added []string
	for i, k := range keys {
		pem, err := store.ReadPrivateKey(k)
		if err != nil {
			return nil, err
		}
		priv, err := ssh.ParseRawPrivateKey(pem)
		if err != nil {
			return nil, out.Errf(out.ExitUsage, "KEY_INVALID", "make a new one with `komando key gen`", "key %s: %v", k.Name, err)
		}
		signer, err := ssh.NewSignerFromKey(priv)
		if err != nil {
			return nil, err
		}
		if err := ag.Add(agent.AddedKey{PrivateKey: priv, Comment: "komando:" + k.Name, LifetimeSecs: agentLifetime}); err != nil {
			return nil, out.Errf(out.ExitError, "SSH_AGENT_REFUSED", "check the ssh-agent, or use `komando shell SERVER`", "the ssh-agent did not take key %s: %v", k.Name, err)
		}
		added = append(added, k.Name)
		pub := filepath.Join(dir, fmt.Sprintf("key%d.pub", i+1))
		if err := os.WriteFile(pub, ssh.MarshalAuthorizedKey(signer.PublicKey()), 0o600); err != nil {
			return nil, err
		}
		opts[k.Name] = []string{"-o", "IdentitiesOnly=yes", "-o", "IdentityAgent=" + sock, "-i", pub}
	}
	audit(st, "host ssh-command", nil, "", true, map[string]any{"agent_keys": added, "agent_lifetime_secs": agentLifetime})
	return opts, nil
}
