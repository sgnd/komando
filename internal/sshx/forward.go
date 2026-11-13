package sshx

import (
	"os"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

// Session opens a session on c. For a server with forward_agent (host
// edit --forward-agent) it lends the session this computer's ssh-agent
// (SSH_AUTH_SOCK), as ssh -A does: the server's side of it lasts only as
// long as the connection. Without forward_agent, or without an agent
// here, it is a plain session.
func (c *Client) Session() (*ssh.Session, error) {
	sess, err := c.NewSession()
	if err != nil || c.Host == nil || !c.Host.ForwardAgent {
		return sess, err
	}
	sock := os.Getenv("SSH_AUTH_SOCK")
	if sock == "" {
		return sess, nil
	}
	c.fwdOnce.Do(func() { c.fwdErr = agent.ForwardToRemote(c.Client, sock) })
	if c.fwdErr == nil {
		_ = agent.RequestAgentForwarding(sess) // a server that refuses it still runs the command
	}
	return sess, nil
}
