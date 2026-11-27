package cli

import (
	"os"
	"regexp"
	"strings"

	"github.com/spf13/cobra"
	"golang.org/x/crypto/ssh"

	"github.com/sgnd/komando/internal/out"
)

// gateLine is what `ssh-gate line` prints.
type gateLine struct {
	Line        string `json:"line"`
	Name        string `json:"name"`
	ReadOnly    bool   `json:"read_only"`
	Network     bool   `json:"network"`
	ShellAccess bool   `json:"shell_access"`
	Komando     string `json:"komando"`
	AddTo       string `json:"add_to"`
}

func (l gateLine) Text() string { return l.Line + "\n" }

func sshGateLineCmd() *cobra.Command {
	var name string
	var readOnly, network, shellAccess bool
	c := &cobra.Command{
		Use:   "line PUBLIC_KEY --name NAME",
		Short: "Print the authorized_keys line that limits a key to komando",
		Long: `Prints the line to add to ~/.ssh/authorized_keys on this computer, so the
key runs komando through ssh-gate and nothing else. PUBLIC_KEY is the key's
line (ssh-ed25519 AAAA... comment) or a .pub file holding it. The line names
this komando by its full path, as sshd does not search PATH.

A --read-only key runs only commands that read, and only those that stay
on the servers and conns in your list: no net checks, no cert check of
a website, and no exec, job start, docker exec, cluster kubernetes exec or snippet exec,
whose programs can connect anywhere and carry what they read in a URL or a
DNS name. Add --network too for a read key that may do those.

With --shell-access (not with --read-only) the key may also open a login
shell on one server: ssh -t HOST komando shell SERVER, word for word. Its
line has restrict,pty, so sshd gives it a terminal when it asks for one.
The shell is refused on a protected server, a Windows server or this
computer, with any other word or flag, without the terminal, and on every
server while you have deny rules of your own (komando policy list); db
shell and cluster kubernetes shell stay refused. On the servers it opens on, the
shell is full control of the server, as the account komando logs in with:
what is typed is outside komando's per-command rules, masking and audit.
Give such a key only to a device you would give that login to. Each
session's start and end are in komando audit list (key, server, how long, why
it ended), and a session with no input and no output for 30 minutes ends.`,
		Example: `  komando ssh-gate line --name phone ~/phone.pub
  komando ssh-gate line --name phone-read --read-only 'ssh-ed25519 AAAA... phone'
  komando ssh-gate line --name phone-checks --read-only --network ~/phone.pub
  komando ssh-gate line --name ops --shell-access ~/ops.pub`,
		Args: cobra.ExactArgs(1),
		RunE: inCall(func(cl *call, cmd *cobra.Command, args []string) error {
			if !gateLabel.MatchString(name) {
				return out.Usage("--name takes 1 to 64 letters, digits, dots, dashes or underscores")
			}
			if network && !readOnly {
				return out.Usage("--network goes with --read-only: a key that may change things runs any program on servers already").
					WithHint("for example: komando ssh-gate line --name " + name + " --read-only --network " + args[0])
			}
			if shellAccess && readOnly {
				return out.Usage("--shell-access goes with a key that may change things: a --read-only key opens no shell").
					WithHint("for example: komando ssh-gate line --name " + name + " --shell-access " + args[0])
			}
			key, err := gatePublicKey(args[0])
			if err != nil {
				return err
			}
			self := komandoPath()
			if !strings.HasPrefix(self, "/") {
				return out.Errf(out.ExitError, "SSH_GATE_PATH", "run komando by its full path, for example /usr/local/bin/komando ssh-gate line ...",
					"komando cannot tell its own full path, which the line needs")
			}
			command := gateShellQuote(self) + " ssh-gate --name " + name
			if readOnly {
				command += " --read-only"
			}
			if network {
				command += " --network"
			}
			opts := "restrict,"
			if shellAccess {
				command += " --shell-access"
				opts += "pty," // sshd gives the key a terminal when it asks for one
			}
			// in authorized_keys, " and \ inside command="..." are escaped
			escaped := strings.NewReplacer(`\`, `\\`, `"`, `\"`).Replace(command)
			cl.out.Print("ssh-gate.line", gateLine{
				Line: opts + `command="` + escaped + `" ` + key, Name: name, ReadOnly: readOnly, Network: network, ShellAccess: shellAccess,
				Komando: self, AddTo: "~/.ssh/authorized_keys",
			}, nil)
			return nil
		}),
	}
	c.Flags().StringVar(&name, "name", "", "the key's name in the audit log (required)")
	c.Flags().BoolVar(&readOnly, "read-only", false, "the key runs only commands that read")
	c.Flags().BoolVar(&network, "network", false, "with --read-only: the key may also run reads that reach the network (net, cert check of a URL, exec --read-only)")
	c.Flags().BoolVar(&shellAccess, "shell-access", false, "the key may also open a login shell on one server (ssh -t HOST komando shell SERVER); not with --read-only")
	_ = c.MarkFlagRequired("name")
	return c
}

// gatePublicKey reads a public key line, or a file holding one, and gives
// it back as "TYPE BASE64 COMMENT", without options.
func gatePublicKey(arg string) (string, error) {
	text := arg
	if _, _, _, _, err := ssh.ParseAuthorizedKey([]byte(arg)); err != nil {
		if fi, serr := os.Stat(arg); serr == nil && fi.Mode().IsRegular() && fi.Size() < 64<<10 {
			b, rerr := os.ReadFile(arg)
			if rerr != nil {
				return "", rerr
			}
			text = string(b)
		}
	}
	pub, comment, options, _, err := ssh.ParseAuthorizedKey([]byte(text))
	if err != nil {
		return "", out.Errf(out.ExitUsage, "USAGE", "give the key's public line (ssh-ed25519 AAAA... name) or its .pub file",
			"not an SSH public key")
	}
	if len(options) > 0 {
		return "", out.Errf(out.ExitUsage, "USAGE", "give the public key line without options; ssh-gate line adds its own",
			"the key line already has options (%s)", strings.Join(options, ","))
	}
	line := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(pub)))
	if comment = strings.TrimSpace(comment); comment != "" && !strings.ContainsAny(comment, "\r\n") {
		line += " " + comment
	}
	return line, nil
}

// gateShellQuote quotes a path for the shell sshd runs the forced command
// with, when it needs it.
func gateShellQuote(s string) string {
	if regexp.MustCompile(`^[A-Za-z0-9/._+-]+$`).MatchString(s) {
		return s
	}
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}
