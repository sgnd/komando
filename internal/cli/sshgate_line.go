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
	Line     string `json:"line"`
	Name     string `json:"name"`
	ReadOnly bool   `json:"read_only"`
	Network  bool   `json:"network"`
	Komando  string `json:"komando"`
	AddTo    string `json:"add_to"`
}

func (l gateLine) Text() string { return l.Line + "\n" }

func sshGateLineCmd() *cobra.Command {
	var name string
	var readOnly, network bool
	c := &cobra.Command{
		Use:   "line PUBLIC_KEY --name NAME",
		Short: "Print the authorized_keys line that limits a key to komando",
		Long: `Prints the line to add to ~/.ssh/authorized_keys on this computer, so the
key runs komando through ssh-gate and nothing else. PUBLIC_KEY is the key's
line (ssh-ed25519 AAAA... comment) or a .pub file holding it. The line names
this komando by its full path, as sshd does not search PATH.

A --read-only key runs only commands that read, and only those that stay
on the servers and conns in your list: no net checks, no cert check of
a website, and no exec, job start, docker exec, cluster exec or recipe run,
whose programs can connect anywhere and carry what they read in a URL or a
DNS name. Add --network too for a read key that may do those.`,
		Example: `  komando ssh-gate line --name phone ~/phone.pub
  komando ssh-gate line --name phone-read --read-only 'ssh-ed25519 AAAA... phone'
  komando ssh-gate line --name phone-checks --read-only --network ~/phone.pub`,
		Args: cobra.ExactArgs(1),
		RunE: inCall(func(cl *call, cmd *cobra.Command, args []string) error {
			if !gateLabel.MatchString(name) {
				return out.Usage("--name takes 1 to 64 letters, digits, dots, dashes or underscores")
			}
			if network && !readOnly {
				return out.Usage("--network goes with --read-only: a key that may change things runs any program on servers already").
					WithHint("for example: komando ssh-gate line --name " + name + " --read-only --network " + args[0])
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
			// in authorized_keys, " and \ inside command="..." are escaped
			escaped := strings.NewReplacer(`\`, `\\`, `"`, `\"`).Replace(command)
			cl.out.Print("ssh-gate.line", gateLine{
				Line: `restrict,command="` + escaped + `" ` + key, Name: name, ReadOnly: readOnly, Network: network,
				Komando: self, AddTo: "~/.ssh/authorized_keys",
			}, nil)
			return nil
		}),
	}
	c.Flags().StringVar(&name, "name", "", "the key's name in the audit log (required)")
	c.Flags().BoolVar(&readOnly, "read-only", false, "the key runs only commands that read")
	c.Flags().BoolVar(&network, "network", false, "with --read-only: the key may also run reads that reach the network (net, cert check of a URL, exec --read-only)")
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
