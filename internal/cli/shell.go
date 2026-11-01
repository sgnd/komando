package cli

import (
	"os"
	"os/signal"
	"syscall"

	"github.com/spf13/cobra"
	"golang.org/x/crypto/ssh"
	"golang.org/x/term"

	"github.com/sgnd/komando/internal/out"
	"github.com/sgnd/komando/internal/sshx"
)

// shellCmd is the only interactive command, meant for humans taking over
// from an agent. Agents should use exec / job instead.
func shellCmd() *cobra.Command {
	return &cobra.Command{
		Use:     "shell HOST",
		Aliases: []string{"ssh", "connect"},
		Short:   "Interactive login shell (humans only; agents use exec/job)",
		Args:    cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			fd := int(os.Stdin.Fd())
			if !term.IsTerminal(fd) {
				return out.Errf(out.ExitUsage, "NOT_A_TTY", "use `komando exec` or `komando job start` for non-interactive work", "shell requires an interactive terminal")
			}
			st, err := loadState()
			if err != nil {
				return err
			}
			h, err := singleHost(st, args[0])
			if err != nil {
				return err
			}
			audit(st, "shell", []string{h.Name}, "", true, nil)
			return withClient(cmd.Context(), st, h, func(c *sshx.Client) error {
				sess, err := c.NewSession()
				if err != nil {
					return err
				}
				defer sess.Close()
				w, hgt, _ := term.GetSize(fd)
				t := os.Getenv("TERM")
				if t == "" {
					t = "xterm-256color"
				}
				if err := sess.RequestPty(t, hgt, w, ssh.TerminalModes{ssh.ECHO: 1}); err != nil {
					return err
				}
				old, err := term.MakeRaw(fd)
				if err != nil {
					return err
				}
				defer term.Restore(fd, old)
				sess.Stdin, sess.Stdout, sess.Stderr = os.Stdin, os.Stdout, os.Stderr
				winch := make(chan os.Signal, 1)
				signal.Notify(winch, syscall.SIGWINCH)
				defer signal.Stop(winch)
				go func() {
					for range winch {
						if w, h, err := term.GetSize(fd); err == nil {
							_ = sess.WindowChange(h, w)
						}
					}
				}()
				if err := sess.Shell(); err != nil {
					return err
				}
				err = sess.Wait()
				if ee, ok := err.(*ssh.ExitError); ok {
					return exitCode(ee.ExitStatus())
				}
				return err
			})
		},
	}
}
