package cli

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os/exec"
)

// tunnelServeProcess is the background process of tunnel start for tunnel
// id: the host key policy this command checked, and the passwords typed
// for the login-ask servers on the way on its input (never in its
// arguments or environment).
func tunnelServeProcess(cl *call, self, id string, logins map[string]string) *exec.Cmd {
	pargs := []string{"tunnel", "serve", id}
	if cl.flags.hostKeyPolicy != "" {
		pargs = append(pargs, "--host-key-policy", cl.flags.hostKeyPolicy)
		if cl.flags.hostKeyPolicy == "off" {
			pargs = append(pargs, "--yes") // checked by this command already
		}
	}
	if len(logins) > 0 {
		pargs = append(pargs, loginsStdinFlag)
	}
	p := tunnelServeCommand(self, pargs)
	p.Stdin = nil
	if len(logins) > 0 {
		p.Stdin = loginsInput(logins)
	}
	return p
}

// serveLogins: tunnel serve asks nobody, and has only the passwords tunnel
// start typed (read from stdin when fromStdin).
func serveLogins(cl *call, fromStdin bool) error {
	cl.logins.background = true
	if !fromStdin {
		return nil
	}
	in := bufio.NewReader(cl.stdin)
	if err := readLogins(cl, in); err != nil {
		return err
	}
	cl.stdin = in
	return nil
}

// serveFail is how tunnel serve says why it stops: one ERROR line, which
// tunnel start reads from its log.
func serveFail(cl *call, err error) error {
	e := toErr(err)
	b, _ := json.Marshal(serveErr{Code: e.Code, Message: e.Message, Hint: e.Hint, Exit: e.Exit})
	fmt.Fprintf(cl.out.W, "ERROR %s\n", b)
	return exitCode(1)
}
