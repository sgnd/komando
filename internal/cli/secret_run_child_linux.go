package cli

import (
	"os/exec"
	"syscall"
)

// endWithKomando asks Linux to send the program SIGTERM when komando dies,
// even by SIGKILL. Linux ties it to the starting thread, so it can fire early.
func endWithKomando(c *exec.Cmd) {
	if c.SysProcAttr == nil {
		c.SysProcAttr = &syscall.SysProcAttr{}
	}
	c.SysProcAttr.Pdeathsig = syscall.SIGTERM
}
