package cli

import (
	"os/exec"
	"syscall"
)

// endWithKomando asks Linux to send the program SIGTERM when komando dies,
// even by SIGKILL, so it does not run on with the secrets. Linux ties this
// to the thread that started the program, not the process: if that OS
// thread exits first (Go may end idle threads), the program gets SIGTERM
// early. Go keeps the threads it starts programs on, so this is rare.
func endWithKomando(c *exec.Cmd) {
	if c.SysProcAttr == nil {
		c.SysProcAttr = &syscall.SysProcAttr{}
	}
	c.SysProcAttr.Pdeathsig = syscall.SIGTERM
}
