//go:build darwin

package engine

import (
	"os"

	"golang.org/x/sys/unix"
)

func parentPID() int { return os.Getppid() }

type sysctlProcs struct{}

func osProcs() ProcTable { return sysctlProcs{} }

func (sysctlProcs) Proc(pid int) (Proc, bool) {
	k, err := unix.SysctlKinfoProc("kern.proc.pid", pid)
	if err != nil || int(k.Proc.P_pid) != pid {
		return Proc{}, false
	}
	comm := make([]byte, 0, len(k.Proc.P_comm))
	for _, c := range k.Proc.P_comm {
		if c == 0 {
			break
		}
		comm = append(comm, byte(c))
	}
	p := Proc{PPID: int(k.Eproc.Ppid), Name: string(comm)}
	if raw, err := unix.SysctlRaw("kern.procargs2", pid); err == nil {
		p.Env = envLookup(procArgsEnv(raw))
	}
	return p, true
}
