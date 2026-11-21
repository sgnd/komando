//go:build linux

package engine

import (
	"os"
	"strconv"
	"strings"
)

func parentPID() int { return os.Getppid() }

type procFS struct{}

func osProcs() ProcTable { return procFS{} }

func (procFS) Proc(pid int) (Proc, bool) {
	dir := "/proc/" + strconv.Itoa(pid)
	b, err := os.ReadFile(dir + "/stat")
	if err != nil {
		return Proc{}, false
	}
	ppid, name, ok := parseProcStat(string(b))
	if !ok {
		return Proc{}, false
	}
	p := Proc{PPID: ppid, Name: name}
	if e, err := os.ReadFile(dir + "/environ"); err == nil {
		p.Env = envLookup(strings.Split(string(e), "\x00"))
	}
	return p, true
}
