package engine

import (
	"bytes"
	"encoding/binary"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
)

// Proc is what komando can learn about one process above it.
type Proc struct {
	PPID int
	Name string // the program's name, as the system lists it
	// Env looks up the process's environment; nil when the system does not
	// let this user read it.
	Env func(string) (string, bool)
}

// ProcTable lists processes by id.
type ProcTable interface {
	Proc(pid int) (Proc, bool)
}

// maxAncestors bounds the walk up the process tree.
const maxAncestors = 64

// agentPrograms are the names of agent harnesses that are native programs.
// The match is on the whole name, in lower case.
var agentPrograms = map[string]string{
	"claude":       "Claude Code",
	"codex":        "Codex",
	"cursor-agent": "Cursor",
}

// AncestorAgent is the AI agent among the processes above pid (pid
// included), or "". An agent's harness sets its variables in the shell it
// runs commands in and a program that strips them from its own environment
// does not change the processes above it. Only a process that leaves the
// tree (it forks and lets its parent exit, so init adopts it) is out of
// reach.
func AncestorAgent(t ProcTable, pid int) string {
	seen := map[int]bool{}
	for i := 0; i < maxAncestors && pid > 1 && !seen[pid]; i++ {
		seen[pid] = true
		p, ok := t.Proc(pid)
		if !ok {
			return ""
		}
		if p.Env != nil {
			if a := AgentName(p.Env); a != "" {
				return a
			}
		}
		if a, ok := agentPrograms[strings.ToLower(filepath.Base(p.Name))]; ok {
			return a
		}
		pid = p.PPID
	}
	return ""
}

var (
	parentOnce  sync.Once
	parentAgent string
)

// ParentAgent is AncestorAgent for the running program, worked out once.
func ParentAgent() string {
	parentOnce.Do(func() { parentAgent = AncestorAgent(osProcs(), parentPID()) })
	return parentAgent
}

// parseProcStat reads the parent id and the name from /proc/PID/stat
// ("pid (name) state ppid ..."; the name may hold spaces and brackets).
func parseProcStat(s string) (ppid int, name string, ok bool) {
	open, end := strings.IndexByte(s, '('), strings.LastIndexByte(s, ')')
	if open < 0 || end < open {
		return 0, "", false
	}
	rest := strings.Fields(s[end+1:])
	if len(rest) < 2 {
		return 0, "", false
	}
	ppid, err := strconv.Atoi(rest[1])
	return ppid, s[open+1 : end], err == nil
}

// procArgsEnv is the environment lines of a macOS kern.procargs2 buffer:
// argc, the program path, padding, argc arguments, then KEY=value lines.
func procArgsEnv(raw []byte) []string {
	if len(raw) < 4 {
		return nil
	}
	argc := int(binary.LittleEndian.Uint32(raw))
	parts := bytes.Split(raw[4:], []byte{0})
	i := 1 // the program path
	for i < len(parts) && len(parts[i]) == 0 {
		i++
	}
	i += argc
	var env []string
	for ; i < len(parts) && len(parts[i]) > 0; i++ {
		env = append(env, string(parts[i]))
	}
	return env
}

// envLookup looks keys up in KEY=value lines.
func envLookup(lines []string) func(string) (string, bool) {
	return func(k string) (string, bool) {
		for _, l := range lines {
			if v, ok := strings.CutPrefix(l, k+"="); ok {
				return v, true
			}
		}
		return "", false
	}
}
