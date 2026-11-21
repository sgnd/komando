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
	// Args is the command line (argv); nil when the system does not let
	// this user read it. A node program's Name is "node": its argv[1] names
	// the harness.
	Args []string
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

// agentPrograms are the program names of agent harnesses (the command's
// base name without an extension, in lower case), one entry per supported
// agent that runs on this computer. A node or python harness is named by
// its argv[1], so argv[0] and argv[1] are both matched.
var agentPrograms = map[string]string{
	"claude":       "Claude Code",
	"codex":        "Codex",
	"cursor-agent": "Cursor",
	"gemini":       "Gemini CLI",
	"opencode":     "OpenCode",
	"openhands":    "OpenHands",
	"goose":        "Goose",
	"aider":        "Aider",
	"cline":        "Cline",
	"kiro":         "Kiro",
	"kiro-cli":     "Kiro",
	"kimi":         "Kimi Code",
	"droid":        "Factory",
}

// agentPackages are folder names a harness's script lives in (an npm
// package such as .../claude-code/cli.js); a whole path part must match.
var agentPackages = map[string]string{
	"claude-code":  "Claude Code",
	"gemini-cli":   "Gemini CLI",
	"codex-cli":    "Codex",
	"cursor-agent": "Cursor",
	"opencode-ai":  "OpenCode",
	"kimi-cli":     "Kimi Code",
	"kiro-cli":     "Kiro",
}

// programAgent is the agent a process's name or command line names, or "".
func programAgent(p Proc) string {
	names := []string{p.Name}
	for i := 0; i < len(p.Args) && i < 2; i++ {
		names = append(names, p.Args[i])
	}
	for _, n := range names {
		base := strings.ToLower(filepath.Base(n))
		base = strings.TrimSuffix(base, filepath.Ext(base))
		if a, ok := agentPrograms[base]; ok {
			return a
		}
	}
	if len(p.Args) > 1 {
		for _, part := range strings.Split(filepath.ToSlash(p.Args[1]), "/") {
			if a, ok := agentPackages[strings.ToLower(part)]; ok {
				return a
			}
		}
	}
	return ""
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
		if a := programAgent(p); a != "" {
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

// procArgs is the command line and the environment lines of a macOS
// kern.procargs2 buffer: argc, the program path, padding, argc arguments,
// then KEY=value lines.
func procArgs(raw []byte) (args, env []string) {
	if len(raw) < 4 {
		return nil, nil
	}
	argc := int(binary.LittleEndian.Uint32(raw))
	parts := bytes.Split(raw[4:], []byte{0})
	i := 1 // the program path
	for i < len(parts) && len(parts[i]) == 0 {
		i++
	}
	for n := 0; n < argc && i < len(parts); n, i = n+1, i+1 {
		args = append(args, string(parts[i]))
	}
	for ; i < len(parts) && len(parts[i]) > 0; i++ {
		env = append(env, string(parts[i]))
	}
	return args, env
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
