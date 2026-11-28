package cli

import (
	"bytes"
	"cmp"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"maps"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"strings"
	"time"

	"github.com/sgnd/komando/internal/store"
)

// The guard for agents other than Claude Code. Each harness sends its tool
// calls in its own shape and wants the answer in its own shape; guardCall
// turns a call into the Claude Code tool checkTool knows, and guardAnswer
// writes the decision back:
//
//	Cursor     ~/.cursor/hooks.json   beforeShellExecution, beforeReadFile, preToolUse
//	Gemini CLI ~/.gemini/settings.json hooks.BeforeTool (v0.26+)
//	Codex      ~/.codex/hooks.json     hooks.PreToolUse (a person approves it once in /hooks)

// agentCall is one tool call, as checkTool sees it.
type agentCall struct {
	tool string
	in   map[string]any
}

// guardCalls reads a harness's hook input into the calls to check (a patch
// can touch several files). Unknown input gives none: it is let through.
func guardCalls(agent string, b []byte) []agentCall {
	var m map[string]any
	if json.Unmarshal(b, &m) != nil {
		return nil
	}
	str := func(m map[string]any, k string) string { s, _ := m[k].(string); return s }
	input, _ := m["tool_input"].(map[string]any)
	if input == nil {
		input = map[string]any{}
	}
	switch agent {
	case "cursor":
		switch str(m, "hook_event_name") {
		case "beforeShellExecution":
			return []agentCall{{"Bash", map[string]any{"command": str(m, "command")}}}
		case "beforeReadFile":
			return []agentCall{{"Read", map[string]any{"file_path": str(m, "file_path")}}}
		}
		switch str(m, "tool_name") {
		case "Shell":
			return []agentCall{{"Bash", map[string]any{"command": str(input, "command")}}}
		case "Read", "Write", "Delete":
			return []agentCall{{"Read", map[string]any{"file_path": cmp.Or(str(input, "file_path"), str(input, "path"), str(input, "target_file"))}}}
		case "Grep":
			return []agentCall{{"Grep", map[string]any{"path": str(input, "path"), "glob": str(input, "glob")}}}
		}
	case "gemini":
		switch str(m, "tool_name") {
		case "run_shell_command":
			return []agentCall{{"Bash", map[string]any{"command": str(input, "command")}}}
		case "read_file", "write_file", "replace":
			return []agentCall{{"Read", map[string]any{"file_path": str(input, "file_path")}}}
		case "read_many_files":
			var calls []agentCall
			for _, k := range []string{"paths", "include"} {
				l, _ := input[k].([]any)
				for _, p := range l {
					if s, ok := p.(string); ok {
						calls = append(calls, agentCall{"Grep", map[string]any{"path": s, "glob": s}})
					}
				}
			}
			return calls
		case "glob":
			return []agentCall{{"Glob", map[string]any{"path": str(input, "path"), "glob": str(input, "pattern")}}}
		case "grep_search":
			return []agentCall{{"Grep", map[string]any{"path": str(input, "path"), "glob": str(input, "include")}}}
		case "list_directory":
			return []agentCall{{"Glob", map[string]any{"path": str(input, "dir_path")}}}
		}
	case "codex":
		switch str(m, "tool_name") {
		case "Bash":
			return []agentCall{{"Bash", map[string]any{"command": str(input, "command")}}}
		case "apply_patch", "Edit", "Write":
			var calls []agentCall
			for _, p := range patchFiles(str(input, "command")) {
				calls = append(calls, agentCall{"Write", map[string]any{"file_path": p}})
			}
			if p := str(input, "file_path"); p != "" {
				calls = append(calls, agentCall{"Write", map[string]any{"file_path": p}})
			}
			return calls
		}
	}
	return nil
}

// patchFiles lists the files an apply_patch patch touches.
func patchFiles(patch string) []string {
	var files []string
	for _, l := range strings.Split(patch, "\n") {
		l = strings.TrimSpace(l)
		for _, pre := range []string{"*** Update File: ", "*** Add File: ", "*** Delete File: ", "*** Move to: "} {
			if p, ok := strings.CutPrefix(l, pre); ok {
				files = append(files, strings.TrimSpace(p))
			}
		}
	}
	return files
}

// guardAnswer is the harness's way to deny (or, for Cursor, to allow).
func guardAnswer(agent string, d guardDecision) []byte {
	reason := "komando guard: " + d.Reason
	var v any
	switch agent {
	case "cursor":
		if !d.Deny {
			v = map[string]any{"permission": "allow"}
		} else {
			v = map[string]any{"permission": "deny", "user_message": reason, "agent_message": reason}
		}
	case "gemini":
		if !d.Deny {
			return nil
		}
		v = map[string]any{"decision": "deny", "reason": reason}
	default: // codex, claude
		if !d.Deny {
			return nil
		}
		v = map[string]any{"hookSpecificOutput": map[string]any{"hookEventName": "PreToolUse", "permissionDecision": "deny", "permissionDecisionReason": reason}}
	}
	b, _ := json.Marshal(v)
	return append(b, '\n')
}

// guardAgent decides all of one hook input's calls: the first denial wins.
func guardAgent(cl *call, agent string, b []byte, home string) guardDecision {
	var where struct {
		Cwd string `json:"cwd"`
	}
	_ = json.Unmarshal(b, &where)
	for _, c := range guardCalls(agent, b) {
		if d := checkTool(cl, c.tool, c.in, home, hookCwd(where.Cwd)); d.Deny {
			return d
		}
	}
	return allow()
}

// agentHooks are the harnesses `agent skill install` sets the guard up for, when
// the person uses them (their folder exists).
var agentHooks = []struct {
	name, dir, file string
	add             func(settings map[string]any, command string)
}{
	{"cursor", ".cursor", "hooks.json", func(s map[string]any, cmd string) {
		s["version"] = 1
		hooks := mapIn(s, "hooks")
		for ev, matcher := range map[string]string{"beforeShellExecution": "", "beforeReadFile": "", "preToolUse": "Write|Grep|Delete"} {
			entry := map[string]any{"command": cmd}
			if matcher != "" {
				entry["matcher"] = matcher
			}
			hooks[ev] = append(withoutGuard(hooks[ev]), entry)
		}
	}},
	{"gemini", ".gemini", "settings.json", func(s map[string]any, cmd string) {
		hooks := mapIn(s, "hooks")
		hooks["BeforeTool"] = append(withoutGuard(hooks["BeforeTool"]), map[string]any{
			"matcher": "run_shell_command|read_file|read_many_files|write_file|replace|grep_search|glob|list_directory",
			"hooks":   []any{map[string]any{"name": "komando-guard", "type": "command", "command": cmd, "timeout": 5000}},
		})
	}},
	{"codex", ".codex", "hooks.json", func(s map[string]any, cmd string) {
		hooks := mapIn(s, "hooks")
		hooks["PreToolUse"] = append(withoutGuard(hooks["PreToolUse"]), map[string]any{
			"matcher": "Bash|apply_patch|Edit|Write",
			"hooks":   []any{map[string]any{"type": "command", "command": cmd, "timeout": 30}},
		})
	}},
}

func mapIn(m map[string]any, k string) map[string]any {
	v, _ := m[k].(map[string]any)
	if v == nil {
		v = map[string]any{}
		m[k] = v
	}
	return v
}

// withoutGuard drops komando's own entries (an older install) from a hook list.
func withoutGuard(v any) []any {
	l, _ := v.([]any)
	kept := []any{}
	for _, e := range l {
		m, ok := e.(map[string]any)
		if ok {
			if c, _ := m["command"].(string); strings.Contains(c, " guide guard") {
				continue
			}
			if isGuardEntry(m) {
				continue
			}
		}
		kept = append(kept, e)
	}
	return kept
}

// installAgentHook adds the guard to one harness's settings file, keeping
// everything else in it, like installGuardHook does for Claude Code.
func installAgentHook(path string, add func(map[string]any, string), command string, dryRun bool) (skillFile, error) {
	f := skillFile{Path: path, Action: "created"}
	settings := map[string]any{}
	old, err := os.ReadFile(path)
	switch {
	case err == nil:
		if len(bytes.TrimSpace(old)) > 0 {
			if err := json.Unmarshal(old, &settings); err != nil {
				return f, fmt.Errorf("%s is not valid JSON, so komando left it alone: %v", path, err)
			}
		}
		f.Action = "updated"
	case !errors.Is(err, fs.ErrNotExist):
		return f, err
	}
	add(settings, command)
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(settings); err != nil {
		return f, err
	}
	if bytes.Equal(buf.Bytes(), old) {
		f.Action = "unchanged"
		return f, nil
	}
	if f.Action == "updated" {
		f.Backup = newBackup(path)
	}
	if dryRun {
		return f, nil
	}
	if f.Backup != "" {
		if err := saveBackup(f.Backup, old); err != nil {
			return f, err
		}
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return f, err
	}
	return f, store.WriteFileAtomic(path, buf.Bytes(), 0o600)
}

// guardHookTools are the Claude Code tools the guard looks at.
const guardHookTools = "Bash|Read|Edit|Write|MultiEdit|NotebookEdit|Grep|Glob"

// installGuardHook adds the guard to a Claude Code settings file, keeping
// everything else in it. It returns the action like installSkill.
func installGuardHook(path, komandoPath string, dryRun bool) (skillFile, error) {
	f := skillFile{Path: path, Action: "created"}
	settings := map[string]any{}
	old, err := os.ReadFile(path)
	switch {
	case err == nil:
		if err := json.Unmarshal(old, &settings); err != nil {
			return f, fmt.Errorf("%s is not valid JSON, so komando left it alone: %v", path, err)
		}
		f.Action = "updated"
	case !errors.Is(err, fs.ErrNotExist):
		return f, err
	}
	command := guardHookLine(komandoPath, "claude")
	hooks, _ := settings["hooks"].(map[string]any)
	if hooks == nil {
		hooks = map[string]any{}
	}
	pre, _ := hooks["PreToolUse"].([]any)
	kept := []any{}
	for _, e := range pre {
		if m, ok := e.(map[string]any); ok && isGuardEntry(m) {
			continue // an older komando guard: replaced below
		}
		kept = append(kept, e)
	}
	kept = append(kept, map[string]any{
		"matcher": guardHookTools,
		"hooks":   []any{map[string]any{"type": "command", "command": command}},
	})
	hooks["PreToolUse"] = kept
	settings["hooks"] = hooks
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(settings); err != nil {
		return f, err
	}
	if bytes.Equal(buf.Bytes(), old) {
		f.Action = "unchanged"
		return f, nil
	}
	if f.Action == "updated" {
		f.Backup = newBackup(path)
	}
	if dryRun {
		return f, nil
	}
	if f.Backup != "" {
		if err := saveBackup(f.Backup, old); err != nil {
			return f, err
		}
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return f, err
	}
	return f, store.WriteFileAtomic(path, buf.Bytes(), 0o600)
}

// newBackup is the name the old copy of an agent's settings or skill file
// gets: PATH.bak, or PATH.bak.<UTC time> when that is taken. A backup
// there already (the user's own .bak too, or a link of that name) is never
// written over.
func newBackup(path string) string {
	return backupName(path, time.Now(), func(p string) bool { _, err := os.Lstat(p); return err == nil })
}

// saveBackup writes it 0600 (settings files can hold tokens) through a
// temporary file of a random name, so never through a link.
func saveBackup(name string, old []byte) error {
	if _, err := os.Lstat(name); err == nil {
		return fmt.Errorf("%s appeared while komando wrote it; nothing was changed, run it again", name)
	}
	return store.WriteFileAtomic(name, old, 0o600)
}

// guardDidNotRun is the reason a harness reads when komando's guard could
// not answer: the program is gone, is not a program, crashed or failed.
const guardDidNotRun = "it did not run, so the call is refused: run komando doctor"

// hookOS is the system the hook line is written for; tests set it.
var hookOS = runtime.GOOS

// guardHookLine is the hook command for harness h (claude, cursor, gemini,
// codex). sh runs komando's guard on the call (stdin passes through) and
// prints its answer only when the guard ran to the end; on any failure it
// prints h's own deny instead, so the harness refuses the call rather than
// going on without the guard.
func guardHookLine(prog, h string) string {
	if hookOS == "windows" {
		// no /bin/sh: komando's guard is called directly, as before 0.17.2,
		// and a call goes through when komando is missing (doctor says so;
		// a PowerShell wrapper is row C419)
		line := shellQuote(prog) + " guide guard"
		if h != "claude" {
			line += " --for " + h
		}
		return line
	}
	refuse := strings.TrimSpace(string(guardAnswer(h, deny(guardDidNotRun))))
	script := `out=$("$0" guide guard --for ` + h + `) && printf %s "$out" || { printf %s ` + shellQuote(refuse) +
		`; echo ` + shellQuote("komando guard: "+guardDidNotRun) + ` >&2; }`
	return "/bin/sh -c " + shellQuote(script) + " " + shellQuote(prog)
}

// hookLineProgram is the komando program a guard hook line runs, and
// whether the line is guardHookLine's form; an older line names the
// program as its first word.
func hookLineProgram(line string) (prog string, wrapped bool) {
	if w := shellWords(line); len(w) == 4 && w[0] == "/bin/sh" && w[1] == "-c" && strings.Contains(w[2], `"$0" guide guard --for `) {
		return w[3], true
	}
	return firstWord(line), false
}

func isGuardEntry(m map[string]any) bool {
	hs, _ := m["hooks"].([]any)
	for _, h := range hs {
		if hm, ok := h.(map[string]any); ok {
			if c, _ := hm["command"].(string); strings.HasSuffix(c, " guide guard") || strings.Contains(c, " guide guard --for ") {
				return true
			}
		}
	}
	return false
}

// komandoPath is how the hook calls komando: the full path found in PATH
// when it is this program (it survives upgrades), else this program's own
// path, or "" when the system cannot say. Never a bare name: PATH is where
// an AI agent could put a program of its own first.
func komandoPath() string {
	self, _ := selfProgram()
	if p, err := exec.LookPath("komando"); err == nil {
		if a, b := statOf(p), statOf(self); a != nil && b != nil && os.SameFile(a, b) {
			if abs, err := filepath.Abs(p); err == nil {
				return abs
			}
		}
	}
	return self
}

// selfProgram is os.Executable; tests replace it.
var selfProgram = os.Executable

func statOf(p string) os.FileInfo {
	fi, err := os.Stat(p)
	if err != nil {
		return nil
	}
	return fi
}

// shellQuote writes s as one shell word: as it is when every character is
// plain, else in single quotes. An empty value is a pair of quotes (an argument, not
// nothing), and ; | & < > ( ) * ? ~ # and line breaks are quoted too, so a
// value read from a file cannot add a second command to a line komando
// prints for a person to copy.
func shellQuote(s string) string {
	if s != "" && plainShellWord.MatchString(s) {
		return s
	}
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

var plainShellWord = regexp.MustCompile(`^[A-Za-z0-9_./:=@%+,-]+$`)

// claudeGuard reads a harness's settings file (Claude Code's, or another
// agent's hook file): whether it has komando's guard, and "" or what keeps
// that guard from refusing a call it cannot check (guardHookProblem).
func claudeGuard(path string) (found bool, problem string) {
	b, err := os.ReadFile(path)
	if err != nil {
		return false, ""
	}
	var settings any
	if json.Unmarshal(b, &settings) != nil {
		return strings.Contains(string(b), " guide guard"), path + " is not valid JSON, so the agent reads no hooks from it"
	}
	for _, c := range guardHookCommands(settings) {
		found = true
		if problem == "" {
			problem = guardHookProblem(c)
		}
	}
	return found, problem
}

// guardHookCommands are the guard hook lines anywhere in a settings file,
// in the old form and in guardHookLine's.
func guardHookCommands(v any) []string {
	var lines []string
	switch v := v.(type) {
	case map[string]any:
		if c, ok := v["command"].(string); ok && strings.Contains(c, " guide guard") {
			lines = append(lines, c)
		}
		for _, k := range slices.Sorted(maps.Keys(v)) {
			lines = append(lines, guardHookCommands(v[k])...)
		}
	case []any:
		for _, e := range v {
			lines = append(lines, guardHookCommands(e)...)
		}
	}
	return lines
}

// guardHookProblem says what keeps one guard hook line from refusing a
// call komando cannot check, or "".
func guardHookProblem(line string) string {
	prog, wrapped := hookLineProgram(line)
	why := guardProgramProblem(prog)
	switch {
	case why != "" && wrapped:
		return why + ", so the agent's every tool call is refused"
	case why != "":
		return why + ", so the agent goes on without the guard"
	case !wrapped && hookOS != "windows":
		return "it uses the old hook line, which lets a call through when komando is missing"
	}
	return ""
}

// guardProgramProblem says why the program a hook names cannot run, or "".
func guardProgramProblem(prog string) string {
	if !filepath.IsAbs(prog) {
		// found through PATH when the hook runs, where an AI agent could put
		// a program of its own first
		return "its command " + prog + " is not a full path"
	}
	fi, err := os.Stat(prog)
	switch {
	case err != nil:
		return "its command " + prog + " does not exist"
	case fi.IsDir() || runtime.GOOS != "windows" && fi.Mode()&0o111 == 0: // Windows has no mode bits
		return "its command " + prog + " is not a program"
	case runtime.GOOS != "windows" && fi.Mode()&0o002 != 0:
		return "its command " + prog + " may be changed by every user of this computer"
	}
	return ""
}

// firstWord is the first word of a shell command line, unquoted: the
// program a hook runs (shellQuote writes it).
func firstWord(line string) string {
	var b strings.Builder
	quote := byte(0)
	line = strings.TrimSpace(line)
	for i := 0; i < len(line); i++ {
		c := line[i]
		switch {
		case quote != 0 && c == quote:
			quote = 0
		case quote != 0:
			b.WriteByte(c)
		case c == '\'' || c == '"':
			quote = c
		case c == '\\' && i+1 < len(line):
			i++
			b.WriteByte(line[i])
		case c == ' ' || c == '\t':
			return b.String()
		default:
			b.WriteByte(c)
		}
	}
	return b.String()
}
