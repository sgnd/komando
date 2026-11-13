package cli

import (
	"bytes"
	"cmp"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

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
func guardAgent(agent string, b []byte, home string) guardDecision {
	var where struct {
		Cwd string `json:"cwd"`
	}
	_ = json.Unmarshal(b, &where)
	for _, c := range guardCalls(agent, b) {
		if d := checkTool(c.tool, c.in, home, hookCwd(where.Cwd)); d.Deny {
			return d
		}
	}
	return allow()
}

// agentHooks are the harnesses `guide install` sets the guard up for, when
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
		f.Backup = settingsBackup(path)
	}
	if dryRun {
		return f, nil
	}
	if f.Backup != "" {
		if err := saveSettingsBackup(f.Backup, old); err != nil {
			return f, err
		}
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return f, err
	}
	return f, store.WriteFileAtomic(path, buf.Bytes(), 0o600)
}
