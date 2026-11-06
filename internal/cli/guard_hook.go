package cli

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"

	"github.com/sgnd/komando/internal/store"
)

// guideGuardCmd is the hook an agent harness runs before each tool call. It
// reads the call as JSON on stdin and answers in Claude Code's hook format.
// Anything it cannot read is let through: the guard must never stop work it
// does not understand.
func guideGuardCmd() *cobra.Command {
	var agent string
	c := &cobra.Command{
		Use:    "guard",
		Short:  "Hook for AI agents: stop tool calls that would read secrets on this computer",
		Hidden: true,
		Args:   cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if agent != "" && agent != "claude" {
				b, err := io.ReadAll(io.LimitReader(os.Stdin, 4<<20))
				home, herr := os.UserHomeDir()
				d := allow()
				if err == nil && herr == nil {
					d = guardAgent(agent, b, home)
				}
				if a := guardAnswer(agent, d); a != nil {
					os.Stdout.Write(a)
				}
				return nil
			}
			var call struct {
				Tool  string         `json:"tool_name"`
				Input map[string]any `json:"tool_input"`
				Cwd   string         `json:"cwd"`
			}
			b, err := io.ReadAll(io.LimitReader(os.Stdin, 4<<20))
			if err != nil || json.Unmarshal(b, &call) != nil {
				return nil
			}
			home, err := os.UserHomeDir()
			if err != nil {
				return nil
			}
			d := checkTool(call.Tool, call.Input, home, hookCwd(call.Cwd))
			if !d.Deny {
				return nil
			}
			return json.NewEncoder(os.Stdout).Encode(map[string]any{"hookSpecificOutput": map[string]any{
				"hookEventName":            "PreToolUse",
				"permissionDecision":       "deny",
				"permissionDecisionReason": "komando guard: " + d.Reason,
			}})
		},
	}
	c.Flags().StringVar(&agent, "for", "", "the harness: claude (default), cursor, gemini or codex")
	return c
}

// hookCwd is the working folder a hook input names, when it is a usable one.
func hookCwd(cwd string) string {
	if !filepath.IsAbs(cwd) {
		return ""
	}
	return filepath.Clean(cwd)
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
	command := shellQuote(komandoPath) + " guide guard"
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
		f.Backup = path + ".bak"
	}
	if dryRun {
		return f, nil
	}
	if f.Backup != "" {
		if err := os.WriteFile(f.Backup, old, 0o600); err != nil {
			return f, err
		}
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return f, err
	}
	return f, store.WriteFileAtomic(path, buf.Bytes(), 0o600)
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

// komandoPath is how the hook calls komando: the name found in PATH when it
// is this program (it survives upgrades), else this program's own path.
func komandoPath() string {
	self, _ := os.Executable()
	if p, err := exec.LookPath("komando"); err == nil {
		if a, b := statOf(p), statOf(self); a != nil && b != nil && os.SameFile(a, b) {
			if abs, err := filepath.Abs(p); err == nil {
				return abs
			}
		}
	}
	if self == "" {
		return "komando"
	}
	return self
}

func statOf(p string) os.FileInfo {
	fi, err := os.Stat(p)
	if err != nil {
		return nil
	}
	return fi
}

func shellQuote(s string) string {
	if strings.ContainsAny(s, " '\"$`\\") {
		return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
	}
	return s
}
