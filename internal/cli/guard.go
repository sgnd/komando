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
	"regexp"
	"strings"

	"github.com/spf13/cobra"

	"github.com/sgnd/komando/internal/store"
)

// The agent guard keeps an AI agent's own tools (reading files, running
// shell commands on this computer) away from secrets, so the agent goes
// through komando, which hides them. komando cannot see what an agent does
// outside it; the agent's harness can, and asks komando before each tool
// call (`komando guide install` sets that up for Claude Code).

// guardDecision is what the guard says about one tool call. Deny is false
// for calls it lets through.
type guardDecision struct {
	Deny   bool
	Reason string
}

func allow() guardDecision { return guardDecision{} }

func deny(format string, a ...any) guardDecision {
	return guardDecision{Deny: true, Reason: fmt.Sprintf(format, a...)}
}

// checkTool decides about one agent tool call: the tool's name and input as
// Claude Code sends them (Read, Edit, Write, MultiEdit, NotebookEdit, Grep,
// Glob, Bash).
func checkTool(tool string, in map[string]any, home string) guardDecision {
	str := func(k string) string { s, _ := in[k].(string); return s }
	switch tool {
	case "Read", "Edit", "Write", "MultiEdit", "NotebookEdit":
		p := str("file_path")
		if p == "" {
			p = str("notebook_path")
		}
		if why := secretPath(p, home); why != "" {
			return deny("%s is %s. komando keeps it away from AI agents; ask the user if you need something from it%s", p, why, viaKomando(why))
		}
	case "Grep", "Glob":
		if why := secretPath(str("path"), home); why != "" {
			return deny("%s is %s; ask the user if you need something from it", str("path"), why)
		}
		if g := str("glob"); g != "" && sensitiveName(g) {
			return deny("%s matches files that hold secrets; leave them out of the search", g)
		}
	case "Bash":
		return checkShell(str("command"), home)
	}
	return allow()
}

func viaKomando(why string) string {
	if why == "komando's own data (vault, keys, inventory, audit log)" {
		return ". Use komando commands instead: `komando list`, `komando secret list`, `komando audit`"
	}
	return ""
}

// secretPath says why a path on this computer is off limits, or "".
func secretPath(p, home string) string {
	if p == "" {
		return ""
	}
	p = guardPath(p, home)
	in := func(dir string) bool {
		rel, err := filepath.Rel(dir, p)
		return err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
	}
	komandoDirs := []string{filepath.Join(home, ".komando")}
	if h := os.Getenv("KOMANDO_HOME"); h != "" {
		komandoDirs = append(komandoDirs, h)
	}
	for _, d := range komandoDirs {
		if in(d) {
			if strings.HasSuffix(p, ".pub") {
				return "" // a public key is meant to be shared
			}
			return "komando's own data (vault, keys, inventory, audit log)"
		}
	}
	for _, d := range []string{".gnupg", ".password-store", ".config/gcloud", ".azure", ".kube", "Library/Keychains"} {
		if in(filepath.Join(home, d)) {
			return "a credential store"
		}
	}
	base := filepath.Base(p)
	if in(filepath.Join(home, ".ssh")) && filepath.Clean(p) != filepath.Join(home, ".ssh") {
		switch {
		case strings.HasSuffix(base, ".pub"), strings.HasPrefix(base, "known_hosts"), base == "config", base == "authorized_keys":
			return ""
		}
		return "a private key"
	}
	if p == filepath.Join(home, ".docker", "config.json") {
		return "a credential store"
	}
	if sensitiveName(p) {
		return "a file that holds secrets"
	}
	return ""
}

func guardPath(p, home string) string {
	p = strings.Trim(p, `"'`)
	kh := os.Getenv("KOMANDO_HOME")
	if kh == "" {
		kh = filepath.Join(home, ".komando")
	}
	for _, v := range []struct{ name, dir string }{{"HOME", home}, {"KOMANDO_HOME", kh}} {
		for _, pre := range []string{"$" + v.name, "${" + v.name + "}"} {
			if p == pre {
				return v.dir
			}
			if strings.HasPrefix(p, pre+"/") {
				return filepath.Join(v.dir, p[len(pre)+1:])
			}
		}
	}
	if p == "~" {
		return home
	}
	if strings.HasPrefix(p, "~/") {
		return filepath.Join(home, p[2:])
	}
	return filepath.Clean(p)
}

// splitShell cuts a shell line into simple commands at ; | & && || newlines
// and parentheses, but not inside quotes: `grep 'a|ssh' f` is one command.
// $( and ` start a command even inside double quotes, because they run.
func splitShell(line string) []string {
	var segs []string
	var cur strings.Builder
	cut := func() {
		segs = append(segs, cur.String())
		cur.Reset()
	}
	var q byte
	subst := 0 // open $( inside double quotes
	for i := 0; i < len(line); i++ {
		c := line[i]
		switch {
		case q == '\'':
			if c == '\'' {
				q = 0
			}
			cur.WriteByte(c)
		case c == '\\' && i+1 < len(line):
			cur.WriteByte(c)
			cur.WriteByte(line[i+1])
			i++
		case q == '"' && c == '"':
			q = 0
			cur.WriteByte(c)
		case c == '`' || c == '$' && i+1 < len(line) && line[i+1] == '(':
			cut() // a command substitution: its own command, quoted or not
			if c == '$' {
				i++
				if q == '"' {
					subst++
				}
			}
		case q == '"' && c == ')' && subst > 0:
			cut()
			subst--
		case q == '"':
			cur.WriteByte(c)
		case c == '\'' || c == '"':
			q = c
			cur.WriteByte(c)
		case c == ';' || c == '|' || c == '&' || c == '\n' || c == '(' || c == ')':
			cut()
		default:
			cur.WriteByte(c)
		}
	}
	cut()
	if q != 0 {
		// an unclosed quote: the shell refuses the line, but be strict and
		// look at every part of it
		return anyOperator.Split(line, -1)
	}
	return segs
}

var anyOperator = regexp.MustCompile(`[;|&\n()` + "`" + `"']`)

// stripQuotedHeredocs drops the bodies of <<'EOF' heredocs: the shell does
// not expand them, so they are data (a file's content, a script for python),
// not commands. Unquoted heredocs stay: $(...) in them runs.
func stripQuotedHeredocs(line string) string {
	lines := strings.Split(line, "\n")
	var out []string
	for i := 0; i < len(lines); i++ {
		out = append(out, lines[i])
		m := heredocStart.FindStringSubmatch(lines[i])
		if m == nil {
			continue
		}
		for i++; i < len(lines) && strings.TrimLeft(lines[i], "\t") != m[2]; i++ {
		}
		if i < len(lines) {
			out = append(out, lines[i])
		}
	}
	return strings.Join(out, "\n")
}

var (
	// reading the passphrase's value; setting it (KOMANDO_VAULT_PASS=...) is fine
	procEnviron    = regexp.MustCompile(`/proc/[^/\s'"]+/environ\b`)
	readsVaultPass = regexp.MustCompile(`\$\{?KOMANDO_VAULT_PASS\b|printenv\s+KOMANDO_VAULT_PASS\b`)
	heredocStart   = regexp.MustCompile(`<<-?[ \t]*(['"])([A-Za-z_][A-Za-z0-9_]*)['"]`)
	envAssign      = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*=`)
	remoteSpec     = regexp.MustCompile(`^([A-Za-z0-9_.-]+@)?[A-Za-z0-9_.-]+:`)
)

// checkShell looks at each simple command of a shell line. Arguments of
// komando itself are paths on servers, which komando masks, so they pass.
func checkShell(line, home string) guardDecision {
	line = stripQuotedHeredocs(line)
	if readsVaultPass.MatchString(line) {
		return deny("KOMANDO_VAULT_PASS opens komando's vault; it is for the user only")
	}
	if procEnviron.MatchString(line) { // /proc/PID/environ, not words like "environments"
		return deny("process environments hold secrets; ask the user for the one value you need")
	}
	for _, seg := range splitShell(line) {
		words := shellWords(seg)
		prog, args := program(words)
		switch filepath.Base(prog) {
		case "":
			continue
		case "komando":
			continue
		case "ssh", "scp", "sftp", "mosh", "sshpass":
			return deny("use komando for servers (`komando exec`, `komando fs`, `komando cp`), not %s: komando checks every command, hides secrets and keeps an audit log", filepath.Base(prog))
		case "rsync":
			for _, a := range args {
				if !strings.HasPrefix(a, "-") && !strings.Contains(a, "://") && remoteSpec.MatchString(a) {
					return deny("use `komando sync` or `komando cp` for servers, not rsync")
				}
			}
		case "printenv", "env", "set", "export", "declare", "typeset":
			// only the forms that list every variable: `set -e` is fine
			dump := len(args) == 0
			if p := filepath.Base(prog); (p == "export" || p == "declare" || p == "typeset") && len(args) == 1 && (args[0] == "-p" || args[0] == "-x" || args[0] == "-px") {
				dump = true
			}
			if dump {
				return deny("listing every environment variable shows tokens and passwords; read only the variable you need (`echo \"$NAME\"`)")
			}
		case "security":
			for _, a := range args {
				if a == "-w" || a == "-g" || a == "dump-keychain" || a == "export" {
					return deny("reading passwords from the keychain is for the user only")
				}
			}
		}
		switch filepath.Base(prog) {
		case "echo", "printf", "touch", "mkdir", "ls", "test", "[":
			continue // they name files without reading them
		}
		for _, w := range words {
			if why := secretPath(w, home); why != "" && looksLikePath(w) {
				return deny("%s is %s. komando keeps it away from AI agents; ask the user if you need something from it%s", w, why, viaKomando(why))
			}
		}
	}
	return allow()
}

// program is the command a simple command runs, after VAR=value words and
// wrappers such as sudo, env, time and nohup.
func program(words []string) (string, []string) {
	for i := 0; i < len(words); i++ {
		w := words[i]
		switch {
		case envAssign.MatchString(w):
			continue
		case w == "sudo" || w == "doas" || w == "time" || w == "nohup" || w == "exec" || w == "command" || w == "nice" || w == "xargs":
			continue
		case w == "env" && i+1 < len(words) && (envAssign.MatchString(words[i+1]) || strings.HasPrefix(words[i+1], "-")):
			continue
		case strings.HasPrefix(w, "-") && i > 0:
			continue // a wrapper's flag, e.g. sudo -u app
		}
		return w, words[i+1:]
	}
	return "", nil
}

// looksLikePath: a word that names a file, not a flag or a plain word
// (e.g. `grep password` is fine, `cat .env` is not).
func looksLikePath(w string) bool {
	w = strings.Trim(w, `"'`)
	if strings.ContainsAny(w, " \t") {
		return false // a sentence, e.g. a commit message
	}
	if i := strings.Index(w, "="); i >= 0 && strings.HasPrefix(w, "-") {
		w = w[i+1:]
	}
	return strings.ContainsAny(w, "/~.") || w == "credentials" || strings.HasPrefix(w, "id_")
}

// shellWords splits a simple command into words, removing quotes and
// redirections' operators.
func shellWords(s string) []string {
	var words []string
	var cur strings.Builder
	var q rune
	flush := func() {
		if cur.Len() > 0 {
			words = append(words, cur.String())
			cur.Reset()
		}
	}
	escaped := false
	for _, r := range s {
		switch {
		case escaped: // \x is a plain x, as in the shell: \" opens no quote
			cur.WriteRune(r)
			escaped = false
		case r == '\\' && q != '\'':
			escaped = true
		case q != 0:
			if r == q {
				q = 0
			} else {
				cur.WriteRune(r)
			}
		case r == '\'' || r == '"':
			q = r
		case r == ' ' || r == '\t' || r == '<' || r == '>':
			flush()
		default:
			cur.WriteRune(r)
		}
	}
	flush()
	return words
}

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
			}
			b, err := io.ReadAll(io.LimitReader(os.Stdin, 4<<20))
			if err != nil || json.Unmarshal(b, &call) != nil {
				return nil
			}
			home, err := os.UserHomeDir()
			if err != nil {
				return nil
			}
			d := checkTool(call.Tool, call.Input, home)
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
