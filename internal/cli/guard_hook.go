package cli

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"maps"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/sgnd/komando/internal/store"
)

// guideGuardCmd is the hook an agent harness runs before each tool call. It
// reads the call as JSON on stdin and answers in the harness's hook format.
// Anything it cannot read is let through: the guard must never stop work it
// does not understand. A call over guardInputMax, which it cannot read
// whole, is refused, and so is a check that does not finish in guardBudget
// or that crashes.
func guideGuardCmd() *cobra.Command {
	var agent string
	c := &cobra.Command{
		Use:    "guard",
		Short:  "Stop AI agent tool calls that would read secrets on this computer",
		Hidden: true,
		Args:   cobra.NoArgs,
		RunE: inCall(func(cl *call, cmd *cobra.Command, _ []string) error {
			_, err := cl.out.W.Write(guardHook(cl, agent))
			return err
		}),
	}
	c.Flags().StringVar(&agent, "for", "", "the harness: claude (default), cursor, gemini or codex")
	return c
}

// guardBudget is how long the guard may take for one call: under every
// harness's own hook time limit (Gemini's is 5s), so the guard answers.
var guardBudget = 3 * time.Second

// guardHook is the guard's answer to the hook input on stdin, in agent's
// format; nil lets the call through.
func guardHook(cl *call, agent string) []byte {
	if agent == "" {
		agent = "claude"
	}
	decide, budget := guardDecide, guardBudget
	done := make(chan guardDecision, 1)
	go func() {
		defer func() {
			if recover() != nil {
				done <- deny("the check stopped with an internal error, so the call is refused")
			}
		}()
		done <- decide(cl, agent)
	}()
	timer := time.NewTimer(budget)
	defer timer.Stop()
	select {
	case d := <-done:
		return guardAnswer(agent, d)
	case <-timer.C:
		return guardAnswer(agent, deny("the check did not finish in %v, so the call is refused; try it again", budget))
	}
}

// guardDecide reads one hook input and decides it for every home komando
// guards: the first denial wins.
var guardDecide = func(cl *call, agent string) guardDecision {
	b, err := io.ReadAll(io.LimitReader(cl.stdin, guardInputMax+1))
	if len(b) > guardInputMax {
		return deny("the tool call is too large for komando's guard to check (over 4 MiB)")
	}
	if err != nil {
		return allow()
	}
	var in struct {
		Tool  string         `json:"tool_name"`
		Input map[string]any `json:"tool_input"`
		Cwd   string         `json:"cwd"`
	}
	if agent == "claude" && json.Unmarshal(b, &in) != nil {
		return allow()
	}
	d := allow()
	for _, home := range guardHomes() {
		if d.Deny {
			break
		}
		if agent == "claude" {
			d = checkTool(cl, in.Tool, in.Input, home, hookCwd(in.Cwd))
		} else {
			d = guardAgent(cl, agent, b, home)
		}
	}
	return d
}

// guardInputMax is the most of one hook input the guard reads; a larger
// call is refused, as one the guard cannot check whole.
const guardInputMax = 4 << 20

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

// guardHookLine is the hook command for harness h (claude, cursor, gemini,
// codex). sh runs komando's guard on the call (stdin passes through) and
// prints its answer only when the guard ran to the end; on any failure it
// prints h's own deny instead, so the harness refuses the call rather than
// going on without the guard.
func guardHookLine(prog, h string) string {
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
	case !wrapped:
		return "it uses the old hook line, which lets a call through when komando is missing"
	}
	return ""
}

// guardProgramProblem says why the program a hook names cannot run, or "".
func guardProgramProblem(prog string) string {
	if !strings.Contains(prog, "/") {
		if _, err := exec.LookPath(prog); err != nil {
			return "its command " + prog + " is not in PATH"
		}
		return ""
	}
	fi, err := os.Stat(prog)
	switch {
	case err != nil:
		return "its command " + prog + " does not exist"
	case fi.IsDir() || fi.Mode()&0o111 == 0:
		return "its command " + prog + " is not a program"
	case fi.Mode()&0o002 != 0:
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

// hookSettingFiles are, per AI agent folder, the files that hold its hooks
// or can switch them off.
var hookSettingFiles = map[string][]string{
	".claude": {"settings.json", "settings.local.json"},
	".codex":  {"hooks.json", "config.toml"},
	".gemini": {"settings.json"},
	".cursor": {"hooks.json"},
}

// guardSelfWhy says why an AI agent may not write, move or delete p, or "":
// an agent's folder, a file that holds its hooks, or the komando program
// the guard hook runs. Links are followed; names are folded where the
// file system folds them.
func guardSelfWhy(p string) string {
	if p == "" {
		return ""
	}
	for _, c := range withReal([]string{filepath.Clean(p)}, realPath(p)) {
		name := c
		if caseFoldFS {
			name = foldCase(c)
		}
		base, parent := filepath.Base(name), filepath.Base(filepath.Dir(name))
		if _, ok := hookSettingFiles[base]; ok {
			return "an AI agent's settings folder, which holds komando's guard hook"
		}
		if slices.Contains(hookSettingFiles[parent], base) {
			return "an AI agent's hook settings, which run komando's guard"
		}
		for _, prog := range guardPrograms() {
			if samePath(c, prog) {
				return "the komando program the guard hook runs"
			}
		}
	}
	return ""
}

// guardPrograms are the komando programs a guard hook runs: this one and
// the komando in PATH, each as named and as its link leads.
func guardPrograms() []string {
	var l []string
	if self, err := os.Executable(); err == nil {
		l = withReal(l, self)
	}
	if p, err := exec.LookPath("komando"); err == nil {
		if abs, err := filepath.Abs(p); err == nil {
			l = withReal(l, abs)
		}
	}
	return l
}

// samePath says whether a and b name one file: by identity when both
// exist, else by their cleaned path.
func samePath(a, b string) bool {
	if fa, fb := statOf(a), statOf(b); fa != nil && fb != nil {
		return os.SameFile(fa, fb)
	}
	return filepath.Clean(a) == filepath.Clean(b)
}

// readOnlyPrograms only look at the paths they name; a redirect of their
// output is checked on its own.
var readOnlyPrograms = map[string]bool{"cat": true, "less": true, "more": true, "head": true, "tail": true, "grep": true,
	"egrep": true, "fgrep": true, "rg": true, "ls": true, "stat": true, "file": true, "wc": true, "diff": true, "cmp": true,
	"readlink": true, "realpath": true, "which": true, "type": true, "command": true, "test": true, "[": true, "jq": true,
	"echo": true, "printf": true, "md5": true, "md5sum": true, "shasum": true, "sha256sum": true, "cd": true, "pushd": true}

// redirectTarget is a file a shell segment writes with > or >>.
var redirectTarget = regexp.MustCompile(`[0-9&]?>>?\|?\s*("[^"]*"|'[^']*'|[^\s;&|<>()]+)`)

// checkSelfWrite refuses a shell segment that writes, moves, deletes or
// changes the mode of a guard file (guardSelfWhy): through a redirect, or
// as an argument of a program that is not only a reader. A program named
// by a command inside it ($(command -v komando)) counts as komando.
func checkSelfWrite(cl *call, seg, base string, args []string, home, cwd string) guardDecision {
	refuse := func(w, why string) guardDecision {
		return deny("%s is %s; an AI agent does not change it. Ask the user to do it", w, why)
	}
	for _, m := range redirectTarget.FindAllStringSubmatch(seg, -1) {
		w := strings.Trim(m[1], `"'`)
		if why := guardSelfWhy(guardPathAt(cl, w, home, cwd)); why != "" {
			return refuse(w, why)
		}
	}
	if readOnlyPrograms[base] {
		return allow()
	}
	for _, a := range args {
		if strings.HasPrefix(a, "-") {
			continue
		}
		if (strings.Contains(a, "$(") || strings.Contains(a, "`")) && strings.Contains(a, "komando") {
			return refuse(a, "the komando program the guard hook runs")
		}
		if why := guardSelfWhy(guardPathAt(cl, a, home, cwd)); why != "" {
			return refuse(a, why)
		}
	}
	return allow()
}
