package cli

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"runtime/debug"
	"slices"
	"strings"
	"time"

	"github.com/spf13/cobra"
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

// guardHookArgs is the harness named by args when they are a hook line's
// own words (guide guard, with --for H or --for=H), the form
// guardHookLine writes. Such a call runs the guard alone (runGuardHook):
// no command tree, store or vault, which every agent tool call would
// otherwise open. Any other form runs as the command.
func guardHookArgs(args []string) (agent string, ok bool) {
	if len(args) < 2 || args[0] != "guide" || args[1] != "guard" {
		return "", false
	}
	switch rest := args[2:]; {
	case len(rest) == 0:
		return "", true
	case len(rest) == 2 && rest[0] == "--for":
		return rest[1], true
	case len(rest) == 1 && strings.HasPrefix(rest[0], "--for="):
		return strings.TrimPrefix(rest[0], "--for="), true
	}
	return "", false
}

// runGuardHook answers one hook call on cl as guideGuardCmd does, and
// its exit code: a harness refuses the call when the answer cannot be
// written.
func runGuardHook(cl *call, agent string) int {
	if _, err := cl.out.W.Write(guardHook(cl, agent)); err != nil {
		fmt.Fprintf(cl.out.Err, "Error: komando's guard could not write its answer: %v\n", err)
		return 1
	}
	return 0
}

// guardMemory and guardProcs cap one guard process: many agent sessions
// run a guard on every tool call, all at once.
const (
	guardMemory = 64 << 20
	guardProcs  = 2
)

// limitGuardProcess caps this process when it runs only the guard hook.
func limitGuardProcess(args []string) {
	if _, ok := guardHookArgs(args); ok {
		debug.SetMemoryLimit(guardMemory)
		runtime.GOMAXPROCS(guardProcs)
	}
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
		if lb := strings.ToLower(base); (lb == "komando" || lb == "komando.exe") && !komandoFolderOK(c) {
			return komandoNamedWhy
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
// output is checked on its own. Programs that read in one form and write
// in another are in readsOnly.
var readOnlyPrograms = map[string]bool{"cat": true, "less": true, "more": true, "head": true, "tail": true, "grep": true, "cut": true,
	"egrep": true, "fgrep": true, "rg": true, "ls": true, "stat": true, "file": true, "wc": true, "diff": true, "cmp": true,
	"readlink": true, "realpath": true, "which": true, "type": true, "command": true, "test": true, "[": true, "jq": true,
	"echo": true, "printf": true, "md5": true, "md5sum": true, "shasum": true, "sha256sum": true, "cd": true, "pushd": true}

// redirectTarget is what a shell segment writes with >, >>, >|, zsh's >!
// or >&: a file, or after >& an output it copies or closes (redirectFiles).
var redirectTarget = regexp.MustCompile(`[0-9&]?>>?([|&!]?)\s*("[^"]*"|'[^']*'|[^\s;&|<>()]+)`)

// outputNumber is the word after >& that copies or closes an output (2>&1,
// >&2, 2>&-) instead of naming a file.
var outputNumber = regexp.MustCompile(`^([0-9]+-?|-)$`)

// redirectFiles are the files s writes through a redirect.
func redirectFiles(s string) []string {
	var files []string
	for _, m := range redirectTarget.FindAllStringSubmatch(s, -1) {
		if m[1] == "&" && outputNumber.MatchString(m[2]) {
			continue
		}
		files = append(files, strings.Trim(m[2], `"'`))
	}
	return files
}

// redirectWrites are the files a simple command's redirects open for
// writing (>, >>, >|, zsh's >!, N>, <> and >&FILE), as the shell reads
// them: a > in quotes is text, and quotes around the name are removed. For each, glob
// says the shell expands it, as shellWordsGlob does. The shell opens them,
// whatever the program is.
func redirectWrites(seg string) (files []string, globs []bool) {
	var cur strings.Builder
	var q rune
	escaped, target, afterGT, inWord, glob, brace := false, false, false, false, false, false
	flush := func() {
		if target && (cur.Len() > 0 || inWord) {
			files = append(files, cur.String())
			globs = append(globs, glob || brace && strings.Contains(cur.String(), ","))
			target = false
		}
		cur.Reset()
		inWord, glob, brace = false, false, false
	}
	for _, r := range seg {
		gt := afterGT
		afterGT = false
		switch {
		case escaped:
			cur.WriteRune(r)
			escaped = false
		case r == '\\' && q != '\'':
			escaped, inWord = true, true
		case q != 0:
			if r == q {
				q = 0
			} else {
				cur.WriteRune(r)
			}
		case r == '\'' || r == '"':
			q, inWord = r, true
		case r == '>':
			flush()
			target, afterGT = true, true
		case gt && (r == '&' || r == '|' || r == '!'):
			afterGT = true // >&FILE, >|FILE and >!FILE: the file follows
		case r == ' ' || r == '\t' || r == '<':
			flush()
		default:
			glob = glob || strings.ContainsRune("*?[", r)
			brace = brace || r == '{'
			cur.WriteRune(r)
			inWord = true
		}
	}
	flush()
	return files, globs
}

// writingPrograms change the files their arguments name.
var writingPrograms = map[string]bool{"cp": true, "mv": true, "ln": true, "link": true, "install": true, "tee": true,
	"dd": true, "truncate": true, "chmod": true, "chown": true, "chgrp": true, "rm": true, "rmdir": true, "unlink": true,
	"shred": true, "touch": true, "mkdir": true, "mkfifo": true, "rsync": true, "patch": true, "sponge": true, "rename": true,
	"ditto": true, "gzip": true, "gunzip": true, "bzip2": true, "bunzip2": true, "xz": true, "unxz": true, "zstd": true,
	"unzstd": true, "lz4": true, "compress": true, "uncompress": true, "ed": true, "ex": true, "split": true, "csplit": true,
	"zip": true, "plutil": true, "xattr": true, "trash": true}

// writesFiles says whether the program base, run with args, changes the
// files its arguments name: a writing program, sed, sort, uniq or awk in a
// form that writes (readerArgs), or less with a log file.
func writesFiles(base string, args []string) bool {
	if writingPrograms[base] {
		return true
	}
	if base == "less" {
		return slices.ContainsFunc(args, func(a string) bool {
			return strings.HasPrefix(a, "-o") || strings.HasPrefix(a, "-O") || strings.HasPrefix(a, "--log-file") || strings.HasPrefix(a, "--LOG-FILE")
		})
	}
	if _, ok := readerSpecs[base]; ok && base != "go" {
		_, reads := readerArgs(base, args)
		return !reads
	}
	return false
}

// checkWrites refuses a command that writes a file the guard cannot name
// before the line runs, a secret path or a guard file: each file its
// redirects open, whatever the program is, and each argument of a program
// that writes the files its arguments name (writesFiles) or whose name the
// guard cannot read. The program's words are seg's without its redirects.
func checkWrites(cl *call, seg string, vars lineVars, home, cwd string) guardDecision {
	d := checkWritesIn(cl, literalDollars(seg), vars, home, cwd)
	d.Reason = strings.ReplaceAll(d.Reason, literalDollar, "$")
	return d
}

// literalDollar stands for a $ in single quotes, which the shell gives as
// text: a private-use character, which no shell line a person writes holds.
const literalDollar = "\ue001"

// literalDollars is seg with each $ in single quotes written as
// literalDollar, so that expand reads no value there ('{print $1}').
func literalDollars(seg string) string {
	var b strings.Builder
	var q rune
	escaped := false
	for _, r := range seg {
		switch {
		case escaped:
			escaped = false
		case r == '\\' && q != '\'':
			escaped = true
		case q == '\'' && r == '$':
			b.WriteString(literalDollar)
			continue
		case q != 0 && r == q:
			q = 0
		case q == 0 && (r == '\'' || r == '"'):
			q = r
		}
		b.WriteRune(r)
	}
	return b.String()
}

// unmarked is words with each literalDollar a $ again: what the program
// itself is given.
func unmarked(words []string) []string {
	out := make([]string, len(words))
	for i, w := range words {
		out[i] = strings.ReplaceAll(w, literalDollar, "$")
	}
	return out
}

// checkWritesIn is checkWrites for seg with its literal dollars marked.
func checkWritesIn(cl *call, seg string, vars lineVars, home, cwd string) guardDecision {
	files, fglobs := redirectWrites(seg)
	for i, f := range files {
		if d := checkWritten(cl, f, fglobs[i], true, vars, home, cwd); d.Deny {
			return d
		}
	}
	words, globs, bare := shellWordsFlags(dropRedirects(seg))
	prog, args := program(words)
	if prog == "" {
		return allow()
	}
	progs, known := vars.expand(cl, prog, home, cwd)
	_, aliased := vars[aliasVar]
	// a value that is empty or holds a separator runs other words than a
	// program's name: the guard cannot name the program, and the value's
	// words join its arguments
	seps, _ := vars.separators()
	named := known && !aliased && !slices.ContainsFunc(progs, func(p string) bool {
		return p != prog && (p == "" || strings.ContainsAny(p, seps))
	})
	writes := !named
	for _, p := range progs {
		writes = writes || writesFiles(filepath.Base(p), unmarked(args))
	}
	first := len(words) - len(args)
	if !writes {
		if d := checkPartWriters(cl, filepath.Base(prog), words[first:], globs[first:], vars, home, cwd); d.Deny {
			return d
		}
		return checkOutputOptions(cl, filepath.Base(prog), words[first:], globs[first:], vars, home, cwd)
	}
	for _, w := range words[:first-1] {
		if filepath.Base(w) == "xargs" {
			return deny("xargs gives %s names of files to change that komando's guard cannot read before the line runs; name the files on the line", filepath.Base(prog))
		}
	}
	text := scriptWords(filepath.Base(prog), args)
	for j := first; j < len(words); j++ {
		_, known := vars.expand(cl, words[j], home, cwd)
		if !known && text[j-first] {
			continue // code or a file read: a value in it names no written file
		}
		if bare[j] && !known {
			return deny("%s names files this line writes with a value komando's guard cannot read before the line runs, outside quotes, where the shell can make more names of it; name the files on the line", strings.ReplaceAll(words[j], unknownOutput, "$(...)"))
		}
		if d := checkWritten(cl, words[j], globs[j], false, vars, home, cwd); d.Deny {
			return d
		}
	}
	bases, from := []string{anyProgram}, first-1
	if named {
		bases, from = bases[:0], first
		for _, p := range progs {
			bases = append(bases, filepath.Base(p))
		}
	}
	if d := checkTreeChange(cl, bases, words[from:], globs[from:], vars, home, cwd); d.Deny {
		return d
	}
	if b := filepath.Base(prog); copyPrograms[b] {
		return checkCopyInto(cl, b, args, globs[first:], vars, home, cwd)
	}
	return allow()
}

// copyPrograms write in a destination folder names the line does not
// write out (checkCopyInto).
var copyPrograms = map[string]bool{"cp": true, "mv": true, "install": true, "rsync": true, "ln": true, "link": true, "ditto": true}

// outputOptions are the options many programs take for the file they
// write: cc -o FILE, curl --output FILE, go build -o FILE, openssl -out
// FILE, wget --output-document FILE. wget's -O and -P are too.
var outputOptions = map[string]bool{"-o": true, "--output": true, "--output-file": true, "--output-document": true,
	"-out": true, "--out": true, "--log-file": true, "--logfile": true, "--directory-prefix": true}

// checkOutputOptions checks, as checkWritten does, the file an output
// option of a program that is not only a reader names (outputOptions).
// komando's -o is a format, and komando checks the files it writes itself.
func checkOutputOptions(cl *call, base string, args []string, globs []bool, vars lineVars, home, cwd string) guardDecision {
	if readOnlyPrograms[base] || base == "komando" {
		return allow()
	}
	for j := 0; j < len(args); j++ {
		a := args[j]
		file, glob, ok := "", false, false
		if name, val, eq := strings.Cut(a, "="); eq && strings.HasPrefix(a, "--") && outputOptions[name] {
			file, glob, ok = val, globs[j], true
		} else if (outputOptions[a] || base == "wget" && (a == "-O" || a == "-P")) && j+1 < len(args) {
			j++
			file, glob, ok = args[j], globs[j], true
		}
		if !ok {
			continue
		}
		if d := checkWritten(cl, file, glob, true, vars, home, cwd); d.Deny {
			return d
		}
	}
	return allow()
}

// fdNumber is the file descriptor of >&N, or the - of >&-.
var fdNumber = regexp.MustCompile(`^([0-9]+|-)$`)

// unreadName says whether the shell gives the word w, a file name, a value
// the guard does not read: zsh's =NAME (the program NAME in PATH), ~+ and
// ~- (the working folder and the one before), ~N (a folder on the stack),
// and ~NAME other than the user's own (another user's home folder, or a
// zsh named folder: hash -d, or a variable that holds a folder).
func unreadName(cl *call, w string, vars lineVars, home string) bool {
	if len(w) > 1 && w[0] == '=' && strings.ContainsRune("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_.-", rune(w[1])) {
		return true
	}
	name, _, _ := strings.Cut(strings.TrimPrefix(w, "~"), "/")
	if !strings.HasPrefix(w, "~") || name == "" {
		return false
	}
	if name != filepath.Base(home) || !userName.MatchString(name) {
		return true
	}
	_, set := vars[name]
	_, redefined := vars[redefinedVar]
	return set || redefined || cl.getenv(name) != ""
}

// checkWritten refuses w, a word that names a file the command writes: a
// redirect's file, or an argument of a program that writes. Refused are a
// value with a part the guard cannot read (expand) in a shape unknownWhy
// refuses, a relative name after a cd it could not follow (lostDir) read
// the same way, a secret path and a guard file. An argument is read as the
// program reads it too: after = (dd of=FILE, --target-directory=DIR) and
// after a short option's letters (-tDIR).
func checkWritten(cl *call, w string, glob, redirect bool, vars lineVars, home, cwd string) guardDecision {
	shown := strings.ReplaceAll(w, unknownOutput, "$(...)")
	values, known := vars.expand(cl, w, home, cwd)
	if !known {
		shapes, ok := vars.shapes(cl, w, home, cwd)
		if !ok {
			return deny("%s %s", shown, unknownName)
		}
		for _, s := range shapes {
			for _, c := range writtenNames(s, redirect) {
				if why := unknownWhy(cl, c, home); why != "" {
					return deny("%s %s", shown, why)
				}
			}
		}
	}
	for _, v := range values {
		if cwd == lostDir && v != "" && !strings.HasPrefix(v, "-") && !fdNumber.MatchString(v) && !filepath.IsAbs(guardPath(cl, v, home)) &&
			unknownWhy(cl, unknownOutput+"/"+v, home) != "" {
			return deny("%s names a file in the folder a cd on this line moved to, which komando's guard cannot know before the line runs; write to a full path", shown)
		}
		for _, c := range writtenNames(v, redirect) {
			if c == "" {
				continue
			}
			if unreadName(cl, c, vars, home) {
				return deny("%s names the file this line writes with a value komando's guard cannot read before the line runs; write to a file named on the line", shown)
			}
			g := glob || c != w && wordHasGlob(c)
			if !redirect && !g && !looksLikePath(c) {
				continue
			}
			if why := secretWord(cl, c, home, cwd, g); why != "" {
				return deny("%s is %s. komando keeps it away from AI agents; ask the user if you need something from it%s", shown, why, viaKomando(why))
			}
			why := guardSelfWhy(guardPathAt(cl, c, home, cwd))
			if g {
				why = guardGlobWhy(cl, c, home, cwd)
			}
			if why != "" {
				return refuseSelf(shown, why)
			}
		}
	}
	return allow()
}

// writtenNames are the file names a value that names a written file can
// give: the value, and for a program's argument the part after = and each
// part after a short option's letters (-ft/x gives t/x and /x).
func writtenNames(v string, redirect bool) []string {
	names := []string{v}
	if redirect {
		return names
	}
	if i := strings.IndexByte(v, '='); i > 0 {
		names = append(names, v[i+1:])
	}
	if len(v) > 2 && v[0] == '-' && v[1] != '-' {
		for k := 2; k < len(v); k++ {
			names = append(names, v[k:])
			if c := v[k]; !('a' <= c && c <= 'z' || 'A' <= c && c <= 'Z') {
				break
			}
		}
	}
	return names
}

// writesKomandoByName is a shell line whose program changes a file named by
// a command that names komando: rm "$(command -v komando)", chmod 777
// `which komando`. splitShell gives the command its own segment, so this
// reads the whole line.
var writesKomandoByName = regexp.MustCompile("(^|[;&|(\\s])(rm|unlink|mv|cp|ln|chmod|chown|install|truncate|tee|dd|shred|sed|perl)\\s[^;&|\\n]*(\\$\\(|`)[^)`]*\\bkomando\\b")

// checkSelfWrite refuses a shell segment that writes, moves, deletes or
// changes the mode of a guard file (guardSelfWhy): through a redirect, or
// as an argument of a program that is not only a reader.
func checkSelfWrite(cl *call, line, seg, base string, args []string, home, cwd string) guardDecision {
	if d := checkSelfRedirects(cl, seg, home, cwd); d.Deny || readsOnly(base, args) {
		return d
	}
	words, globs := shellWordsGlob(seg)
	off := len(words) - len(args) // args are the last words of seg
	for i, a := range args {
		if strings.HasPrefix(a, "-") {
			continue
		}
		p := guardPathAt(cl, a, home, cwd)
		why := guardSelfWhy(p)
		if off >= 0 && globs[off+i] {
			why = guardGlobWhy(cl, a, home, cwd)
		}
		if why != "" && !(why == komandoNamedWhy && komandoWordHarmless(line, p)) {
			return refuseSelf(a, why)
		}
	}
	return allow()
}

// checkSelfRedirects refuses a shell segment whose redirect writes a guard
// file (guardSelfWhy), whatever the program is: the shell writes it.
func checkSelfRedirects(cl *call, seg, home, cwd string) guardDecision {
	for _, w := range redirectFiles(seg) {
		if why := guardSelfWhy(guardPathAt(cl, w, home, cwd)); why != "" {
			return refuseSelf(w, why)
		}
	}
	return allow()
}

func refuseSelf(w, why string) guardDecision {
	return deny("%s is %s; an AI agent does not change it: %s", w, why, selfWayOut(why))
}

// checkWholeLine refuses what a line does as a whole, before it is split
// into commands: reading the vault passphrase or a process environment, and
// changing the komando program through a command that names it.
func checkWholeLine(line string) guardDecision {
	switch {
	case readsVaultPass.MatchString(line):
		return deny("KOMANDO_VAULT_PASS opens komando's vault; it is for the user only")
	case writesKomandoByName.MatchString(line):
		return deny("the line changes the komando program the guard hook runs; an AI agent does not change it. Ask the user to do it")
	case procEnviron.MatchString(line): // /proc/PID/environ, not words like "environments"
		return deny("process environments hold secrets; ask the user for the one value you need")
	}
	return allow()
}

// komandoNamedWhy is guardSelfWhy's reason for a file named komando.
const komandoNamedWhy = "a program named komando, which a guard hook could run in place of komando"

// selfWayOut is what an AI agent does instead of changing a guard file:
// a program it builds gets another name; anything else is the user's.
func selfWayOut(why string) string {
	if why == komandoNamedWhy {
		return "build it under another name (for example go build -o komando-dev), or ask the user to run it"
	}
	return "ask the user to do it"
}

// komandoFolderOK says whether c, named komando, is a folder an agent may
// name: a real folder, not a link, outside every PATH folder, such as
// cmd/komando in the repo (go build ./cmd/komando). A link, or a folder in
// a PATH folder, can be swapped for a program by the same line before a
// hook that names komando by its bare name finds it.
func komandoFolderOK(c string) bool {
	fi, err := os.Lstat(c)
	if err != nil || !fi.IsDir() {
		return false
	}
	dir := filepath.Dir(c)
	for _, d := range filepath.SplitList(os.Getenv("PATH")) {
		if d == "" {
			d = "."
		}
		if abs, err := filepath.Abs(d); err == nil && samePath(abs, dir) {
			return false
		}
	}
	return true
}

// namesGuardFile is a hook file, an agent's settings folder itself, as a
// line writes it anywhere: after ~, $HOME or a full path, in code or in a
// variable, with / or with \ (PowerShell and cmd on Windows).
var namesGuardFile = regexp.MustCompile(`(?i)\.claude[/\\]settings[^/\\\s'"]*\.json|\.codex[/\\](hooks\.json|config\.toml)|\.gemini[/\\]settings\.json|\.cursor[/\\]hooks\.json|\.(claude|codex|gemini|cursor)[/\\]?(["'\s;&|)]|$)`)

// komandoPathWord is a word of a line that ends in /komando or
// /komando.exe (or \komando on Windows).
var komandoPathWord = regexp.MustCompile(`(?i)([^\s'"=;&|()<>,]*[/\\]komando(\.exe)?)(["'\s;&|)<>,]|$)`)

var komandoWord = regexp.MustCompile(`(?i)\bkomando\b`)

// inlineCode are programs that run code given on their line (-c, -e).
var inlineCode = map[string]bool{"python": true, "python2": true, "python3": true, "node": true, "nodejs": true, "deno": true, "bun": true,
	"ruby": true, "perl": true, "php": true, "lua": true, "osascript": true, "pwsh": true, "powershell": true, "tclsh": true}

// checkGuardFiles refuses a segment of line that changes a guard file:
// named as its argument or redirect (checkSelfWrite), or anywhere on the
// line when its program is not only a reader (checkGuardFileNamed). A
// program that writes in another form (sed, awk, sort, uniq, go) is
// checked against the line too, without the files the readers on it
// read (lineWithoutReadFiles): a path in its script or a flag still counts.
// komando's own commands check the files they write themselves; their
// redirects, which the shell writes, are checked here too.
func checkGuardFiles(cl *call, line, seg, prog string, args []string, home, cwd string) guardDecision {
	base := filepath.Base(prog)
	if base == "komando" {
		return checkSelfRedirects(cl, seg, home, cwd) // the shell writes them
	}
	if d := checkSelfWrite(cl, line, seg, base, args, home, cwd); d.Deny || prog == "" || readOnlyPrograms[base] {
		return d
	}
	line = lineForOthers(line, seg)
	if _, ok := readerArgs(base, args); ok {
		return checkGuardFileNamed(cl, lineWithoutReadFiles(line), base, args, home, cwd)
	}
	return checkGuardFileNamed(cl, line, base, args, home, cwd)
}

// checkGuardFileNamed refuses a command that is not only a reader when its
// line names a guard file anywhere, not only as its own argument: in code
// given to an interpreter (python3 -c "open('~/.claude/settings.json','w')"),
// or in a variable a later command uses (f=~/.claude/settings.json; rm "$f").
// Code given to an interpreter may not name komando at all: it can find the
// program by name (shutil.which).
func checkGuardFileNamed(cl *call, line, base string, args []string, home, cwd string) guardDecision {
	refuse := func(what, why string) guardDecision {
		return deny("the line names %s and runs %s, which can change it; an AI agent does not change komando's guard: %s", what, base, selfWayOut(why))
	}
	if m := namesGuardFile.FindString(line); m != "" {
		return refuse(strings.TrimRight(m, "\"' ;&|)"), "")
	}
	for _, m := range komandoPathWord.FindAllStringSubmatch(line, -1) {
		w := m[1]
		if runtime.GOOS == "windows" { // \ is a separator there, not an escape
			w = strings.ReplaceAll(w, `\`, "/")
		}
		p := guardPathAt(cl, w, home, cwd)
		if why := guardSelfWhy(p); why != "" && !(why == komandoNamedWhy && komandoWordHarmless(line, p)) {
			return refuse(m[1], why)
		}
	}
	if b := strings.TrimSuffix(strings.ToLower(base), ".exe"); inlineCode[b] || strings.HasPrefix(b, "python3.") {
		for _, a := range args {
			if (a == "-c" || a == "-e" || a == "-E" || a == "--eval" || a == "-Command" || a == "-command") && komandoWord.MatchString(line) {
				return refuse("komando", komandoNamedWhy)
			}
		}
	}
	return allow()
}
