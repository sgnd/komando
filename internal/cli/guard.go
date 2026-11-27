package cli

import (
	"fmt"
	"os/user"
	"path"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"strings"

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
// Glob, Bash). cwd is the agent's working folder, from the hook input, or
// "" when it is not known: relative paths are read from it.
func checkTool(cl *call, tool string, in map[string]any, home, cwd string) guardDecision {
	str := func(k string) string { s, _ := in[k].(string); return s }
	switch tool {
	case "Read", "Edit", "Write", "MultiEdit", "NotebookEdit":
		p := str("file_path")
		if p == "" {
			p = str("notebook_path")
		}
		if why := secretWord(cl, p, home, cwd, false); why != "" {
			return deny("%s is %s. komando keeps it away from AI agents; ask the user if you need something from it%s", p, why, viaKomando(why))
		}
		if why := guardSelfWhy(guardPathAt(cl, p, home, cwd)); tool != "Read" && why != "" {
			return deny("%s is %s; an AI agent does not change it: %s", p, why, selfWayOut(why))
		}
	case "Grep", "Glob":
		if why := secretWord(cl, str("path"), home, cwd, false); why != "" {
			return deny("%s is %s; ask the user if you need something from it", str("path"), why)
		}
		if g := str("glob"); g != "" && sensitiveName(g) {
			return deny("%s matches files that hold secrets; leave them out of the search", g)
		}
		if tool != "Grep" {
			break // Glob lists names; Grep reads the files
		}
		dir := str("path")
		if dir == "" {
			dir = cwd // Grep searches the working folder by default
		}
		if dir == "" {
			break
		}
		if p := guardPathAt(cl, dir, home, cwd); holdsProtected(cl, p, home) {
			return deny("%s holds komando's data and private keys, and a search of it reads them; search a project folder instead", dir)
		}
		if g := str("glob"); g != "" && !filepath.IsAbs(g) {
			// Grep reads what the glob picks: path/.komando/* reads komando's data
			if why := secretWord(cl, filepath.Join(dir, g), home, cwd, true); why != "" {
				return deny("%s in %s matches %s; leave it out of the search", g, dir, why)
			}
		}
	case "Bash":
		return checkShell(cl, str("command"), home, cwd)
	}
	return allow()
}

func viaKomando(why string) string {
	if why == komandoData {
		return ". Use komando commands instead: `komando list`, `komando secret list`, `komando audit`"
	}
	return ""
}

// secretPath says why a path on this computer is off limits, or "".
func secretPath(cl *call, p, home string) string {
	if p == "" {
		return ""
	}
	p = underHome(guardPath(cl, p, home), home)
	if isProcEnviron(p) {
		return procEnv
	}
	komandoDirs := []string{filepath.Join(home, ".komando"), store.Home()}
	if h := cl.getenv("KOMANDO_HOME"); h != "" {
		komandoDirs = append(komandoDirs, h)
	}
	for _, d := range komandoDirs {
		if r := realPath(d); r != d {
			komandoDirs = append(komandoDirs, r) // a path seen through its links matches too
		}
	}
	if caseFoldFS {
		// ~/.KOMANDO/state.json is the same file on these systems
		p, home = foldCase(p), foldCase(home)
		for i, d := range komandoDirs {
			komandoDirs[i] = foldCase(d)
		}
	}
	in := func(dir string) bool {
		if caseFoldFS {
			dir = foldCase(dir)
		}
		return pathIn(p, dir)
	}
	for _, d := range komandoDirs {
		if in(d) {
			if strings.HasSuffix(p, ".pub") {
				return "" // a public key is meant to be shared
			}
			return komandoData
		}
	}
	for _, d := range credentialStores {
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

// caseFoldFS: the file systems macOS and Windows use by default do not
// tell ~/.komando from ~/.KOMANDO.
var caseFoldFS = runtime.GOOS == "darwin" || runtime.GOOS == "windows"

// pathIn reports whether p is dir or a path in it.
func pathIn(p, dir string) bool {
	rel, err := filepath.Rel(dir, p)
	return err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}

// isProcEnviron: /proc/PID/environ, also /proc/self/task/1/environ, holds
// the variables of a process, komando's vault passphrase among them.
func isProcEnviron(p string) bool {
	// with / on Windows too, where Cygwin and MSYS shells have /proc; a path
	// made absolute there gains a drive (C:\proc\self\environ), which is
	// left out so the check still sees /proc
	p = path.Clean(filepath.ToSlash(strings.TrimPrefix(p, filepath.VolumeName(p))))
	return strings.HasPrefix(p, "/proc/") && path.Base(p) == "environ"
}

// holdsProtected reports whether the folder p holds one of the folders
// secretPath guards (p is the home folder, /Users or /): a recursive read
// of p reads them too.
func holdsProtected(cl *call, p, home string) bool {
	if !filepath.IsAbs(p) {
		return false
	}
	for _, q := range []string{filepath.Clean(p), realPath(p)} {
		for _, d := range protectedDirs(cl, home) {
			if caseFoldFS {
				q, d = foldCase(q), foldCase(d)
			}
			if q != d && pathIn(d, q) {
				return true
			}
		}
	}
	return false
}

// secretWord is secretPath for a word as the agent wrote it: a relative path
// is read from cwd, and links and hard links are followed. glob says the
// shell expands the word (it has unquoted *, ?, [ or {): it is then off
// limits when it could match a protected path (`~/.komand?/vault.ke?`),
// whether or not the file is there yet.
func secretWord(cl *call, w, home, cwd string, glob bool) string {
	if w == "" {
		return ""
	}
	if glob {
		return secretGlob(cl, w, home, cwd)
	}
	p := guardPathAt(cl, w, home, cwd)
	if why := secretPath(cl, p, home); why != "" {
		return why
	}
	if real := realPath(p); real != p {
		if why := secretPath(cl, real, home); why != "" {
			return why
		}
	}
	if filepath.IsAbs(p) {
		return hardLinkSecret(cl, p, home)
	}
	return ""
}

// realPath is p with its links followed, as far as the path exists, so
// link/state.json counts when link leads to komando's folder.
func realPath(p string) string {
	if !filepath.IsAbs(p) {
		return p
	}
	rest := ""
	for dir := p; ; dir = filepath.Dir(dir) {
		if real, err := filepath.EvalSymlinks(dir); err == nil {
			return filepath.Join(real, rest)
		}
		if dir == filepath.Dir(dir) {
			return p
		}
		rest = filepath.Join(filepath.Base(dir), rest)
	}
}

// guardPathAt is guardPath, with a relative path joined to cwd when cwd is
// known (not "" or lostDir).
func guardPathAt(cl *call, w, home, cwd string) string {
	p := guardPath(cl, w, home)
	if !filepath.IsAbs(p) {
		if cwd == "" || cwd == lostDir {
			return filepath.Clean(p)
		}
		p = lexOrKernel(cwd + string(filepath.Separator) + p)
	}
	return p
}

func wordHasGlob(w string) bool { return strings.ContainsAny(w, "*?[{") }

// secretGlob: a glob is off limits when a file it matches here is, or when
// it could name a protected folder or something in it: `~/.komand?`,
// `~/.ss?/id_*` and `.komando/keys/*` (from the home folder) all count.
func secretGlob(cl *call, w, home, cwd string) string {
	for _, pat := range expandBraces(w, 0) {
		p := guardPathAt(cl, pat, home, cwd)
		if last := filepath.Base(p); strings.HasPrefix(last, ".") {
			for _, n := range []string{".env", ".env.local", ".env.production", ".pgpass", ".my.cnf", ".netrc", ".git-credentials", ".htpasswd", ".npmrc", ".pypirc"} {
				if ok, _ := filepath.Match(last, n); ok {
					return "a file that holds secrets"
				}
			}
		}
		if !filepath.IsAbs(p) {
			continue // relative, and the folder is not known
		}
		if m, err := filepath.Glob(p); err == nil {
			last := filepath.Base(p)
			for i, f := range m {
				if i == 500 {
					break
				}
				if strings.HasPrefix(filepath.Base(f), ".") && !strings.HasPrefix(last, ".") {
					continue // the shell's * does not match a dot file
				}
				if isCredentialStore(f, home) && filepath.Base(p) == "*" {
					continue // `du -sh ~/*/*` names ~/Library/Keychains, it does not read it
				}
				if why := secretPath(cl, realPath(f), home); why != "" {
					return why
				}
			}
		}
		for _, d := range protectedDirs(cl, home) {
			for _, q := range []string{p, realPath(p)} {
				if c, ok := globUnder(q, d, home); ok {
					if why := secretPath(cl, c, home); why != "" {
						return why
					}
				}
			}
		}
	}
	return ""
}

// credentialStores are the folders under home that other programs keep
// their credentials in.
var credentialStores = []string{".gnupg", ".password-store", ".aws", ".config/gcloud", ".azure", ".kube", "Library/Keychains"}

func isCredentialStore(p, home string) bool {
	for _, d := range credentialStores {
		if d := filepath.Join(home, d); p == d || caseFoldFS && foldCase(p) == foldCase(d) {
			return true
		}
	}
	return false
}

// protectedDirs are the folders secretPath guards as a whole.
func protectedDirs(cl *call, home string) []string {
	dirs := []string{filepath.Join(home, ".komando"), filepath.Join(home, ".ssh"), filepath.Join(home, ".docker")}
	if h := cl.getenv("KOMANDO_HOME"); h != "" {
		dirs = append(dirs, filepath.Clean(h))
	}
	for _, d := range credentialStores {
		dirs = append(dirs, filepath.Join(home, d))
	}
	return dirs
}

// globUnder reports whether the glob p can match the folder dir or a path
// in it, and gives that path with the rest of the glob after dir, e.g.
// ~/.komand?/keys/* gives ~/.komando/keys/*. Like the shell, * and ? do
// not match a leading dot. A glob that ends in a bare * at a credential
// store names the folder among others (`du -sh ~/*/*`); it does not count.
func globUnder(p, dir, home string) (string, bool) {
	if caseFoldFS {
		p, dir, home = foldCase(p), foldCase(dir), foldCase(home)
	}
	// by / on every system: a Windows path has \ between its parts
	pc := strings.Split(strings.Trim(filepath.ToSlash(p), "/"), "/")
	dc := strings.Split(strings.Trim(filepath.ToSlash(dir), "/"), "/")
	if len(pc) < len(dc) {
		return "", false
	}
	if len(pc) == len(dc) && pc[len(pc)-1] == "*" && isCredentialStore(dir, home) {
		return "", false
	}
	for i, d := range dc {
		if strings.HasPrefix(d, ".") && !strings.HasPrefix(pc[i], ".") && pc[i] != d {
			return "", false
		}
		if ok, err := filepath.Match(pc[i], d); err != nil || !ok {
			return "", false
		}
	}
	return filepath.Join(append([]string{dir}, pc[len(dc):]...)...), true
}

// expandBraces turns a{b,c}d into abd and acd, as the shell does.
func expandBraces(w string, depth int) []string {
	open := strings.IndexByte(w, '{')
	if open < 0 || depth > 4 {
		return []string{w}
	}
	level, end := 0, -1
	var cuts []int
	for i := open; i < len(w) && end < 0; i++ {
		switch w[i] {
		case '{':
			level++
		case '}':
			if level--; level == 0 {
				end = i
			}
		case ',':
			if level == 1 {
				cuts = append(cuts, i)
			}
		}
	}
	if end < 0 || len(cuts) == 0 {
		return []string{w}
	}
	var alts []string
	start := open + 1
	for _, c := range append(cuts, end) {
		alts = append(alts, w[start:c])
		start = c + 1
	}
	var all []string
	for _, a := range alts {
		for _, x := range expandBraces(w[:open]+a+w[end+1:], depth+1) {
			if len(all) < 64 {
				all = append(all, x)
			}
		}
	}
	return all
}

func guardPath(cl *call, p, home string) string {
	p = strings.Trim(p, `"'`)
	kh := cl.getenv("KOMANDO_HOME")
	if kh == "" {
		kh = filepath.Join(home, ".komando")
	}
	for _, v := range []struct{ name, dir string }{{"HOME", home}, {"KOMANDO_HOME", kh}} {
		for _, pre := range []string{"$" + v.name, "${" + v.name + "}"} {
			if p == pre {
				return v.dir
			}
			if strings.HasPrefix(p, pre+"/") {
				return lexOrKernel(v.dir + string(filepath.Separator) + p[len(pre)+1:])
			}
		}
	}
	if p == "~" {
		return home
	}
	if strings.HasPrefix(p, "~/") {
		return lexOrKernel(home + string(filepath.Separator) + p[2:])
	}
	if name, rest, _ := strings.Cut(p[min(len(p), 1):], "/"); strings.HasPrefix(p, "~") && userName.MatchString(name) {
		return lexOrKernel(userHome(name, home) + string(filepath.Separator) + rest) // ~me/.komando
	}
	if !filepath.IsAbs(p) {
		return p // guardPathAt puts the working folder in front, then reads it
	}
	return lexOrKernel(p)
}

var userName = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9._-]*$`)

// userHome is the home folder of the user name, as ~name names it.
func userHome(name, home string) string {
	if name == filepath.Base(home) {
		return home
	}
	if u, err := user.Lookup(name); err == nil && u.HomeDir != "" {
		return u.HomeDir
	}
	return filepath.Join(filepath.Dir(home), name)
}

// A glob names the files it matches when the line runs. A glob that names a
// file a command writes is checked against the guard files two ways: the
// files it matches now, and the agent folders and hook files it could match
// by name. The shell's * and ? do not match a leading dot; a line that
// changes how globs match, or uses a glob form the guard does not read, is
// refused (checkGlobForms).

// guardGlobWhy is guardSelfWhy for the glob w, read from cwd: why a file
// it matches now, or a guard file it could match by name, may not be
// changed by an AI agent, or "".
func guardGlobWhy(cl *call, w, home, cwd string) string {
	for _, pat := range expandBraces(w, 0) {
		p := guardPathAt(cl, pat, home, cwd)
		if why := guardSelfWhy(p); why != "" {
			return why // a brace list leaves plain names
		}
		if filepath.IsAbs(p) {
			if m, err := filepath.Glob(p); err == nil {
				for i, f := range m {
					if i == 500 {
						break
					}
					if !shellGlobMatches(p, f) {
						continue
					}
					if why := guardSelfWhy(f); why != "" {
						return why
					}
				}
			}
		}
		if why := guardNameGlob(p); why != "" {
			return why
		}
	}
	return ""
}

// shellGlobMatches says whether the shell's glob p matches the path f that
// filepath.Glob gave: not where a part of f starts with a dot that the same
// part of p does not start with.
func shellGlobMatches(p, f string) bool {
	pc := strings.Split(filepath.ToSlash(p), "/")
	fc := strings.Split(filepath.ToSlash(f), "/")
	if len(pc) != len(fc) {
		return true
	}
	for i := range pc {
		if strings.HasPrefix(fc[i], ".") && !strings.HasPrefix(pc[i], ".") {
			return false
		}
	}
	return true
}

// checkTreeChange refuses rm -r, mv and chmod, chown or chgrp -R of a
// folder that is or holds a protected path or a guard file, the rule
// find -delete follows (touchesProtected): the change reaches everything
// under the folder. A glob counts as the names it matches now.
func checkTreeChange(cl *call, base string, args []string, globs []bool, vars lineVars, home, cwd string) guardDecision {
	verb := "changes"
	switch base {
	case "rm":
		verb = "removes"
	case "mv", "trash":
		verb = "moves"
	case anyProgram:
		verb = "may remove or move"
	}
	for _, line := range treeLines(cl, args, globs, vars, home, cwd) {
		words := make([]string, len(line))
		for i, w := range line {
			words[i] = w.w
		}
		for _, i := range treeOperands(base, words) {
			if words[i] == "" {
				continue // an empty value names no folder: the word goes, or rm "" fails
			}
			for _, p := range treeTargets(cl, words[i], line[i].glob, home, cwd) {
				if filepath.IsAbs(p) && touchesProtected(cl, p, home) {
					return deny("%s %s %s and everything under it, which is or holds komando's data, private keys or guard files; name the files inside instead", base, verb, p)
				}
			}
		}
	}
	return allow()
}

// anyProgram stands for a program the guard cannot name before the line
// runs (a value, command output, an alias): it may remove or move any of
// its operands.
const anyProgram = "a program komando's guard cannot name"

// treeOperands are the indexes of the arguments base removes, moves or
// changes with everything under them: rm -r's operands, mv's sources,
// trash's operands (macOS moves them to the Trash), every operand of
// anyProgram, and the operands of chmod, chown or chgrp -R (the mode or
// owner among them names nothing that matters).
func treeOperands(base string, args []string) []int {
	var ops []int
	recursive, target, opts := false, false, true
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case !opts || a == "-" || !strings.HasPrefix(a, "-"):
			ops = append(ops, i)
		case a == "--":
			opts = false
		case strings.HasPrefix(a, "--"):
			name, _, valued := strings.Cut(a, "=")
			recursive = recursive || longOption(name, "--recursive")
			if base == "mv" && longOption(name, "--target-directory") {
				target = true
				if !valued {
					i++
				}
			}
		default:
			letters := a[1:]
			recursive = recursive || strings.Contains(letters, "R") || base == "rm" && strings.Contains(letters, "r")
			if k := strings.IndexAny(letters, "tS"); base == "mv" && k >= 0 {
				target = target || letters[k] == 't'
				if k == len(letters)-1 {
					i++ // the folder or the suffix is the next word
				}
			}
		}
	}
	switch {
	case recursive && (base == "rm" || base == "chmod" || base == "chown" || base == "chgrp"), base == "mv" && target, base == "trash", base == anyProgram:
		return ops
	case base == "mv" && len(ops) > 1:
		return ops[:len(ops)-1]
	}
	return nil
}

// longOption says whether name is the long option opt or a short form of
// it GNU tools accept (--rec for --recursive, --t for --target-directory).
func longOption(name, opt string) bool {
	return len(name) > 2 && strings.HasPrefix(opt, name)
}

// guardNameGlob says why a name the glob p could match is a guard file by
// its name alone (guardSelfWhy): an AI agent's settings folder, its hook
// file, or a program named komando. For komando the glob must hold a
// plain letter: a bare * matches every name, and the files it matches now
// are checked one by one.
func guardNameGlob(p string) string {
	parts := strings.Split(strings.TrimRight(filepath.ToSlash(p), "/"), "/")
	base, parent := parts[len(parts)-1], ""
	if len(parts) > 1 {
		parent = parts[len(parts)-2]
	}
	for dir, files := range hookSettingFiles {
		if globName(base, dir) {
			return "an AI agent's settings folder, which holds komando's guard hook"
		}
		if globName(parent, dir) {
			for _, f := range files {
				if globName(base, f) {
					return "an AI agent's hook settings, which run komando's guard"
				}
			}
		}
	}
	plain := strings.ContainsFunc(base, func(r rune) bool { return 'a' <= r && r <= 'z' || 'A' <= r && r <= 'Z' })
	if plain && (globName(base, "komando") || runtime.GOOS == "windows" && globName(base, "komando.exe")) {
		return komandoNamedWhy
	}
	return ""
}

// globName says whether the glob part pat matches name as the shell does:
// * and ? not a leading dot, and names folded where the file system folds
// them.
func globName(pat, name string) bool {
	if pat == "" || strings.HasPrefix(name, ".") && !strings.HasPrefix(pat, ".") {
		return false
	}
	if caseFoldFS {
		pat, name = foldCase(pat), foldCase(name)
	}
	ok, err := filepath.Match(pat, name)
	return err == nil && ok
}

// globOptions are shell options that change what a glob matches: hidden
// files too (dotglob, GLOB_DOTS, GLOBIGNORE), names in any case
// (nocaseglob, CASE_GLOB), more pattern forms (extglob, EXTENDED_GLOB,
// KSH_GLOB, globstar) or a glob in a variable's value (GLOB_SUBST).
var globOptions = regexp.MustCompile(`(?i)dot_?glob|glob_?dots|globignore|ext_?glob|extended_?glob|ksh_?glob|sh_?glob|glob_?subst|glob_?star|bare_?glob_?qual|case_?glob`)

// checkGlobForms refuses a line whose globs the guard cannot read: a glob
// qualifier or group (globGroup), or a glob on a line that changes how
// globs match (globOptions).
func checkGlobForms(line string) guardDecision {
	if globGroup(dropHeredocs(line, true)) {
		return deny("the line has a glob qualifier or a ( ) group in a word, which komando's guard does not read (zsh's *(D) also matches hidden files, *(e:...:) runs code); name the files plainly")
	}
	if globOptions.MatchString(line) {
		for _, seg := range splitShell(line) {
			if _, globs := shellWordsGlob(seg); slices.Contains(globs, true) {
				return deny("the line changes how globs match and uses a glob, which komando's guard cannot follow; name the files plainly")
			}
		}
	}
	for _, seg := range splitShell(dropHeredocs(line, true)) {
		words, globs := shellWordsGlob(seg)
		for i, w := range words {
			if globs[i] && bracketDiffers(w) {
				return deny("%s has a [ ] list that komando's guard does not read the way the shell does ([!x], [[:alpha:]], [a-]); name the files plainly", w)
			}
		}
	}
	return allow()
}

// bracketDiffers says whether the glob word w holds a [ ] list the shell
// and filepath.Match read differently: [!x] (to Go, ! is a letter), a class,
// collating symbol or equivalence ([[:alpha:]], [[.a.]], [[=a=]]), or a - or
// ] where Go wants a letter ([a-], [-a], []a]). Without its closing ] the
// shell reads [ as a letter.
func bracketDiffers(w string) bool {
	for rest := w; ; {
		i := strings.IndexByte(rest, '[')
		if i < 0 {
			return false
		}
		rest = rest[i+1:]
		start := 0
		if strings.HasPrefix(rest, "!") || strings.HasPrefix(rest, "^") {
			start = 1
		}
		end := strings.IndexByte(rest[min(start+1, len(rest)):], ']')
		if end < 0 {
			continue
		}
		list := rest[start : end+min(start+1, len(rest))]
		if strings.HasPrefix(rest, "!") || strings.Contains(list, "[:") || strings.Contains(list, "[.") || strings.Contains(list, "[=") || goRangeRejects(list) {
			return true
		}
	}
}

// goRangeRejects says whether filepath.Match rejects the [ ] list list: a
// range may not start or end with - or ], which the shell takes as letters.
func goRangeRejects(list string) bool {
	for k := 0; k < len(list); k++ {
		if list[k] == '-' || list[k] == ']' {
			return true
		}
		if k+1 < len(list) && list[k+1] == '-' {
			k += 2
			if k >= len(list) || list[k] == '-' || list[k] == ']' {
				return true
			}
		}
	}
	return false
}

// globGroup says whether line has an unquoted ( inside a word: a zsh glob
// qualifier or group (*(D), *(e:...:), a(b|c)) or an extended glob of bash
// (@(...), !(...)). A ( after $, <, > or = starts a command or an array,
// NAME() defines a function, and (( )) and $(( )) count.
func globGroup(line string) bool {
	var q byte
	word := false
	for i := 0; i < len(line); i++ {
		c := line[i]
		switch {
		case q == '\'':
			if c == '\'' {
				q = 0
			}
		case c == '\\':
			i++
			word = true
		case c == '$' && strings.HasPrefix(line[i:], "$(("), !word && strings.HasPrefix(line[i:], "(("):
			i = arithEnd(line, i) // arithmetic: no globs
			word = q == '"'
		case c == '`' || c == '$' && i+1 < len(line) && line[i+1] == '(':
			end, bodyEnd := outputEnd(line, i)
			from := i + 2
			if c == '`' {
				from = i + 1
			}
			if globGroup(line[min(from, bodyEnd):bodyEnd]) {
				return true
			}
			i, word = end-1, true
		case q == '"':
			if c == '"' {
				q = 0
			}
		case c == '\'' || c == '"':
			q, word = c, true
		case c == '(':
			if word && !strings.ContainsRune("$<>=(", rune(line[i-1])) && (i+1 >= len(line) || line[i+1] != ')') {
				return true
			}
			word = false
		case strings.ContainsRune(" \t\n;&|)<>", rune(c)):
			word = false
		default:
			word = true
		}
	}
	return false
}

// arithEnd is the index of the last ) of the (( )) or $(( )) that starts
// at line[i], or the line's last index.
func arithEnd(line string, i int) int {
	depth := 0
	for j := i; j < len(line); j++ {
		switch line[j] {
		case '(':
			depth++
		case ')':
			if depth--; depth == 0 {
				return j
			}
		}
	}
	return len(line) - 1
}
