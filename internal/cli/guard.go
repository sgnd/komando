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
	"os/user"
	"path/filepath"
	"regexp"
	"runtime"
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
// Glob, Bash). cwd is the agent's working folder, from the hook input, or
// "" when it is not known: relative paths are read from it.
func checkTool(tool string, in map[string]any, home, cwd string) guardDecision {
	str := func(k string) string { s, _ := in[k].(string); return s }
	switch tool {
	case "Read", "Edit", "Write", "MultiEdit", "NotebookEdit":
		p := str("file_path")
		if p == "" {
			p = str("notebook_path")
		}
		if why := secretWord(p, home, cwd, false); why != "" {
			return deny("%s is %s. komando keeps it away from AI agents; ask the user if you need something from it%s", p, why, viaKomando(why))
		}
	case "Grep", "Glob":
		if why := secretWord(str("path"), home, cwd, false); why != "" {
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
		if p := guardPathAt(dir, home, cwd); holdsProtected(p, home) {
			return deny("%s holds komando's data and private keys, and a search of it reads them; search a project folder instead", dir)
		}
		if g := str("glob"); g != "" && !filepath.IsAbs(g) {
			// Grep reads what the glob picks: path/.komando/* reads komando's data
			if why := secretWord(filepath.Join(dir, g), home, cwd, true); why != "" {
				return deny("%s in %s matches %s; leave it out of the search", g, dir, why)
			}
		}
	case "Bash":
		return checkShell(str("command"), home, cwd)
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
func secretPath(p, home string) string {
	if p == "" {
		return ""
	}
	p = guardPath(p, home)
	if isProcEnviron(p) {
		return procEnv
	}
	komandoDirs := []string{filepath.Join(home, ".komando")}
	if h := os.Getenv("KOMANDO_HOME"); h != "" {
		komandoDirs = append(komandoDirs, h)
	}
	for _, d := range komandoDirs {
		if r := realPath(d); r != d {
			komandoDirs = append(komandoDirs, r) // a path seen through its links matches too
		}
	}
	if caseFoldFS {
		// ~/.KOMANDO/state.json is the same file on these systems
		p, home = strings.ToLower(p), strings.ToLower(home)
		for i, d := range komandoDirs {
			komandoDirs[i] = strings.ToLower(d)
		}
	}
	in := func(dir string) bool {
		if caseFoldFS {
			dir = strings.ToLower(dir)
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
	p = filepath.Clean(p)
	return strings.HasPrefix(p, "/proc/") && filepath.Base(p) == "environ"
}

// holdsProtected reports whether the folder p holds one of the folders
// secretPath guards (p is the home folder, /Users or /): a recursive read
// of p reads them too.
func holdsProtected(p, home string) bool {
	if !filepath.IsAbs(p) {
		return false
	}
	for _, q := range []string{filepath.Clean(p), realPath(p)} {
		for _, d := range protectedDirs(home) {
			if caseFoldFS {
				q, d = strings.ToLower(q), strings.ToLower(d)
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
func secretWord(w, home, cwd string, glob bool) string {
	if w == "" {
		return ""
	}
	if glob {
		return secretGlob(w, home, cwd)
	}
	p := guardPathAt(w, home, cwd)
	if why := secretPath(p, home); why != "" {
		return why
	}
	if real := realPath(p); real != p {
		if why := secretPath(real, home); why != "" {
			return why
		}
	}
	if filepath.IsAbs(p) {
		return hardLinkSecret(p, home)
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
// known.
func guardPathAt(w, home, cwd string) string {
	p := guardPath(w, home)
	if !filepath.IsAbs(p) && cwd != "" {
		p = filepath.Join(cwd, p)
	}
	return p
}

func wordHasGlob(w string) bool { return strings.ContainsAny(w, "*?[{") }

// secretGlob: a glob is off limits when a file it matches here is, or when
// it could name a protected folder or something in it: `~/.komand?`,
// `~/.ss?/id_*` and `.komando/keys/*` (from the home folder) all count.
func secretGlob(w, home, cwd string) string {
	for _, pat := range expandBraces(w, 0) {
		p := guardPathAt(pat, home, cwd)
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
				if why := secretPath(realPath(f), home); why != "" {
					return why
				}
			}
		}
		for _, d := range protectedDirs(home) {
			for _, q := range []string{p, realPath(p)} {
				if c, ok := globUnder(q, d, home); ok {
					if why := secretPath(c, home); why != "" {
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
var credentialStores = []string{".gnupg", ".password-store", ".config/gcloud", ".azure", ".kube", "Library/Keychains"}

func isCredentialStore(p, home string) bool {
	for _, d := range credentialStores {
		if d := filepath.Join(home, d); p == d || caseFoldFS && strings.EqualFold(p, d) {
			return true
		}
	}
	return false
}

// protectedDirs are the folders secretPath guards as a whole.
func protectedDirs(home string) []string {
	dirs := []string{filepath.Join(home, ".komando"), filepath.Join(home, ".ssh"), filepath.Join(home, ".docker")}
	if h := os.Getenv("KOMANDO_HOME"); h != "" {
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
		p, dir, home = strings.ToLower(p), strings.ToLower(dir), strings.ToLower(home)
	}
	pc := strings.Split(strings.Trim(p, "/"), "/")
	dc := strings.Split(strings.Trim(dir, "/"), "/")
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
	if name, rest, _ := strings.Cut(p[min(len(p), 1):], "/"); strings.HasPrefix(p, "~") && userName.MatchString(name) {
		return filepath.Join(userHome(name, home), rest) // ~me/.komando
	}
	return filepath.Clean(p)
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
// not commands. Unquoted heredocs stay: $(...) in them runs. So does the
// body a shell reads as its script (`bash <<'EOF'`).
func stripQuotedHeredocs(line string) string {
	lines := strings.Split(line, "\n")
	var out []string
	for i := 0; i < len(lines); i++ {
		out = append(out, lines[i])
		m := heredocStart.FindStringSubmatchIndex(lines[i])
		if m == nil {
			continue
		}
		segs := splitShell(lines[i][:m[0]])
		if prog, _ := program(shellWords(segs[len(segs)-1])); isShell(filepath.Base(prog)) {
			continue // the body is a script: it runs
		}
		end := lines[i][m[4]:m[5]]
		for i++; i < len(lines) && strings.TrimLeft(lines[i], "\t") != end; i++ {
		}
		if i < len(lines) {
			out = append(out, lines[i])
		}
	}
	return strings.Join(out, "\n")
}

var (
	// reading the passphrase's value; setting it (KOMANDO_VAULT_PASS=...) is fine
	procEnviron    = regexp.MustCompile(`/proc/[^\s'"]*environ\b`)
	readsVaultPass = regexp.MustCompile(`\$\{?KOMANDO_VAULT_PASS\b|printenv\s+KOMANDO_VAULT_PASS\b`)
	heredocStart   = regexp.MustCompile(`<<-?[ \t]*(['"])([A-Za-z_][A-Za-z0-9_]*)['"]`)
	envAssign      = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*(\[[^\]]*\])?\+?=`)
	remoteSpec     = regexp.MustCompile(`^([A-Za-z0-9_.-]+@)?[A-Za-z0-9_.-]+:`)
	// $(echo X), `printf X`, $(ls X): their output is the words X, which
	// become the outer command's arguments
	nameSubst = regexp.MustCompile(`\$\(\s*(echo|printf|ls|realpath|readlink|dirname)\b([^()` + "`" + `]*)\)|` + "`" + `\s*(echo|printf|ls|realpath|readlink|dirname)\b([^` + "`" + `]*)` + "`")
)

// inlineNames puts the words of $(echo X) and `echo X` in place of the
// substitution, as the shell does: `cat $(echo ~)/.komando/state.json`
// reads ~/.komando/state.json.
func inlineNames(line string) string {
	return nameSubst.ReplaceAllStringFunc(line, func(m string) string {
		g := nameSubst.FindStringSubmatch(m)
		args := strings.TrimSpace(g[2] + g[4])
		if g[1]+g[3] == "printf" {
			if f, rest, ok := strings.Cut(args, " "); ok && strings.Contains(f, "%") {
				args = strings.TrimSpace(rest) // the format: the rest is what it prints
			}
		}
		return args
	})
}

// checkShell looks at each simple command of a shell line, keeping track of
// `cd` so relative paths are read from the right folder. Arguments of
// komando itself pass: komando checks the local files it reads itself
// (readLocalFile), and the rest are paths on servers, which it masks.
func checkShell(line, home, cwd string) guardDecision {
	return checkShellDepth(line, home, cwd, 0)
}

func checkShellDepth(line, home, cwd string, depth int) guardDecision {
	line = stripQuotedHeredocs(line)
	if readsVaultPass.MatchString(line) {
		return deny("KOMANDO_VAULT_PASS opens komando's vault; it is for the user only")
	}
	if procEnviron.MatchString(line) { // /proc/PID/environ, not words like "environments"
		return deny("process environments hold secrets; ask the user for the one value you need")
	}
	if in := inlineNames(line); in != line && depth < 3 {
		if d := checkShellDepth(in, home, cwd, depth+1); d.Deny {
			return d
		}
	}
	for _, seg := range splitShell(line) {
		words, globs := shellWordsGlob(seg)
		if d := checkAgentVars(words, depth); d.Deny {
			return d
		}
		prog, args := program(words)
		base := filepath.Base(prog)
		switch {
		case prog == "":
			continue
		case base == "komando":
			continue
		case base == "cd" || base == "pushd":
			cwd = nextDir(args, home, cwd)
			if why := secretPath(cwd, home); cwd != "" && why != "" {
				return deny("%s is %s. komando keeps it away from AI agents; ask the user if you need something from it%s", cwd, why, viaKomando(why))
			}
		case isShell(base) || base == "eval":
			// the script of `bash -c '...'`, `bash -lc '...'` and `eval '...'`
			// is a shell line too
			script := shellScript(args)
			if base == "eval" {
				script = strings.Join(args, " ")
			}
			if script != "" && depth < 3 {
				if d := checkShellDepth(script, home, cwd, depth+1); d.Deny {
					return d
				}
			}
		case base == "ssh" || base == "scp" || base == "sftp" || base == "mosh" || base == "sshpass":
			return deny("use komando for servers (`komando exec`, `komando fs`, `komando cp`), not %s: komando checks every command, hides secrets and keeps an audit log", base)
		case base == "rsync":
			for _, a := range args {
				if !strings.HasPrefix(a, "-") && !strings.Contains(a, "://") && remoteSpec.MatchString(a) {
					return deny("use `komando sync` or `komando cp` for servers, not rsync")
				}
			}
		case base == "printenv" || base == "env" || base == "set" || base == "export" || base == "declare" || base == "typeset":
			// only the forms that list every variable: `set -e` is fine
			dump := len(args) == 0
			if (base == "export" || base == "declare" || base == "typeset") && len(args) == 1 && (args[0] == "-p" || args[0] == "-x" || args[0] == "-px") {
				dump = true
			}
			if dump {
				return deny("listing every environment variable shows tokens and passwords; read only the variable you need (`echo \"$NAME\"`)")
			}
		case base == "security":
			for _, a := range args {
				if a == "-w" || a == "-g" || a == "dump-keychain" || a == "export" {
					return deny("reading passwords from the keychain is for the user only")
				}
			}
		}
		switch base {
		case "echo", "printf", "touch", "mkdir", "ls", "test", "[":
			continue // they name files without reading them
		}
		recursive := recursiveReader(base, args)
		first := len(words) - len(args) // where the arguments start
		wcwd := cwd
		for j := 0; j < len(words); j++ {
			w := words[j]
			if j >= first {
				switch {
				case (base == "tar" || base == "git" || base == "make") && (w == "-C" || w == "--directory") && j+1 < len(words):
					// tar -C DIR and git -C DIR: the words after it are read from DIR
					j++
					if wcwd = nextDir(words[j:j+1], home, wcwd); wcwd != "" {
						if why := secretPath(wcwd, home); why != "" {
							return deny("%s is %s. komando keeps it away from AI agents; ask the user if you need something from it%s", wcwd, why, viaKomando(why))
						}
					}
					continue
				case (base == "tar" || base == "git" || base == "make") && strings.HasPrefix(w, "--directory="):
					if wcwd = nextDir([]string{strings.TrimPrefix(w, "--directory=")}, home, wcwd); wcwd != "" {
						if why := secretPath(wcwd, home); why != "" {
							return deny("%s is %s. komando keeps it away from AI agents; ask the user if you need something from it%s", wcwd, why, viaKomando(why))
						}
					}
					continue
				case base == "find" && findPattern[w]:
					j++ // a name pattern: find lists names; -exec, which reads, is checked
					continue
				}
			}
			glob := globs[j] && !strings.HasPrefix(w, "-")
			if !looksLikePath(w) && !glob {
				continue
			}
			if why := secretWord(w, home, wcwd, glob); why != "" {
				return deny("%s is %s. komando keeps it away from AI agents; ask the user if you need something from it%s", w, why, viaKomando(why))
			}
			if recursive && j >= first && !glob && !strings.HasPrefix(w, "-") && holdsProtected(guardPathAt(w, home, wcwd), home) {
				return deny("%s holds komando's data and private keys, and %s reads all of it; work on a project folder instead", w, base)
			}
		}
	}
	return allow()
}

// findPattern are find's tests that take a name pattern.
var findPattern = map[string]bool{"-name": true, "-iname": true, "-path": true, "-ipath": true, "-wholename": true, "-iwholename": true, "-regex": true, "-iregex": true, "-lname": true, "-ilname": true}

func isShell(base string) bool {
	switch base {
	case "sh", "bash", "zsh", "dash", "ksh", "mksh", "ash", "fish":
		return true
	}
	return false
}

// shellScript is the script a shell's arguments give with -c, or "": -c can
// come in a cluster (`bash -lc`, `sh -ec`), and options and their values
// (`-o pipefail`, `--`) can come between it and the script.
func shellScript(args []string) string {
	c := false
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "--":
			if c && i+1 < len(args) {
				return args[i+1]
			}
			return ""
		case a == "--rcfile" || a == "--init-file":
			i++
		case strings.HasPrefix(a, "--"):
		case len(a) > 1 && (a[0] == '-' || a[0] == '+'):
			if a[0] == '-' && strings.ContainsRune(a[1:], 'c') {
				c = true
			}
			if strings.ContainsAny(a[1:], "oO") {
				i++ // -o pipefail
			}
		default:
			if c {
				return a
			}
			return "" // a script file
		}
	}
	return ""
}

// recursiveReader reports whether a command reads every file under the
// folders it is given (grep -r, rg, tar c, zip -r, cp -r, find -exec, ...):
// given the home folder, it reads komando's data and the private keys too.
func recursiveReader(base string, args []string) bool {
	cluster := func(letters string) bool {
		for _, a := range args {
			if len(a) > 1 && a[0] == '-' && a[1] != '-' && strings.ContainsAny(a[1:], letters) {
				return true
			}
		}
		return false
	}
	has := func(long ...string) bool {
		for _, a := range args {
			for _, l := range long {
				if a == l || strings.HasPrefix(a, l+"=") {
					return true
				}
			}
		}
		return false
	}
	switch base {
	case "rg", "ag", "ack", "ack-grep", "rclone", "restic", "borg", "7z", "7za", "7zz":
		return true
	case "grep", "egrep", "fgrep", "zgrep", "ugrep":
		return cluster("rR") || has("--recursive", "--dereference-recursive", "--directories=recurse")
	case "zip", "diff":
		return cluster("rR") || has("--recurse-paths", "--recursive")
	case "cp", "rsync":
		return cluster("rRa") || has("--recursive", "--archive")
	case "tar", "bsdtar", "gtar":
		if has("--extract", "--list", "--get", "--diff", "--compare") || cluster("xtd") {
			return false
		}
		return len(args) == 0 || strings.HasPrefix(args[0], "-") || !strings.ContainsAny(args[0], "xtd")
	case "find":
		return has("-exec", "-execdir", "-ok", "-okdir")
	}
	return false
}

// nextDir is the folder `cd ARGS` moves to from cwd, or "" when the guard
// cannot know it (`cd -`, `cd "$DIR"`).
func nextDir(args []string, home, cwd string) string {
	for _, a := range args {
		if a == "--" || a == "-L" || a == "-P" || a == "-e" || a == "-@" {
			continue
		}
		if a == "-" || strings.ContainsAny(strings.NewReplacer("$HOME", "", "${HOME}", "", "$KOMANDO_HOME", "", "${KOMANDO_HOME}", "").Replace(a), "$`") {
			return ""
		}
		if wordHasGlob(a) {
			return "" // checked as a glob with the other words
		}
		p := guardPath(a, home)
		if filepath.IsAbs(p) {
			return p
		}
		if cwd == "" {
			return ""
		}
		return filepath.Join(cwd, p)
	}
	return home
}

// checkAgentVars stops a command that changes the variables komando knows
// an AI agent by (agentVars): `CLAUDECODE=0 komando ...`, `unset`, `export`,
// `read`, `env -u`, `env -i` and `exec -c` would make komando treat the
// agent as a script and skip the person's window, masking and the
// secret-file stops. So would `sudo komando`, which starts komando with a
// clean environment. A name komando cannot read (`unset $V`, `${!CLAUDE*}`)
// or a pattern (`CLAUDE*`, `CLAUDE{CODE,_CODE_ENTRYPOINT}`) that could be
// one counts as that name.
func checkAgentVars(words []string, depth int) guardDecision {
	why := func(name string) guardDecision {
		return deny("%s tells komando that an AI agent is running it; changing or clearing it would switch off komando's safety stops for agents. Leave it as it is", name)
	}
	cleared := func(how string) guardDecision {
		return deny("%s clears the variables komando knows an AI agent by, which would switch off komando's safety stops for agents", how)
	}
	// the words up to the program: shell keywords, NAME=value words and
	// wrappers (sudo, env, ...) with their flags; and the arguments of the
	// shell's own commands that set or remove variables
	wrapper, pos := "", 0
	sudo, keepsEnv := "", false
	for i := 0; i < len(words); i++ {
		w := words[i]
		base := filepath.Base(w)
		switch {
		case wrapper == "" && shellKeyword[w]:
			if w == "function" {
				i++
			}
		case envAssign.MatchString(w):
			if name, ok := agentVarIn(assignName(w)); ok {
				return why(name)
			}
		case w == "unset" || w == "export" || w == "declare" || w == "typeset" || w == "local" || w == "readonly" || w == "integer" || w == "float":
			for _, a := range words[i+1:] {
				if strings.HasPrefix(a, "-") || strings.HasPrefix(a, "+") {
					continue // -n, -x, +x, -m: the names are what count
				}
				if name, ok := agentVarIn(assignName(a)); ok {
					return why(name)
				}
			}
			return allow()
		case w == "read" || w == "mapfile" || w == "readarray" || w == "printf" || w == "getopts" || w == "for" || w == "select":
			for _, n := range setNames(w, words[i+1:]) {
				if name, ok := agentVarIn(n); ok {
					return why(name)
				}
			}
			return allow()
		case wrapper == "env" && strings.HasPrefix(w, "--") && w != "--":
			opt, val, hasVal := envLongOption(w)
			switch opt {
			case "--ignore-environment":
				return cleared("`env " + w + "`")
			case "--unset", "--chdir", "--split-string", "--argv0":
				if !hasVal && i+1 < len(words) {
					i++
					val = words[i]
				}
			}
			switch opt {
			case "--unset":
				if name, ok := agentVarIn(val); ok {
					return why(name)
				}
			case "--split-string":
				if depth < 3 {
					return checkAgentVars(append(append([]string{"env"}, shellWords(val)...), words[i+1:]...), depth+1)
				}
			}
		case wrapper == "env" && w == "-":
			return cleared("`env -`")
		case wrapper == "env" && len(w) > 1 && w[0] == '-' && w[1] != '-':
			// a cluster of short flags: -i, -vu NAME, -uNAME, -S 'words'
			for j := 1; j < len(w); j++ {
				c := w[j]
				if c == 'i' {
					return cleared("`env " + w + "`")
				}
				if c != 'u' && c != 'C' && c != 'S' && c != 'a' {
					continue
				}
				val := w[j+1:]
				if val == "" && i+1 < len(words) {
					i++
					val = words[i]
				}
				if c == 'u' {
					if name, ok := agentVarIn(val); ok {
						return why(name)
					}
				}
				if c == 'S' && depth < 3 {
					return checkAgentVars(append(append([]string{"env"}, shellWords(val)...), words[i+1:]...), depth+1)
				}
				break
			}
		case wrapper == "exec" && len(w) > 1 && w[0] == '-' && w[1] != '-' && strings.ContainsRune(w, 'c'):
			return cleared("`exec -c`")
		case isWrapper(base):
			wrapper, pos = base, 0
			if base == "sudo" || base == "doas" {
				sudo = base
			}
		case strings.HasPrefix(w, "-") && wrapper != "":
			if wrapper == "sudo" && (strings.HasPrefix(w, "--preserve-env") || len(w) > 1 && w[1] != '-' && strings.ContainsRune(w, 'E')) {
				keepsEnv = true
			}
			if wrapperValue[wrapper][w] {
				i++
			}
		case pos < wrapperPositional[wrapper]:
			pos++ // timeout 10, taskset 0x1
		default:
			// the program: its arguments are its own
			if base == "komando" && (sudo == "doas" || sudo == "sudo" && !keepsEnv) {
				return deny("%s starts komando with a clean environment, so komando would not know that an AI agent runs it; run komando without %s (it does not need root on this computer)", sudo, sudo)
			}
			return allow()
		}
	}
	return allow()
}

// shellKeyword are words that can start a simple command before the
// command itself: `{ unset X; }`, `! unset X`, `if unset X`, `builtin unset X`.
var shellKeyword = map[string]bool{"{": true, "}": true, "!": true, "if": true, "then": true, "else": true, "elif": true, "fi": true,
	"do": true, "done": true, "while": true, "until": true, "builtin": true, "coproc": true, "noglob": true, "nocorrect": true, "function": true}

// assignName is the variable name of NAME=value or NAME+=value.
func assignName(w string) string {
	n, _, _ := strings.Cut(w, "=")
	return strings.TrimSuffix(n, "+")
}

// agentVarIn reports the agent variable a name word sets or removes: the
// name itself, one of a {a,b} list, one a pattern matches (zsh `unset -m`),
// or any when the name is not known until the shell runs ($V, ${!P*}, `...`).
func agentVarIn(w string) (string, bool) {
	if strings.ContainsAny(w, "$`") {
		for _, a := range agentVars {
			if strings.Contains(w, a.env) {
				return a.env, true
			}
		}
		return agentVars[0].env + " (or another agent variable)", true
	}
	for _, x := range expandBraces(w, 0) {
		elem := x
		if i := strings.IndexByte(x, '['); i > 0 && strings.HasSuffix(x, "]") {
			elem = x[:i] // NAME[i]: an element of the variable NAME
		}
		for _, a := range agentVars {
			if x == a.env || elem == a.env {
				return a.env, true
			}
			if strings.ContainsAny(x, "*?[") {
				if ok, _ := filepath.Match(x, a.env); ok {
					return a.env, true
				}
			}
		}
	}
	return "", false
}

// setNames are the variable names a shell builtin that sets variables is
// given: read's and mapfile's names (not their flags' values), printf -v
// NAME, getopts' NAME, and for's and select's loop variable.
func setNames(builtin string, args []string) []string {
	var names []string
	switch builtin {
	case "for", "select":
		if len(args) > 0 {
			names = append(names, args[0])
		}
	case "getopts":
		if len(args) > 1 {
			names = append(names, args[1])
		}
	case "printf":
		for i, a := range args {
			if a == "-v" && i+1 < len(args) {
				names = append(names, args[i+1])
			} else if strings.HasPrefix(a, "-v") {
				names = append(names, a[2:])
			}
			if !strings.HasPrefix(a, "-") {
				break
			}
		}
	case "read", "mapfile", "readarray":
		values := "dnOsuCc" // flags whose value is not a name
		if builtin == "read" {
			values = "dinNptu"
		}
		for i := 0; i < len(args); i++ {
			a := args[i]
			if a == "--" {
				names = append(names, args[i+1:]...)
				break
			}
			if len(a) < 2 || a[0] != '-' {
				n, _, _ := strings.Cut(a, "?") // zsh: read NAME?prompt
				names = append(names, n)
				continue
			}
			for j := 1; j < len(a); j++ {
				if c := a[j]; strings.IndexByte(values, c) >= 0 || c == 'a' || c == 'A' {
					v := a[j+1:]
					if v == "" && i+1 < len(args) {
						i++
						v = args[i]
					}
					if c == 'a' || c == 'A' {
						names = append(names, v) // read -a NAME: an array
					}
					break
				}
			}
		}
	}
	return names
}

// envLongOption is the GNU env option w names: GNU takes any unambiguous
// start of a long option (--uns, --ignore-env). An ambiguous start that
// could clear or remove variables is taken as that, to be safe.
func envLongOption(w string) (opt, val string, hasVal bool) {
	name, val, hasVal := strings.Cut(w, "=")
	var match []string
	for _, o := range []string{"--ignore-environment", "--null", "--unset", "--chdir", "--split-string", "--block-signal",
		"--default-signal", "--ignore-signal", "--list-signal-handling", "--debug", "--argv0", "--help", "--version"} {
		if o == name {
			return o, val, hasVal
		}
		if len(name) > 2 && strings.HasPrefix(o, name) {
			match = append(match, o)
		}
	}
	for _, o := range match {
		if o == "--ignore-environment" || o == "--unset" || o == "--split-string" {
			return o, val, hasVal
		}
	}
	if len(match) == 1 {
		return match[0], val, hasVal
	}
	return name, val, hasVal
}

// program is the command a simple command runs, after shell keywords,
// VAR=value words and wrappers such as sudo, env, time, timeout and nohup.
func program(words []string) (string, []string) {
	wrapper, pos := "", 0
	for i := 0; i < len(words); i++ {
		w := words[i]
		base := filepath.Base(w)
		switch {
		case wrapper == "" && shellKeyword[w]:
			if w == "function" {
				i++
			}
			continue
		case envAssign.MatchString(w):
			continue
		case isWrapper(base) && base != "env":
			wrapper, pos = base, 0
			continue
		case base == "env" && i+1 < len(words) && (envAssign.MatchString(words[i+1]) || strings.HasPrefix(words[i+1], "-")):
			wrapper, pos = "env", 0
			continue
		case strings.HasPrefix(w, "-") && i > 0:
			// a wrapper's flag, e.g. sudo -u app: skip its value too
			if wrapperValue[wrapper][w] {
				i++
			}
			continue
		case pos < wrapperPositional[wrapper]:
			pos++
			continue
		}
		return w, words[i+1:]
	}
	return "", nil
}

func isWrapper(w string) bool {
	switch w {
	case "env", "sudo", "doas", "time", "nohup", "exec", "command", "nice", "xargs",
		"timeout", "setsid", "stdbuf", "chrt", "ionice", "taskset", "caffeinate", "busybox", "toybox", "unbuffer":
		return true
	}
	return false
}

// wrapperValue are the wrappers' flags that take the next word as a value.
var wrapperValue = map[string]map[string]bool{
	"env":        {"-u": true, "--unset": true, "-C": true, "--chdir": true, "-S": true, "--split-string": true},
	"sudo":       {"-u": true, "-g": true, "-h": true, "-p": true, "-C": true, "-D": true, "-r": true, "-t": true, "-U": true, "-T": true},
	"doas":       {"-u": true, "-C": true},
	"nice":       {"-n": true},
	"exec":       {"-a": true},
	"time":       {"-f": true, "-o": true},
	"xargs":      {"-I": true, "-n": true, "-P": true, "-L": true, "-d": true, "-E": true, "-s": true, "-a": true},
	"timeout":    {"-s": true, "--signal": true, "-k": true, "--kill-after": true},
	"stdbuf":     {"-i": true, "-o": true, "-e": true, "--input": true, "--output": true, "--error": true},
	"ionice":     {"-c": true, "-n": true, "--class": true, "--classdata": true},
	"chrt":       {"-T": true, "-P": true, "-D": true},
	"caffeinate": {"-t": true, "-w": true},
}

// wrapperPositional are the wrappers that take words before the program:
// timeout DURATION, chrt PRIORITY, taskset MASK.
var wrapperPositional = map[string]int{"timeout": 1, "chrt": 1, "taskset": 1}

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
	for _, v := range []string{"$HOME", "${HOME}", "$KOMANDO_HOME", "${KOMANDO_HOME}"} {
		if strings.HasPrefix(w, v) {
			return true
		}
	}
	return strings.ContainsAny(w, "/~.") || w == "credentials" || strings.HasPrefix(w, "id_")
}

// shellWords splits a simple command into words, removing quotes and
// redirections' operators.
func shellWords(s string) []string {
	w, _ := shellWordsGlob(s)
	return w
}

// shellWordsGlob is shellWords, and for each word whether the shell expands
// it as a glob: it has *, ?, [ or a {a,b} list outside quotes. `cat .e*`
// does, `grep -o '.*' f` and `cat ${HOME}/notes` do not.
func shellWordsGlob(s string) ([]string, []bool) {
	var words []string
	var globs []bool
	var cur strings.Builder
	var q rune
	glob, brace, inWord := false, false, false
	flush := func() {
		if cur.Len() > 0 || inWord {
			words = append(words, cur.String())
			globs = append(globs, glob || brace && strings.Contains(cur.String(), ","))
			cur.Reset()
		}
		glob, brace, inWord = false, false, false
	}
	escaped := false
	for _, r := range s {
		switch {
		case escaped: // \x is a plain x, as in the shell: \" opens no quote
			cur.WriteRune(r)
			escaped = false
		case r == '\\' && q != '\'':
			escaped = true
			inWord = true
		case q != 0:
			if r == q {
				q = 0
			} else {
				cur.WriteRune(r)
			}
		case r == '\'' || r == '"':
			q = r
			inWord = true
		case r == ' ' || r == '\t' || r == '<' || r == '>':
			flush()
		default:
			if strings.ContainsRune("*?[", r) {
				glob = true
			}
			if r == '{' {
				brace = true
			}
			cur.WriteRune(r)
			inWord = true
		}
	}
	flush()
	return words, globs
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
