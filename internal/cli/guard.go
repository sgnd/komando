package cli

import (
	"fmt"
	"os"
	"os/user"
	"path"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
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
	// with / on Windows too, where Cygwin and MSYS shells have /proc; a path
	// made absolute there gains a drive (C:\proc\self\environ), which is
	// left out so the check still sees /proc
	p = path.Clean(filepath.ToSlash(strings.TrimPrefix(p, filepath.VolumeName(p))))
	return strings.HasPrefix(p, "/proc/") && path.Base(p) == "environ"
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
