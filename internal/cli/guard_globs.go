package cli

import (
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"strings"
)

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
	return allow()
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
