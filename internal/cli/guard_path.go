package cli

import (
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"unicode"
)

// foldCase is s as a file system that ignores case compares it (APFS on
// macOS, NTFS on Windows). strings.ToLower is not enough: those systems
// fold ſ (U+017F) to s, and K (U+212A, the Kelvin sign) to k, so ~/.ſsh is
// ~/.ssh there.
func foldCase(s string) string {
	return strings.Map(func(r rune) rune { return unicode.ToLower(unicode.ToUpper(r)) }, s)
}

// kernelPath is the absolute path p, uncleaned, as the system resolves it:
// part by part, each link followed before the next part is read, so a ..
// after a link goes up from where the link leads (proj/l/../x with
// l -> ~/.ssh/sub is ~/.ssh/x), not from proj as filepath.Clean says. The
// parts that do not exist yet are added as they are written.
func kernelPath(p string) string {
	if !filepath.IsAbs(p) {
		return filepath.Clean(p)
	}
	vol := filepath.VolumeName(p)
	cur := vol + string(filepath.Separator)
	missing := false
	for _, e := range strings.FieldsFunc(p[len(vol):], func(r rune) bool { return r == '/' || r == filepath.Separator }) {
		switch {
		case e == ".":
			continue
		case e == "..":
			cur = filepath.Dir(cur)
			continue
		}
		next := filepath.Join(cur, e)
		if !missing {
			if r, err := filepath.EvalSymlinks(next); err == nil {
				cur = r
				continue
			}
			missing = true
		}
		cur = next
	}
	return cur
}

// hasDotDot reports whether p has a .. part.
func hasDotDot(p string) bool {
	return slices.Contains(strings.FieldsFunc(p, func(r rune) bool { return r == '/' || r == filepath.Separator }), "..")
}

// lexOrKernel is the absolute path raw as the guard reads it: cleaned, as
// it was, unless a .. in it comes after a link, where the system goes
// elsewhere: then the path the system reaches (kernelPath).
func lexOrKernel(raw string) string {
	c := filepath.Clean(raw)
	if !filepath.IsAbs(raw) || !hasDotDot(raw) {
		return c
	}
	if k := kernelPath(raw); k != realPath(c) {
		return k
	}
	return c
}

// underHome is p, a path that starts with the real path of home (home
// with its links followed: /private/var/... for /var/...), written from
// home again, so it compares with the folders the guard names in home.
func underHome(p, home string) string {
	rh := realPath(home)
	if rh == home {
		return p
	}
	if rel, err := filepath.Rel(rh, p); err == nil && filepath.IsLocal(rel) {
		return filepath.Join(home, rel)
	}
	if p == rh {
		return home
	}
	return p
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
	for _, v := range []string{"$HOME", "${HOME}", "$KOMANDO_HOME", "${KOMANDO_HOME}"} {
		if strings.HasPrefix(w, v) {
			return true
		}
	}
	return strings.ContainsAny(w, "/~.") || w == "credentials" || strings.HasPrefix(w, "id_")
}

// nextDir is the folder `cd ARGS` moves to from cwd: lostDir when the guard
// cannot know it (`cd -`, `cd "$DIR"`, a glob, or a relative folder from a
// lost one), and "" for a relative folder when cwd is "".
func nextDir(cl *call, args []string, home, cwd string) string {
	for _, a := range args {
		if a == "--" || a == "-L" || a == "-P" || a == "-e" || a == "-@" {
			continue
		}
		if a == "-" || strings.ContainsAny(strings.NewReplacer("$HOME", "", "${HOME}", "", "$KOMANDO_HOME", "", "${KOMANDO_HOME}", "").Replace(a), "$`"+unknownOutput) {
			return lostDir
		}
		if wordHasGlob(a) {
			return lostDir // the word is checked as a glob with the others
		}
		p := guardPath(cl, a, home)
		if filepath.IsAbs(p) {
			return p
		}
		if cwd == "" || cwd == lostDir {
			return cwd
		}
		return lexOrKernel(cwd + string(filepath.Separator) + p)
	}
	return home
}

// cdTarget is the folder cd ARGS, words of a line with vars, moves to from
// cwd (nextDir). A word with more than one value or one the guard cannot
// read, and a relative name CDPATH can send elsewhere, give lostDir.
func cdTarget(cl *call, args []string, vars lineVars, home, cwd string) string {
	dirs := slices.Clone(args)
	_, cdpath := vars["CDPATH"]
	cdpath = cdpath || cl.getenv("CDPATH") != ""
	for k, a := range dirs {
		x, known := vars.expand(cl, a, home, cwd)
		if !known || len(x) != 1 {
			return lostDir
		}
		dirs[k] = x[0]
		if d := x[0]; cdpath && !strings.HasPrefix(d, "-") && d != "." && d != ".." && !strings.HasPrefix(d, "./") && !strings.HasPrefix(d, "../") && !filepath.IsAbs(guardPath(cl, d, home)) {
			return lostDir
		}
	}
	return nextDir(cl, dirs, home, cwd)
}

// lineVars are the values the variables a shell line sets may have for its
// later commands. A name whose value the guard cannot know (read NAME,
// NAME=$(command)) maps to nil. redefinedVar, anyVar and aliasVar are keys
// no variable has: the line can change what a command name runs
// (redefines), it ran code that can set any variable (eval, source, a trap,
// a name reference), and a command name may be an alias, so the program of
// a command is not known. aliasFrom holds where the line made an alias:
// the shell reads a line whole before it runs it, so the alias counts from
// the next line on.
type lineVars map[string][]string

const (
	redefinedVar = "\x00redefined"
	anyVar       = "\x00any"
	aliasVar     = "\x00alias"
	aliasFrom    = "\x00alias-from"
)

// aliasAt notes that the command of a line that ends at end can make a
// command name an alias.
func (v lineVars) aliasAt(end int) {
	_, on := v[aliasVar]
	if _, noted := v[aliasFrom]; !on && !noted {
		v[aliasFrom] = []string{strconv.Itoa(end)}
	}
}

// aliasesFrom turns a noted alias on for a command of line that starts at
// start on a later line, or for code read later (start < 0: an eval's or a
// shell's script).
func (v lineVars) aliasesFrom(line string, start int) {
	at, ok := v[aliasFrom]
	if !ok || len(at) != 1 {
		return
	}
	n, _ := strconv.Atoi(at[0])
	if start < 0 || n <= start && strings.Contains(line[n:start], "\n") {
		v[aliasVar] = nil
		delete(v, aliasFrom)
	}
}

// lostDir is the working folder after a cd the guard cannot follow
// (cd -, cd "$DIR" with an unknown DIR): a path relative to it is unknown.
const lostDir = "\x00"

// varRef is a variable's value in a word: $NAME, ${...}, $1, $@ and the like.
var varRef = regexp.MustCompile(`\$(\{[^}]*\}|[A-Za-z_][A-Za-z0-9_]*|[0-9@*#?$!-])`)

var varName = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

// zshDollar finds the forms zsh gives a value other than the variable's
// own: $=NAME, $~NAME, $^NAME and $+NAME (split, used as a glob, spread,
// set or not), and $NAME[...] and $NAME:MOD (a part of it, or a change
// such as :h, :r or :s/a/b/).
var zshDollar = regexp.MustCompile(`\$[=~^+]+[A-Za-z_{(]|\$[A-Za-z_][A-Za-z0-9_]*[\[:]|\$\{[A-Za-z_][A-Za-z0-9_]*\}[\[:]`)

// shellNumbers are the parameters the shell sets to a number; [0-9]* stands
// for every value they may have.
var shellNumbers = map[string]bool{"$": true, "?": true, "#": true, "!": true, "RANDOM": true, "SRANDOM": true,
	"SECONDS": true, "EPOCHSECONDS": true, "EPOCHREALTIME": true, "LINENO": true, "BASHPID": true, "PPID": true,
	"UID": true, "EUID": true, "HISTCMD": true}

// shellOwn are variables the shell sets itself, whatever the environment
// the guard sees holds ($_ is the last word of the command before).
var shellOwn = map[string]bool{"_": true, "OLDPWD": true, "SHLVL": true, "REPLY": true, "OPTARG": true, "OPTIND": true,
	"BASH_COMMAND": true, "BASH_SOURCE": true, "BASH_ARGV0": true, "FUNCNAME": true, "MATCH": true, "MAPFILE": true,
	"PIPESTATUS": true}

// maxValues is the most values the guard follows for one word; past it the
// word is unknown.
const maxValues = 64

// expand gives the values the word w, run in cwd, may have when the line
// runs, and whether the guard knows them all. A command output it cannot
// know, a variable no rule gives a value and a ${...} with more than a name
// in it are unknown; for the checks of reads such a part is tried as itself
// and as empty. A variable's value also gives the fields the shell may
// split it into.
func (v lineVars) expand(cl *call, w, home, cwd string) (words []string, known bool) {
	known = !strings.Contains(w, unknownOutput)
	w = strings.ReplaceAll(w, unknownOutput, "")
	for rest := w; known; {
		j := strings.Index(rest, "${")
		if j < 0 {
			break
		}
		if loc := varRef.FindStringIndex(rest[j:]); loc == nil || loc[0] != 0 {
			known = false // a ${ the guard does not read to its }
		}
		rest = rest[j+2:]
	}
	known = known && !zshDollar.MatchString(w)
	split := false
	var walk func(s string, from, n int)
	walk = func(s string, from, n int) {
		loc := varRef.FindStringSubmatchIndex(s[from:])
		if loc == nil || n == 8 || len(words) >= maxValues {
			known = known && loc == nil
			words = append(words, s)
			return
		}
		start, end := from+loc[0], from+loc[1]
		name := strings.TrimSuffix(strings.TrimPrefix(s[from+loc[2]:from+loc[3]], "{"), "}")
		split = true
		vals, ok := v.values(cl, name, home, cwd)
		if !ok {
			known = false
			walk(s, end, n+1)
			vals = []string{""}
		}
		for _, val := range vals {
			walk(s[:start]+val+s[end:], start+len(val), n+1)
		}
	}
	walk(w, 0, 0)
	if split {
		var ok bool
		words, ok = v.fields(words)
		known = known && ok
	}
	if len(words) > maxValues {
		words, known = words[:maxValues], false
	}
	return words, known
}

// shapes are the values the word w may have, as expand gives them, with
// each part the guard cannot know written as unknownOutput; ok is false
// when it cannot say where those parts are (a ${ it does not read to its },
// a zsh value form, an IFS it cannot know, too many values).
func (v lineVars) shapes(cl *call, w, home, cwd string) (shapes []string, ok bool) {
	for rest := w; ; {
		j := strings.Index(rest, "${")
		if j < 0 {
			break
		}
		if loc := varRef.FindStringIndex(rest[j:]); loc == nil || loc[0] != 0 {
			return nil, false
		}
		rest = rest[j+2:]
	}
	if zshDollar.MatchString(w) {
		return nil, false
	}
	ok = true
	var walk func(s string, from, n int)
	walk = func(s string, from, n int) {
		loc := varRef.FindStringSubmatchIndex(s[from:])
		if loc == nil || n == 8 || len(shapes) >= maxValues {
			ok = ok && loc == nil
			shapes = append(shapes, s)
			return
		}
		start, end := from+loc[0], from+loc[1]
		name := strings.TrimSuffix(strings.TrimPrefix(s[from+loc[2]:from+loc[3]], "{"), "}")
		vals, known := v.values(cl, name, home, cwd)
		if !known {
			vals = []string{unknownOutput}
		}
		for _, val := range vals {
			walk(s[:start]+val+s[end:], start+len(val), n+1)
		}
	}
	walk(w, 0, 0)
	shapes, split := v.fields(shapes)
	return shapes, ok && split && len(shapes) <= maxValues
}

// A part of a written name the guard cannot know before the line runs may
// hold / and .., so the folder before it does not say where the file is:
// what the guard knows is the end of the name after the last unknown part.
// Refused are a name that ends in the unknown part (a wholly unknown
// target, /tmp/$name too), a fixed part after it that is komando's, a key's
// or an agent's ("$dir/settings.json"), and an ending after it in the last
// part that such a name has ("/tmp/$name.json"). Allowed is the rest
// ("$dir/out.txt", "/tmp/out-$name.log"). A relative name after a cd the
// guard cannot follow reads the same way. unknownName and
// protectedInUnknown are unknownWhy's reasons.
const (
	unknownName        = "names the file this line writes with a value komando's guard cannot read before the line runs; write to a file named on the line"
	protectedInUnknown = "names a file of komando, a key or an AI agent's guard in a folder komando's guard cannot know before the line runs; write to a full path"
)

// unknownWhy says why the written name s, its unknown parts written as
// unknownOutput, is refused, or "".
func unknownWhy(cl *call, s, home string) string {
	first := strings.Index(s, unknownOutput)
	if first < 0 {
		return ""
	}
	parts := strings.Split(s[first:], "/")
	for _, p := range parts[1:] {
		if !strings.Contains(p, unknownOutput) && protectedName(cl, p, home) {
			return protectedInUnknown
		}
	}
	last := parts[len(parts)-1]
	k := strings.LastIndex(last, unknownOutput)
	if k < 0 {
		if last == "" || last == "." || last == ".." {
			return unknownName // the unknown folder itself
		}
		return ""
	}
	end := last[k+len(unknownOutput):]
	if end == "" {
		return unknownName
	}
	if protectedName(cl, "*"+end, home) {
		return protectedInUnknown
	}
	return ""
}

// komandoDataNames are the files and folders komando keeps in its data
// folder (store.Path).
var komandoDataNames = []string{"state.json", "store.db", "store.key", "vault.key", "vault.json", "audit.jsonl", "keys",
	"known_hosts", "runtime.json", "runtime.pids", "login", "spawn", "tunnels", "vpn", "bitwarden-device"}

// sensitiveSamples are names sensitiveName counts, one of each form, that
// a glob is tried against.
var sensitiveSamples = []string{".env", ".env.local", "a.env", ".pgpass", ".my.cnf", ".netrc", ".git-credentials",
	".htpasswd", ".npmrc", ".pypirc", "credentials", "credentials.json", "master.key", "shadow", "id_rsa", "id_ed25519",
	"secrets.json", "secret.yml", "vault.key", "wp-config.php", "a.pem", "a.key", "a.p12", "a.pfx", "a.jks", "a.keystore",
	"a.kdbx", "a.ovpn"}

// protectedName says whether name, written in a folder the guard cannot
// know, may be a file or folder of komando, a key or an agent's guard: one
// of komandoDataNames, the komando program, an agent's folder or hook
// settings, a folder secretPath guards or one that holds it (.config,
// Library), a credential store's config, a name sensitiveName counts, or a
// glob that can match one of them.
func protectedName(cl *call, name, home string) bool {
	names := append(slices.Clone(komandoDataNames), "komando", "komando.exe", "config", "config.json")
	for dir, files := range hookSettingFiles {
		names = append(append(names, dir), files...)
	}
	for _, d := range protectedDirs(cl, home) {
		if rel, err := filepath.Rel(home, d); err == nil && !strings.HasPrefix(rel, "..") {
			names = append(names, strings.Split(filepath.ToSlash(rel), "/")...)
		} else {
			names = append(names, filepath.Base(d))
		}
	}
	fold := func(s string) string {
		if caseFoldFS {
			return foldCase(s)
		}
		return s
	}
	pats, whole := expandBraces(name)
	if !whole {
		return true // the names past the limit are not read
	}
	for _, pat := range pats {
		glob := wordHasGlob(pat)
		if !glob && sensitiveName(pat) {
			return true
		}
		for _, n := range append(names, sensitiveSamples...) {
			if fold(pat) == fold(n) {
				return true
			}
			if ok, _ := filepath.Match(fold(pat), fold(n)); glob && ok {
				return true
			}
		}
	}
	return false
}

// fields adds to vals the fields the shell may split them into: at blanks,
// and at each character of an IFS value the line sets. An IFS the guard
// cannot know leaves them unknown.
func (v lineVars) fields(vals []string) ([]string, bool) {
	seps, ok := v.separators()
	if !ok {
		return vals, false
	}
	out := vals
	for _, val := range vals {
		if f := splitAt(val, seps); len(f) > 1 {
			out = append(out, f...)
		}
	}
	return out, true
}

// separators are the characters the shell may split a value at: blanks,
// and each character of an IFS value the line sets; ok is false when the
// line sets IFS to a value the guard cannot know.
func (v lineVars) separators() (seps string, ok bool) {
	seps = " \t\n"
	ifs, set := v["IFS"]
	if set && ifs == nil {
		return seps, false
	}
	return seps + strings.Join(ifs, ""), true
}

// splitAt is val's fields between the characters of seps, empty ones left
// out.
func splitAt(val, seps string) []string {
	return strings.FieldsFunc(val, func(r rune) bool { return strings.ContainsRune(seps, r) })
}

// values are the values name may have when the line uses it, and whether
// the guard knows them: what the line set it to, the shell's own numbers,
// $PWD, the home folders and the environment.
func (v lineVars) values(cl *call, name, home, cwd string) ([]string, bool) {
	if i := strings.IndexByte(name, '?'); i > 0 { // ${NAME:?WORD}: NAME's value, or the line stops
		if base := strings.TrimSuffix(name[:i], ":"); varName.MatchString(base) {
			return v.values(cl, base, home, cwd)
		}
	}
	if vals, ok := v[name]; ok {
		return vals, vals != nil
	}
	if _, ok := v[anyVar]; ok && !shellNumbers[name] {
		return nil, false
	}
	switch {
	case shellNumbers[name]:
		return []string{"[0-9]*"}, true
	case name == "PWD":
		return []string{cwd}, cwd != "" && cwd != lostDir
	case name == "HOME":
		return []string{home}, true
	case name == homeVar:
		if h := cl.getenv(homeVar); h != "" {
			return []string{h}, true
		}
		return []string{filepath.Join(home, ".komando")}, true
	case shellOwn[name] || !varName.MatchString(name):
		return nil, false
	}
	if val := cl.getenv(name); val != "" {
		return []string{val}, true
	}
	return nil, false
}

// set adds vals to name's values, or makes them unknown: an assignment may
// not run (false && f=x, (f=x), x | f=x), so it never replaces a value the
// line set. A name the line has not set yet starts from its value before
// the line, or from "" when the environment does not hold it, unless sure
// says the assignment runs (surelyRuns) and no code the guard does not read
// ran before it.
func (v lineVars) set(cl *call, name string, vals []string, known, sure bool, home, cwd string) {
	old, ok := v[name]
	if _, any := v[anyVar]; !ok && sure && !any {
		old, ok = []string{}, true
	}
	if !ok {
		var had bool
		old, had = v.values(cl, name, home, cwd)
		_, any := v[anyVar]
		switch {
		case had:
		case !any && varName.MatchString(name) && !shellOwn[name]:
			old = []string{""}
		default:
			old = nil
		}
	}
	if old == nil || !known {
		v[name] = nil
		return
	}
	all := slices.Clone(old)
	for _, x := range vals {
		if !slices.Contains(all, x) {
			all = append(all, x)
		}
	}
	if len(all) > maxValues {
		all = nil
	}
	v[name] = all
}

// mayNotRun finds, before a command of a line, what can skip it, run it in
// a subshell or make it data: && || | & ( ) { } < > # ` and the words of
// compound commands.
var mayNotRun = regexp.MustCompile("[&|(){}<>#`]|\\b(if|then|else|elif|while|until|do|case|for|select|function)\\b")

// surelyRuns says whether the command line[start:end] runs in this shell
// before the commands after it: nothing before it can skip it or put it in
// a subshell, and it is not piped or put in the background.
func surelyRuns(line string, start, end int) bool {
	after := strings.TrimLeft(line[min(end, len(line)):], " \t")
	return !mayNotRun.MatchString(line[:max(0, start)]) && !strings.HasPrefix(after, "|") && !strings.HasPrefix(after, ")") &&
		(!strings.HasPrefix(after, "&") || strings.HasPrefix(after, "&&"))
}

// forget: the line ran code that can set any variable, so the guard knows
// none from here on.
func (v lineVars) forget() {
	for k := range v {
		if k != redefinedVar && k != aliasVar && k != aliasFrom {
			v[k] = nil
		}
	}
	v[anyVar] = nil
}

// assignExpansion is ${NAME:=VALUE}, ${NAME=VALUE} or zsh's ${NAME::=VALUE}:
// it sets NAME wherever it stands. zsh's flags, as in ${(A)NAME::=...}, and
// an element NAME[i] leave the value unknown.
var assignExpansion = regexp.MustCompile(`\$\{(\([^)]*\))?([A-Za-z_][A-Za-z0-9_]*)(\[[^\]]*\])?:{0,2}=([^}]*)`)

// learn notes what the command seg of line sets for the commands after it.
// seg ends at line[end:]; words are its words. In NAME=$(mktemp) the shell
// line is cut where the command output starts: seg ends at NAME=.
func (v lineVars) learn(cl *call, line, seg string, end int, home, cwd string, words []string) {
	prog, args := program(words)
	after := line[min(end, len(line)):]
	cut := strings.HasPrefix(after, "$(") || strings.HasPrefix(after, "`")
	sure := surelyRuns(line, end-len(seg), end)
	for _, m := range assignExpansion.FindAllStringSubmatch(seg, -1) {
		vals, known := v.expand(cl, m[4], home, cwd)
		v.set(cl, m[2], vals, known && m[1] == "" && m[3] == "", false, home, cwd)
	}
	assign := func(w string, last bool) {
		name, val, _ := strings.Cut(w, "=")
		if !varName.MatchString(name) {
			if i := strings.IndexAny(name, "+["); i > 0 {
				v.set(cl, name[:i], nil, false, false, home, cwd) // NAME+=value, NAME[i]=value
			}
			return
		}
		// NAME="$(...)" ends the segment at NAME=" as NAME=$(...) does at NAME=
		quoted := strings.HasSuffix(seg, `"`)
		if last && val == "" && strings.HasSuffix(strings.TrimSuffix(seg, `"`), "=") {
			switch {
			case strings.HasPrefix(after, "("): // NAME=(...): an array
				v.set(cl, name, nil, false, sure, home, cwd)
				return
			case cut:
				out, ok := "", false
				if o := commandOutputs(after); len(o) > 0 && o[0].start == 0 {
					out, ok = outputValue(cl, o[0].body, false, v)
					rest := after[o[0].end:]
					if quoted {
						ok = ok && strings.HasPrefix(rest, `"`)
						rest = strings.TrimPrefix(rest, `"`)
					}
					ok = ok && (rest == "" || strings.ContainsRune(" \t\n;&|)", rune(rest[0])))
				}
				v.set(cl, name, []string{out}, ok, sure, home, cwd)
				return
			}
		}
		vals, known := v.expand(cl, val, home, cwd)
		v.set(cl, name, vals, known && !(last && cut), sure, home, cwd)
	}
	switch {
	case prog == "":
		for i, w := range words {
			if envAssign.MatchString(w) {
				assign(w, i == len(words)-1)
			}
		}
	case prog == "export" || prog == "local" || prog == "declare" || prog == "readonly" || prog == "typeset" || prog == "nameref":
		if prog == "nameref" || (prog == "local" || prog == "declare" || prog == "typeset") && slices.ContainsFunc(args, nameRefFlag) {
			v.forget() // NAME is another variable's name: a value set through it is not followed
		}
		for i, a := range args {
			if envAssign.MatchString(a) {
				assign(a, i == len(args)-1)
			}
		}
	case (prog == "for" || prog == "select") && len(args) > 2 && args[1] == "in":
		var vals []string
		known, literal := !cut, true
		for _, a := range args[2:] {
			x, k := v.expand(cl, a, home, cwd)
			vals, known = append(vals, x...), known && k
			literal = literal && !strings.ContainsAny(a, "$`*?[")
		}
		// a list of plain words runs the loop: NAME holds one of them only
		v.set(cl, args[0], vals, known, sure && literal, home, cwd)
	case prog == "eval" || prog == "source" || prog == ".":
		v.forget()
		// an alias made in text the guard reads (eval 'alias c=cp') turns the
		// check of later commands on; code it does not read (a sourced file,
		// eval "$x") is outside the guard and can change files itself
		if prog == "eval" && slices.ContainsFunc(args, aliasInText.MatchString) {
			v.aliasAt(end)
		}
	case prog == "trap" && trapRunsAnyTime(args):
		v.forget()
	case prog == "alias" && slices.ContainsFunc(args, func(a string) bool { return strings.Contains(a, "=") }):
		v.aliasAt(end)
	default:
		for _, n := range setNames(prog, args) {
			v.set(cl, n, nil, false, false, home, cwd)
		}
	}
}

// aliasInText finds the word alias in code an eval runs.
var aliasInText = regexp.MustCompile(`(^|[^A-Za-z0-9_])alias(\s|$)`)

// nameRefFlag is declare's, typeset's or local's -n: NAME=OTHER makes NAME
// another name of OTHER.
func nameRefFlag(a string) bool {
	return len(a) > 1 && a[0] == '-' && a[1] != '-' && strings.ContainsRune(a, 'n')
}

// trapScript is the command trap ARGS runs, or "": trap -p, trap -l and
// trap - SIGNAL run none.
func trapScript(args []string) string {
	if len(args) > 0 && args[0] == "--" {
		args = args[1:]
	}
	if len(args) < 2 || args[0] == "-" || strings.HasPrefix(args[0], "-") && len(args[0]) == 2 {
		return ""
	}
	return args[0]
}

// trapRunsAnyTime says whether trap ARGS sets a command that can run before
// a later command of the line: on any signal but EXIT.
func trapRunsAnyTime(args []string) bool {
	if trapScript(args) == "" {
		return false
	}
	start := 1
	if args[0] == "--" {
		start = 2
	}
	for _, s := range args[start:] {
		if s != "EXIT" && s != "0" && s != "SIGEXIT" {
			return true
		}
	}
	return false
}
