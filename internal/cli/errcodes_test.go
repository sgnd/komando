package cli

import (
	"bytes"
	"fmt"
	"go/ast"
	"go/format"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"
	"unicode"

	"github.com/sgnd/komando/internal/out"
)

// The error catalog (errcodes.go, `komando schema` error_codes) is made
// from the source: every out.Errf, out.Error{...}, out.Usage and
// out.NotFound with a code written in it. This test finds them all and
// fails when errcodes.go is not up to date. To bring it up to date:
//
//	KOMANDO_UPDATE_ERRCODES=1 go test ./internal/cli/ -run 'TestErrorCodeCatalog|TestErrorCodesDoc'
//
// (TestErrorCodesDoc writes docs/features/error-codes.md from the catalog.)
func TestErrorCodeCatalog(t *testing.T) {
	want, mixed := scanErrorCodes(t)
	// one code, one exit code: agents branch on either, and the catalog
	// can show only one
	for _, m := range mixed {
		t.Error(m)
	}
	if os.Getenv("KOMANDO_UPDATE_ERRCODES") != "" {
		writeErrorCodes(t, want)
		return
	}
	got := map[string]errorCode{}
	for _, c := range errorCodes {
		got[c.Code] = c
	}
	for _, c := range want {
		if g, ok := got[c.Code]; !ok || g != c {
			t.Errorf("errcodes.go is not up to date for %s (run with KOMANDO_UPDATE_ERRCODES=1)", c.Code)
		}
		delete(got, c.Code)
	}
	for code := range got {
		t.Errorf("errcodes.go lists %s, which no code gives any more (run with KOMANDO_UPDATE_ERRCODES=1)", code)
	}
	if len(want) < 150 {
		t.Errorf("only %d codes found: is the scan looking at internal/?", len(want))
	}
}

var (
	// codeShape is what a code looks like: upper case, digits and
	// underscores (NXDOMAIN has none). Only strings in a code's place are
	// tested: the code argument of out.Errf, a Code field or a call to a
	// function that passes its argument on as the code.
	codeShape = regexp.MustCompile(`^[A-Z][A-Z0-9]*(_[A-Z0-9]+)*$`)
	verbs     = regexp.MustCompile(`%[-+# 0-9.]*[a-zA-Z]`)
	exitNames = map[string]int{"ExitOK": 0, "ExitError": 1, "ExitUsage": 2, "ExitNotFound": 3, "ExitConnect": 4,
		"ExitRemote": 5, "ExitPolicy": 6, "ExitTimeout": 7, "ExitConflict": 8}
)

type codeSite struct {
	file          string
	code          string
	exit          int // -1: not written at this site
	hint, message string
}

// wrapper is a function that passes one of its arguments on as an error
// code, like agentYes(code, msg, what): a call to it with a code written
// in it is a call site too. An argument index of -1 means the function
// writes that part itself (exit, hint, message).
type wrapper struct {
	codeArg, exitArg, hintArg, msgArg int
	exit                              int
	hint, message                     string
}

type goFile struct {
	path string
	f    *ast.File
}

// twoExits are the codes whose exit tells two places apart on purpose:
// WRITE_FAILED is 1 for a file on this computer and 5 on a server (as any
// remote failure); VIA_CYCLE is 2 for the --via just given (host add or
// edit) and 1 for one stored earlier, found when connecting.
// SQL_TX_CONTROL and SQL_STRING_RULES are 2 for SQL the user wrote, refused
// before it runs, and 6 (a safety stop) when the server ended komando's
// transaction or reads SQL by rules komando cannot check.
var twoExits = map[string]bool{"WRITE_FAILED": true, "VIA_CYCLE": true, "SQL_TX_CONTROL": true, "SQL_STRING_RULES": true}

func scanErrorCodes(t *testing.T) (codes []errorCode, mixed []string) {
	t.Helper()
	var files []goFile
	err := filepath.WalkDir("..", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() && d.Name() == "testdata" {
			return filepath.SkipDir
		}
		if d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		f, err := parser.ParseFile(token.NewFileSet(), path, nil, parser.SkipObjectResolution)
		if err != nil {
			return err
		}
		files = append(files, goFile{path, f})
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	sort.SliceStable(files, func(i, j int) bool { return files[i].path < files[j].path })
	wrappers := findWrappers(files)
	var sites []codeSite
	for _, gf := range files {
		sites = append(sites, codeSites(gf.path, gf.f, wrappers)...)
	}
	byCode := map[string][]codeSite{}
	var order []string
	for _, s := range sites {
		if byCode[s.code] == nil {
			order = append(order, s.code)
		}
		byCode[s.code] = append(byCode[s.code], s)
	}
	sort.Strings(order)
	for _, code := range order {
		ss := byCode[code]
		exits := map[int][]string{}
		for _, s := range ss {
			if s.exit >= 0 {
				exits[s.exit] = append(exits[s.exit], s.file)
			}
		}
		if len(exits) > 1 && !twoExits[code] {
			mixed = append(mixed, fmt.Sprintf("%s exits with %d different codes: %v", code, len(exits), exits))
		}
		if from, ok := renamedFrom[code]; ok {
			// the error keeps the exit and hint of the one it renames
			for i := range ss {
				if ss[i].exit < 0 && ss[i].hint == "" {
					f := pickSite(byCode[from])
					ss[i].exit, ss[i].hint = f.Exit, f.Hint
				}
			}
		}
		c := pickSite(ss)
		if m, ok := meanings[code]; ok && letters(c.Example) < 4 {
			c.Example = m
		}
		if h, ok := hintMeanings[code]; ok && !hasWords(c.Hint) {
			c.Hint = h
		}
		if c.Hint == "" { // what the output gives in its place
			c.Hint = out.DefaultHint(c.Exit)
		}
		codes = append(codes, c)
	}
	return codes, mixed
}

// pickSite makes a code's catalog entry from ONE call site, so the example
// and the hint belong together. The exit code is the one most sites give
// (on a tie, the first site's). Among the sites with that exit, it takes
// the ones with a message and a hint written out in full, else those with
// both, else those with a hint, else those with a message, else all; of
// these, the one whose hint most sites give (on a tie, the first).
func pickSite(ss []codeSite) errorCode {
	count, most := map[int]int{}, 0
	for _, s := range ss {
		if s.exit >= 0 {
			count[s.exit]++
			most = max(most, count[s.exit])
		}
	}
	exit := -1
	for _, s := range ss {
		if s.exit >= 0 && count[s.exit] == most {
			exit = s.exit
			break
		}
	}
	hints := map[string]int{}
	for _, s := range ss {
		hints[s.hint]++
	}
	said := func(m string) bool { return letters(m) >= 4 } // "…: …" or "… is …" says nothing
	best := -1
	for _, want := range []func(codeSite) bool{
		func(s codeSite) bool { return s.hint != "" && !strings.Contains(s.hint, "…") && said(s.message) },
		func(s codeSite) bool { return s.hint != "" && said(s.message) },
		func(s codeSite) bool { return s.hint != "" },
		func(s codeSite) bool { return said(s.message) },
		func(codeSite) bool { return true },
	} {
		for i, s := range ss {
			if (s.exit == exit || s.exit < 0) && want(s) && (best < 0 || hints[s.hint] > hints[ss[best].hint]) {
				best = i
			}
		}
		if best >= 0 {
			break
		}
	}
	if exit < 0 {
		exit = 1
	}
	s := ss[best]
	return errorCode{Code: s.code, Exit: exit, Example: s.message, Hint: s.hint}
}

// lit is a string literal's value, or "".
func lit(e ast.Expr) string {
	if b, ok := e.(*ast.BasicLit); ok && b.Kind == token.STRING {
		if s, err := strconv.Unquote(b.Value); err == nil {
			return s
		}
	}
	return ""
}

// srcText is a string as a reader sees it: literals as written, joined
// with +, the format of an fmt.Sprintf, and "…" for a value the program
// fills in. It is "" when nothing in it is written in the source.
func srcText(e ast.Expr) string {
	var parts []string
	written := false
	var walk func(ast.Expr)
	walk = func(e ast.Expr) {
		switch x := e.(type) {
		case *ast.BasicLit:
			if s := lit(x); x.Kind == token.STRING {
				parts, written = append(parts, s), written || s != ""
				return
			}
		case *ast.ParenExpr:
			walk(x.X)
			return
		case *ast.BinaryExpr:
			if x.Op == token.ADD {
				walk(x.X)
				walk(x.Y)
				return
			}
		case *ast.CallExpr:
			if fn, ok := x.Fun.(*ast.SelectorExpr); ok && fn.Sel.Name == "Sprintf" && len(x.Args) > 0 {
				if id, ok := fn.X.(*ast.Ident); ok && id.Name == "fmt" && lit(x.Args[0]) != "" {
					parts, written = append(parts, verbs.ReplaceAllString(lit(x.Args[0]), "…")), true
					return
				}
			}
		}
		parts = append(parts, "…")
	}
	walk(e)
	if !written {
		return ""
	}
	return strings.Join(parts, "")
}

func exitOf(e ast.Expr) int {
	switch x := e.(type) {
	case *ast.SelectorExpr:
		if n, ok := exitNames[x.Sel.Name]; ok {
			return n
		}
	case *ast.Ident:
		if n, ok := exitNames[x.Name]; ok {
			return n
		}
	}
	return -1
}

// assign is one value given to a variable, and the statement that gives it.
type assign struct {
	stmt ast.Node
	val  ast.Expr
}

// localVars lists every value a function gives each of its variables, in
// source order: `code := "SECRET_UNRESOLVED"` then `code = "SECRET_NOT_FOUND"`.
func localVars(body ast.Node) map[string][]assign {
	vars := map[string][]assign{}
	ast.Inspect(body, func(n ast.Node) bool {
		switch x := n.(type) {
		case *ast.AssignStmt:
			if len(x.Lhs) == len(x.Rhs) {
				for i, l := range x.Lhs {
					if id, ok := l.(*ast.Ident); ok {
						vars[id.Name] = append(vars[id.Name], assign{x, x.Rhs[i]})
					}
				}
			}
		case *ast.ValueSpec:
			if len(x.Names) == len(x.Values) {
				for i, id := range x.Names {
					vars[id.Name] = append(vars[id.Name], assign{x, x.Values[i]})
				}
			}
		}
		return true
	})
	return vars
}

// scope is what a call site can see: the variables of the function it is
// in, and the statement that gave the code (nil when the code is written
// at the call itself).
type scope struct {
	vars map[string][]assign
	stmt ast.Node
}

// valueOf is the expression a variable holds at a site: the value the
// code's own statement gives it, else the first value it is given.
func (sc scope) valueOf(e ast.Expr) ast.Expr {
	id, ok := e.(*ast.Ident)
	if !ok {
		return e
	}
	as := sc.vars[id.Name]
	for _, a := range as {
		if a.stmt == sc.stmt && sc.stmt != nil {
			return a.val
		}
	}
	if len(as) > 0 {
		return as[0].val
	}
	return e
}

func (sc scope) str(e ast.Expr) string { return srcText(sc.valueOf(e)) }

func (sc scope) exit(e ast.Expr) int {
	n := exitOf(sc.valueOf(e))
	if n == 0 { // "worst := 0" is a start value, not this error's exit
		return -1
	}
	return n
}

// codesAt are the codes an expression in a code's place can hold, each
// with the scope it is read in.
func codesAt(e ast.Expr, vars map[string][]assign) (codes []string, scopes []scope) {
	if s := lit(e); codeShape.MatchString(s) {
		return []string{s}, []scope{{vars: vars}}
	}
	switch x := e.(type) {
	case *ast.IndexExpr:
		// map[string]string{"host": "PROTECTED_HOST", "conn": "PROTECTED_TARGET"}[kind]
		if cl, ok := x.X.(*ast.CompositeLit); ok {
			for _, el := range cl.Elts {
				if kv, ok := el.(*ast.KeyValueExpr); ok && codeShape.MatchString(lit(kv.Value)) {
					codes, scopes = append(codes, lit(kv.Value)), append(scopes, scope{vars: vars})
				}
			}
		}
	case *ast.Ident:
		// code := "CERT_PROBLEMS" ... out.Error{Code: code}
		for _, a := range vars[x.Name] {
			if s := lit(a.val); codeShape.MatchString(s) {
				codes, scopes = append(codes, s), append(scopes, scope{vars: vars, stmt: a.stmt})
			}
		}
	}
	return codes, scopes
}

// errorSink is a place that makes an error: out.Errf, out.Error{...}, or a
// wrapper call. Its parts are expressions (nil: not written there).
type errorSink struct {
	code, exit, hint, msg ast.Expr
	w                     *wrapper // a wrapper call: the parts it fills itself
}

func sinkOf(n ast.Node, path string, wrappers map[string]*wrapper) *errorSink {
	switch x := n.(type) {
	case *ast.CallExpr:
		name := ""
		switch fn := x.Fun.(type) {
		case *ast.SelectorExpr:
			if id, ok := fn.X.(*ast.Ident); ok && id.Name == "out" {
				name = fn.Sel.Name
			}
		case *ast.Ident:
			if strings.HasSuffix(path, "/out/out.go") {
				name = fn.Name
			} else if w := wrappers[filepath.Dir(path)+"."+fn.Name]; w != nil && w.codeArg < len(x.Args) {
				s := &errorSink{code: x.Args[w.codeArg], w: w}
				arg := func(i int) ast.Expr {
					if i >= 0 && i < len(x.Args) {
						return x.Args[i]
					}
					return nil
				}
				s.exit, s.hint, s.msg = arg(w.exitArg), arg(w.hintArg), arg(w.msgArg)
				return s
			}
		}
		if name == "Errf" && len(x.Args) >= 4 {
			s := &errorSink{code: x.Args[1], exit: x.Args[0], hint: x.Args[2], msg: x.Args[3]}
			if lit(x.Args[3]) == "%s" && len(x.Args) == 5 {
				s.msg = x.Args[4]
			}
			return s
		}
	case *ast.CompositeLit:
		sel, ok := x.Type.(*ast.SelectorExpr)
		id, ok2 := x.Type.(*ast.Ident)
		if !(ok && sel.Sel.Name == "Error") && !(ok2 && id.Name == "Error" && strings.HasSuffix(path, "/out/out.go")) {
			return nil
		}
		s := &errorSink{}
		for _, el := range x.Elts {
			kv, ok := el.(*ast.KeyValueExpr)
			if !ok {
				continue
			}
			switch k, _ := kv.Key.(*ast.Ident); {
			case k == nil:
			case k.Name == "Code":
				s.code = kv.Value
			case k.Name == "Exit":
				s.exit = kv.Value
			case k.Name == "Hint":
				s.hint = kv.Value
			case k.Name == "Message":
				s.msg = kv.Value
			}
		}
		if s.code != nil {
			return s
		}
	case *ast.AssignStmt:
		// soft.Code, soft.Hint = "PARTIAL_FAILURE", "see each result's error and hint"
		if len(x.Lhs) != len(x.Rhs) {
			return nil
		}
		s := &errorSink{}
		for i, l := range x.Lhs {
			if sel, ok := l.(*ast.SelectorExpr); ok {
				switch sel.Sel.Name {
				case "Code":
					s.code = x.Rhs[i]
				case "Exit":
					s.exit = x.Rhs[i]
				case "Hint":
					s.hint = x.Rhs[i]
				case "Message":
					s.msg = x.Rhs[i]
				}
			}
		}
		if s.code != nil {
			return s
		}
	}
	return nil
}

// findWrappers finds the functions that pass an argument on as an error
// code (agentYes, localFileErr, renameNotFound), and the functions that
// pass one on to those, until there are no more. The out package's own
// Errf, NotFound and Usage are read by name instead.
func findWrappers(files []goFile) map[string]*wrapper {
	wrappers := map[string]*wrapper{}
	for changed := true; changed; {
		changed = false
		for _, gf := range files {
			if strings.HasSuffix(filepath.Dir(gf.path), "/out") {
				continue
			}
			for _, d := range gf.f.Decls {
				fd, ok := d.(*ast.FuncDecl)
				if !ok || fd.Body == nil || fd.Recv != nil {
					continue
				}
				key := filepath.Dir(gf.path) + "." + fd.Name.Name
				if wrappers[key] != nil {
					continue
				}
				params := map[string]int{}
				i := 0
				for _, f := range fd.Type.Params.List {
					for _, n := range f.Names {
						params[n.Name] = i
						i++
					}
				}
				argOf := func(e ast.Expr) int {
					if id, ok := e.(*ast.Ident); ok {
						if n, ok := params[id.Name]; ok {
							return n
						}
					}
					return -1
				}
				ast.Inspect(fd.Body, func(n ast.Node) bool {
					if wrappers[key] != nil {
						return false
					}
					s := sinkOf(n, gf.path, wrappers)
					if s == nil || argOf(s.code) < 0 {
						return true
					}
					w := &wrapper{codeArg: argOf(s.code), exitArg: argOf(s.exit), hintArg: argOf(s.hint), msgArg: argOf(s.msg), exit: -1}
					if s.exit != nil {
						w.exit = exitOf(s.exit)
					}
					if s.hint != nil && w.hintArg < 0 {
						w.hint = srcText(s.hint)
					}
					if s.msg != nil && w.msgArg < 0 {
						w.message = srcText(s.msg)
					}
					if s.w != nil { // passes it on to another wrapper
						if w.exit < 0 && w.exitArg < 0 {
							w.exit = s.w.exit
						}
						if w.hint == "" && w.hintArg < 0 {
							w.hint = s.w.hint
						}
						if w.message == "" && w.msgArg < 0 {
							w.message = s.w.message
						}
					}
					wrappers[key], changed = w, true
					return false
				})
			}
		}
	}
	return wrappers
}

func codeSites(path string, f *ast.File, wrappers map[string]*wrapper) []codeSite {
	var sites []codeSite
	visit := func(body ast.Node, vars map[string][]assign) {
		ast.Inspect(body, func(n ast.Node) bool {
			if x, ok := n.(*ast.CallExpr); ok {
				if fn, ok := x.Fun.(*ast.SelectorExpr); ok {
					if id, ok := fn.X.(*ast.Ident); ok && id.Name == "out" || strings.HasSuffix(path, "/out/out.go") {
						switch {
						case fn.Sel.Name == "Usage" && len(x.Args) >= 1:
							sites = append(sites, codeSite{path, "USAGE", 2, "", example(srcText(x.Args[0]))})
						case fn.Sel.Name == "NotFound" && len(x.Args) >= 1 && lit(x.Args[0]) != "":
							k := lit(x.Args[0])
							word := k
							if k == "vpn" {
								word = "VPN"
							}
							sites = append(sites, codeSite{path, strings.ToUpper(k) + "_NOT_FOUND", 3,
								fmt.Sprintf("run `komando %s list` to see available %ss", k, word), word + " … not found"})
						}
					}
				}
			}
			s := sinkOf(n, path, wrappers)
			if s == nil {
				return true
			}
			codes, scopes := codesAt(s.code, vars)
			for i, code := range codes {
				sc := scopes[i]
				site := codeSite{file: path, code: code, exit: -1}
				if s.exit != nil {
					site.exit = sc.exit(s.exit)
				}
				if s.hint != nil {
					site.hint = sc.str(s.hint)
				}
				if s.msg != nil {
					site.message = example(sc.str(s.msg))
				}
				if w := s.w; w != nil {
					if site.exit < 0 && w.exitArg < 0 {
						site.exit = w.exit
					}
					if site.hint == "" && w.hintArg < 0 {
						site.hint = w.hint
					}
					if site.message == "" && w.msgArg < 0 {
						site.message = example(w.message)
					}
				}
				sites = append(sites, site)
			}
			return true
		})
	}
	for _, d := range f.Decls {
		if fd, ok := d.(*ast.FuncDecl); ok && fd.Body != nil {
			visit(fd.Body, localVars(fd.Body))
		} else {
			visit(d, nil)
		}
	}
	return sites
}

// example is a message format as a reader sees it: the values a command
// fills in are "…".
func example(format string) string {
	s := verbs.ReplaceAllString(format, "…")
	s = strings.Join(strings.Fields(s), " ")
	for strings.Contains(s, "……") {
		s = strings.ReplaceAll(s, "……", "…")
	}
	if r := []rune(s); len(r) > 160 {
		s = string(r[:159]) + "…"
	}
	return s
}

// meanings stand in for an example where the message is all values (the
// server's own words): what the code means, in a few words.
var meanings = map[string]string{
	"AUDIT_TAMPERED":       "the audit log was changed outside komando (komando audit verify)",
	"BAD_FILE":             "a file komando was given cannot be used as it is",
	"CACHE_AUTH":           "the cache refused the login (password or ACL user)",
	"CACHE_ERROR":          "the cache answered with an error (its words follow)",
	"DB_AUTH":              "the database refused the user name or password",
	"DB_CONNECT":           "komando could not connect to the database (address, TLS or --via path)",
	"DB_ERROR":             "the database refused the statement (its words follow, with the SQLSTATE)",
	"DB_NOT_FOUND":         "the database named in the conn does not exist",
	"DB_PRIVILEGE":         "the conn's user lacks a right the command needs",
	"DB_USER_IN_USE":       "the database user owns objects or has sessions, so it is not removed",
	"DEPLOY_FAILED":        "key deploy could not add the key to the server's authorized_keys (the server's words follow)",
	"DOCKER_ERROR":         "docker on the server answered with an error",
	"DOCKER_PERMISSION":    "the login user may not use docker on the server (add --sudo, or the docker group)",
	"DRY_RUN_UNSUPPORTED":  "this change cannot be previewed; run it without --dry-run to make it",
	"DUMP_FAILED":          "the backup stopped before the end; no partial file is left",
	"DUMP_UNSUPPORTED":     "komando's own dump cannot write an object (the message names it)",
	"ERROR":                "an error with no more specific code (read the message)",
	"FAILED":               "the command ran on the server and exited non-zero",
	"FILE_ERROR":           "a file on this computer cannot be read or written",
	"HOSTKEY_MISMATCH":     "the server shows a different host key than the one pinned: maybe an attack, never fixed automatically",
	"HOSTKEY_UNKNOWN":      "host keys are strict and this server's key is not pinned yet (the message shows its fingerprint)",
	"K8S_CONFLICT":         "the object changed or exists already (the cluster's words follow)",
	"K8S_ERROR":            "the Kubernetes API answered with an error (its words follow)",
	"K8S_INVALID":          "the cluster refused the request as written (its words follow)",
	"K8S_UNREACHABLE":      "the Kubernetes API did not answer (address, --via path or VPN)",
	"KEYCHAIN_FAILED":      "the system keychain refused (locked, or no Secret Service on Linux)",
	"KILL_FAILED":          "the session or job could not be stopped",
	"PARTIAL_FAILURE":      "some targets failed and some worked (see each result)",
	"QUEUE_AUTH":           "the queue server refused the login (user, Kafka sasl= mechanism or password)",
	"QUEUE_CONNECT":        "komando could not connect to the queue server (address, TLS or --via path)",
	"QUEUE_DENIED":         "the conn's user lacks the permission the command needs (a Kafka ACL, a RabbitMQ permission)",
	"QUEUE_ERROR":          "the queue server answered with an error (its words follow)",
	"READ_FAILED":          "komando could not read from the server or the resource",
	"REGISTRY_AUTH":        "the registry refused the login or the token's scopes",
	"REGISTRY_UNSUPPORTED": "the registry does not allow this request",
	"REGISTRY_UNREACHABLE": "the registry did not answer (address, TLS or --via path)",
	"REMOTE_ERROR":         "an error from outside komando with no more specific code (its words follow)",
	"RESTORE_FAILED":       "the restore stopped; what was loaded before the error stays (unless it ran in one transaction)",
	"REVISION_NOT_FOUND":   "the deployment has no revision with that number (cluster history lists them)",
	"REVOKE_FAILED":        "the key could not be removed from a server's authorized_keys",
	"SECRET_MISMATCH":      "secret check: the value typed is not the stored one",
	"KEYCHAIN_TAKEN":       "another vault's key is already in the keychain under this folder's name, so komando does not replace it",
	"SSH_GATE_SYNTAX":      "an ssh-gate key sent more than one komando command, or a character a shell would expand (the message names it)",
	"STORAGE_CONNECT":      "komando could not reach the bucket or file server",
	"STORAGE_TLS":          "the storage server's TLS certificate does not verify",
	"SWARM_ERROR":          "Docker Swarm answered with an error",
	"TARGET_EMPTY":         "the selector picks nothing (an empty group or tag)",
	"TOOL_FAILED":          "a program komando ran on the server failed (its words follow)",
	"TOOL_TOO_OLD":         "a program on the server is older than komando needs",
	"TUNNEL_FAILED":        "the server refused the port forwarding (AllowTcpForwarding, address)",
	"VAULT_CHANGED":        "the vault changed while komando was writing it; nothing was saved, run it again",
	"VAULT_DECRYPT":        "a secret does not decrypt with the passphrase or key given",
	"VAULT_KEY":            "the vault's key file is missing or broken",
	"VAULT_LOCKED":         "the vault has a passphrase and none was given (KOMANDO_VAULT_PASS)",
	"VPN_STOP_FAILED":      "the VPN session could not be stopped",
	"WEAK_PASSPHRASE":      "the passphrase is shorter than 15 characters",
	"WRITE_FAILED":         "a file could not be written (exit 1 on this computer; exit 5 for a file on a server: fs write, fs replace)",
	"CONNECTION_REFUSED":   "the server refused the connection: nothing listens on that port",
	"DNS_ERROR":            "the server's name does not resolve on this computer",
	"OVPN_UNSUPPORTED":     "the OpenVPN profile has an option komando's own client does not support (the message names it)",
	"SENSITIVE_FILE":       "the file holds secrets or belongs to komando, so an AI agent may not read or copy it",
	"SSM_FAILED":           "AWS Session Manager could not open a session to the instance",
}

// renamedFrom are codes given by renaming another error (e.Code =
// "SWARM_ERROR" on a DOCKER_ERROR), which keeps that error's exit and hint.
var renamedFrom = map[string]string{"SWARM_ERROR": "DOCKER_ERROR"}

// hintMeanings stand in for a hint the program builds as it runs (from the
// key's path, or from the tool's error): what it tells the reader to do.
var hintMeanings = map[string]string{
	"KEY_PASSPHRASE_REQUIRED": "load the key into ssh-agent with `ssh-add PATH`, or store its passphrase with `komando secret set NAME` (the hint gives the whole commands)",
	"NO_PASSPHRASE":           "the vault keeps its key in store.key or the OS keychain already; the hint says which",
	"VPN_CLIENT_MISSING":      "install the program the message names (macOS: `brew install NAME`; Linux: its package)",
	"TOOL_FAILED":             "read the message; `komando conn test CONN` checks reachability (for a known problem, the hint names the fix)",
	"AZURE_LOGIN_REQUIRED":    "set AZURE_TENANT_ID, AZURE_CLIENT_ID and AZURE_CLIENT_SECRET for a service principal, run komando on Azure with a managed identity, or a person runs `az login`",
}

// hasWords reports whether a hint says something beyond the values the
// program fills in ("…, or …" does not).
func hasWords(h string) bool { return letters(h) >= 12 }

func letters(s string) int {
	n := 0
	for _, r := range s {
		if unicode.IsLetter(r) {
			n++
		}
	}
	return n
}

func writeErrorCodes(t *testing.T, codes []errorCode) {
	t.Helper()
	var b bytes.Buffer
	b.WriteString("// Code generated by TestErrorCodeCatalog (KOMANDO_UPDATE_ERRCODES=1); DO NOT EDIT.\n\npackage cli\n\n")
	b.WriteString("// errorCodes is every error code komando gives, with its exit code, an\n// example message and the usual next step, from the source.\nvar errorCodes = []errorCode{\n")
	for _, c := range codes {
		fmt.Fprintf(&b, "\t{%q, %d, %q, %q},\n", c.Code, c.Exit, c.Example, c.Hint)
	}

	b.WriteString("}\n")
	src, err := format.Source(b.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile("errcodes.go", src, 0o644); err != nil {
		t.Fatal(err)
	}
}
