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
)

// The error catalog (errcodes.go, `komando schema` error_codes) is made
// from the source: every out.Errf, out.Error{...}, out.Usage and
// out.NotFound with a code written in it. This test finds them all and
// fails when errcodes.go is not up to date. To bring it up to date:
//
//	KOMANDO_UPDATE_ERRCODES=1 go test ./internal/cli/ -run TestErrorCodeCatalog
func TestErrorCodeCatalog(t *testing.T) {
	want := scanErrorCodes(t)
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
	codeShape = regexp.MustCompile(`^[A-Z][A-Z0-9]*(_[A-Z0-9]+)+$|^(USAGE|ERROR|FAILED|TIMEOUT|CANCELLED)$`)
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

func scanErrorCodes(t *testing.T) []errorCode {
	t.Helper()
	var sites []codeSite
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
		sites = append(sites, codeSites(path, f)...)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	sort.SliceStable(sites, func(i, j int) bool { return sites[i].file < sites[j].file })
	byCode := map[string]*errorCode{}
	var order []string
	for _, s := range sites {
		c := byCode[s.code]
		if c == nil {
			c = &errorCode{Code: s.code, Exit: -1}
			byCode[s.code] = c
			order = append(order, s.code)
		}
		if c.Exit < 0 && s.exit >= 0 {
			c.Exit = s.exit
		}
		if c.Example == "" && s.message != "" {
			c.Example = s.message
		}
		if c.Hint == "" && s.hint != "" {
			c.Hint = s.hint
		}
	}
	sort.Strings(order)
	var out []errorCode
	for _, code := range order {
		c := *byCode[code]
		if c.Exit < 0 {
			c.Exit = 1
		}
		if m, ok := meanings[code]; ok && strings.Trim(c.Example, "… ") == "" {
			c.Example = m
		}
		out = append(out, c)
	}
	return out
}

func codeSites(path string, f *ast.File) []codeSite {
	var sites []codeSite
	lit := func(e ast.Expr) string {
		if b, ok := e.(*ast.BasicLit); ok && b.Kind == token.STRING {
			if s, err := strconv.Unquote(b.Value); err == nil {
				return s
			}
		}
		return ""
	}
	exitOf := func(e ast.Expr) int {
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
	codesIn := func(e ast.Expr) []string {
		if s := lit(e); codeShape.MatchString(s) {
			return []string{s}
		}
		// map[string]string{"host": "PROTECTED_HOST", "conn": "PROTECTED_TARGET"}[kind]
		var codes []string
		if ix, ok := e.(*ast.IndexExpr); ok {
			if cl, ok := ix.X.(*ast.CompositeLit); ok {
				for _, el := range cl.Elts {
					if kv, ok := el.(*ast.KeyValueExpr); ok && codeShape.MatchString(lit(kv.Value)) {
						codes = append(codes, lit(kv.Value))
					}
				}
			}
		}
		return codes
	}
	add := func(codes []string, exit int, hint, msg string) {
		for _, c := range codes {
			sites = append(sites, codeSite{file: path, code: c, exit: exit, hint: hint, message: example(msg)})
		}
	}
	ast.Inspect(f, func(n ast.Node) bool {
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
				}
			}
			switch {
			case name == "Errf" && len(x.Args) >= 4:
				add(codesIn(x.Args[1]), exitOf(x.Args[0]), lit(x.Args[2]), lit(x.Args[3]))
			case name == "Usage" && len(x.Args) >= 1:
				add([]string{"USAGE"}, 2, "", lit(x.Args[0]))
			case name == "NotFound" && len(x.Args) >= 1 && lit(x.Args[0]) != "":
				k := lit(x.Args[0])
				add([]string{strings.ToUpper(k) + "_NOT_FOUND"}, 3, fmt.Sprintf("run `komando %s list` to see available %ss", k, k), k+" … not found")
			}
		case *ast.CompositeLit:
			sel, ok := x.Type.(*ast.SelectorExpr)
			id, ok2 := x.Type.(*ast.Ident)
			if !(ok && sel.Sel.Name == "Error") && !(ok2 && id.Name == "Error" && strings.HasSuffix(path, "/out/out.go")) {
				return true
			}
			var codes []string
			exit, hint, msg := -1, "", ""
			for _, el := range x.Elts {
				kv, ok := el.(*ast.KeyValueExpr)
				if !ok {
					continue
				}
				switch k, _ := kv.Key.(*ast.Ident); {
				case k == nil:
				case k.Name == "Code":
					codes = codesIn(kv.Value)
				case k.Name == "Exit":
					exit = exitOf(kv.Value)
				case k.Name == "Hint":
					hint = lit(kv.Value)
				case k.Name == "Message":
					msg = lit(kv.Value)
				}
			}
			add(codes, exit, hint, msg)
		case *ast.AssignStmt:
			// soft.Code = "PARTIAL_FAILURE", soft.Code, soft.Hint = "X", "..."
			for i, l := range x.Lhs {
				if s, ok := l.(*ast.SelectorExpr); ok && s.Sel.Name == "Code" && i < len(x.Rhs) {
					add(codesIn(x.Rhs[i]), -1, "", "")
				}
			}
		}
		return true
	})
	return sites
}

// example is a message format as a reader sees it: the values a command
// fills in are "…".
func example(format string) string {
	s := verbs.ReplaceAllString(format, "…")
	s = strings.Join(strings.Fields(s), " ")
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
	"DEPLOY_FAILED":        "a rollout did not finish (its events follow)",
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
	"K8S_UNREACHABLE":      "the Kubernetes API did not answer (address, --via path or VPN)",
	"KEYCHAIN_FAILED":      "the system keychain refused (locked, or no Secret Service on Linux)",
	"KILL_FAILED":          "the session or job could not be stopped",
	"PARTIAL_FAILURE":      "some targets failed and some worked (see each result)",
	"READ_FAILED":          "komando could not read from the server or the resource",
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
	"WRITE_FAILED":         "a file could not be written",
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
