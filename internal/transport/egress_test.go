package transport

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// Every outbound client of komando goes through this package for what
// the environment could change: no client takes a proxy from it
// (http.DefaultTransport, http.DefaultClient, an http.Client without a
// Transport, http.Get and friends, http.ProxyFromEnvironment, httpproxy)
// or CAs from SSL_CERT_FILE (x509.SystemCertPool: use Roots). A Proxy is
// nil, Proxy(), http.ProxyURL of a person's config, or a variable that
// holds one of those. Libraries that build their own client get one of
// ours: minio.Options has a Transport, config.LoadDefaultConfig (AWS) is
// called only in loadAWS, which passes WithHTTPClient, and a file that
// asks oauth2 or google for tokens puts its client in the context
// (oauth2.HTTPClient), or they would use http.DefaultClient.
func TestClientsUseTheSharedTransport(t *testing.T) {
	fset := token.NewFileSet()
	var bad []string
	for _, root := range []string{"../../internal", "../../cmd"} {
		err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() {
				if d.Name() == "testdata" || filepath.ToSlash(p) == "../../internal/transport" {
					return filepath.SkipDir
				}
				return nil
			}
			if !strings.HasSuffix(p, ".go") || strings.HasSuffix(p, "_test.go") {
				return nil
			}
			f, err := parser.ParseFile(fset, p, nil, 0)
			if err != nil {
				return err
			}
			for _, b := range egressProblems(fset, f) {
				bad = append(bad, strings.TrimPrefix(b, "../../"))
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	for _, b := range bad {
		t.Error(b)
	}
}

// egressProblems lists the places in f that bypass the shared transport.
func egressProblems(fset *token.FileSet, f *ast.File) []string {
	imports := map[string]string{} // local name -> path
	for _, im := range f.Imports {
		path, _ := strconv.Unquote(im.Path.Value)
		parts := strings.Split(path, "/")
		name := parts[len(parts)-1]
		if len(parts) > 1 && len(name) > 1 && name[0] == 'v' && strings.Trim(name[1:], "0123456789") == "" {
			name = strings.TrimSuffix(parts[len(parts)-2], "-go") // github.com/minio/minio-go/v7 is minio
		}
		if im.Name != nil {
			name = im.Name.Name
		}
		imports[name] = path
	}
	is := func(e ast.Expr, path, sel string) bool {
		s, ok := e.(*ast.SelectorExpr)
		if !ok || s.Sel.Name != sel {
			return false
		}
		id, ok := s.X.(*ast.Ident)
		return ok && imports[id.Name] == path
	}
	var bad []string
	report := func(n ast.Node, what string) { bad = append(bad, fset.Position(n.Pos()).String()+": "+what) }
	const awsConfig, oauth2, google = "github.com/aws/aws-sdk-go-v2/config", "golang.org/x/oauth2", "golang.org/x/oauth2/google"
	var tokenCalls []ast.Node
	oauthClient := false
	fn := "" // the function being walked
	okProxy := func(e ast.Expr) bool {
		switch v := e.(type) {
		case *ast.Ident:
			return true // nil, or a variable set from one of the below
		case *ast.SelectorExpr:
			return v.Sel.Name == "Proxy" // a checked transport's own
		case *ast.CallExpr:
			return is(v.Fun, "github.com/sgnd/komando/internal/transport", "Proxy") || is(v.Fun, "net/http", "ProxyURL")
		}
		return false
	}
	ast.Inspect(f, func(n ast.Node) bool {
		switch v := n.(type) {
		case *ast.FuncDecl:
			fn = v.Name.Name
		case *ast.SelectorExpr:
			if is(v, oauth2, "HTTPClient") {
				oauthClient = true
			}
			for _, s := range []struct{ path, sel string }{{"net/http", "DefaultTransport"}, {"net/http", "DefaultClient"},
				{"net/http", "ProxyFromEnvironment"}, {"crypto/x509", "SystemCertPool"}, {"golang.org/x/net/http/httpproxy", "FromEnvironment"},
				{"github.com/gorilla/websocket", "DefaultDialer"}} {
				if is(v, s.path, s.sel) {
					report(v, s.path+"."+s.sel+" trusts the environment; use internal/transport")
				}
			}
		case *ast.CallExpr:
			for _, name := range []string{"Get", "Head", "Post", "PostForm"} {
				if is(v.Fun, "net/http", name) {
					report(v, "http."+name+" uses http.DefaultClient; build a client on transport.HTTP")
				}
			}
			if is(v.Fun, awsConfig, "LoadDefaultConfig") && fn != "loadAWS" {
				report(v, "config.LoadDefaultConfig builds the SDK's own client; call loadAWS")
			}
			for _, name := range []string{"FindDefaultCredentials", "CredentialsFromJSON", "CredentialsFromJSONWithType", "CredentialsFromJSONWithParams", "DefaultClient", "DefaultTokenSource"} {
				if is(v.Fun, google, name) {
					tokenCalls = append(tokenCalls, v)
				}
			}
			if is(v.Fun, oauth2, "NewClient") {
				tokenCalls = append(tokenCalls, v)
			}
		case *ast.CompositeLit:
			switch {
			case is(v.Type, "net/http", "Client"):
				if !hasKey(v, "Transport") {
					report(v, "an http.Client without a Transport uses http.DefaultTransport; use transport.HTTP")
				}
			case is(v.Type, "github.com/minio/minio-go/v7", "Options"):
				if !hasKey(v, "Transport") {
					report(v, "minio.Options without a Transport builds minio's own client; give it one on transport.HTTP")
				}
			case is(v.Type, "net/http", "Transport") || is(v.Type, "github.com/gorilla/websocket", "Dialer"):
				if e := keyValue(v, "Proxy"); e != nil && !okProxy(e) {
					report(v, "an http.Transport's Proxy must be nil, transport.Proxy() or http.ProxyURL")
				}
			}
		case *ast.AssignStmt:
			for i, l := range v.Lhs {
				if s, ok := l.(*ast.SelectorExpr); ok && s.Sel.Name == "Proxy" && i < len(v.Rhs) && !okProxy(v.Rhs[i]) {
					report(v, "a Proxy must be nil, transport.Proxy() or http.ProxyURL")
				}
			}
		}
		return true
	})
	if !oauthClient {
		for _, c := range tokenCalls {
			report(c, "an oauth2/google token call without a client in the context (oauth2.HTTPClient) uses http.DefaultClient")
		}
	}
	return bad
}

func keyValue(c *ast.CompositeLit, key string) ast.Expr {
	for _, e := range c.Elts {
		if kv, ok := e.(*ast.KeyValueExpr); ok {
			if id, ok := kv.Key.(*ast.Ident); ok && id.Name == key {
				return kv.Value
			}
		}
	}
	return nil
}

func hasKey(c *ast.CompositeLit, key string) bool { return keyValue(c, key) != nil }

// The walker finds what it is meant to find.
func TestEgressWalker(t *testing.T) {
	src := `package x
import (
	"crypto/x509"
	"net/http"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/minio/minio-go/v7"
	"golang.org/x/oauth2/google"
)
func f() {
	_ = http.DefaultTransport
	_ = &http.Client{Timeout: 1}
	_, _ = x509.SystemCertPool()
	_, _ = http.Get("https://example.com")
	tr := &http.Transport{Proxy: http.ProxyFromEnvironment}
	tr.Proxy = nil
	_ = &http.Client{Transport: tr}
	_, _ = config.LoadDefaultConfig(nil)
	_, _ = minio.New("h", &minio.Options{Secure: true})
	_, _ = google.FindDefaultCredentials(nil)
}`
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "x.go", src, 0)
	if err != nil {
		t.Fatal(err)
	}
	if got := egressProblems(fset, f); len(got) != 9 {
		t.Fatalf("found %d: %q", len(got), got)
	}
}
