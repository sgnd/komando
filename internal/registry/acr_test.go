package registry

import (
	"context"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// fakeACR speaks Azure Container Registry's login: the token exchange,
// the token service (basic auth with the refresh token) and the API.
func fakeACR(t *testing.T) (*httptest.Server, TLS) {
	t.Helper()
	var srv *httptest.Server
	srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/oauth2/exchange":
			_ = r.ParseForm()
			if r.Method != "POST" || r.Form.Get("grant_type") != "access_token" || r.Form.Get("service") != "127.0.0.1" {
				w.WriteHeader(400)
				return
			}
			if r.Form.Get("access_token") != "aad-ok" || r.Form.Get("tenant") != "t1" {
				w.WriteHeader(401)
				fmt.Fprint(w, `{"errors":[{"code":"UNAUTHORIZED","message":"the token is for another tenant"}]}`)
				return
			}
			fmt.Fprint(w, `{"refresh_token":"acr-refresh"}`)
		case "/oauth2/token":
			if u, p, _ := r.BasicAuth(); u != ACRUser || p != "acr-refresh" {
				w.WriteHeader(401)
				return
			}
			fmt.Fprint(w, `{"access_token":"acr-access"}`)
		case "/v2/app/tags/list":
			if r.Header.Get("Authorization") != "Bearer acr-access" {
				w.Header().Set("WWW-Authenticate", `Bearer realm="`+srv.URL+`/oauth2/token",service="127.0.0.1"`)
				w.WriteHeader(401)
				return
			}
			fmt.Fprint(w, `{"name":"app","tags":["1.0"]}`)
		default:
			http.NotFound(w, r)
		}
	}))
	pool, err := CAPool(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw}))
	if err != nil {
		t.Fatal(err)
	}
	return srv, TLS{RootCAs: pool}
}

func TestACRLogin(t *testing.T) {
	srv, tc := fakeACR(t)
	defer srv.Close()
	ctx := context.Background()
	host := strings.TrimPrefix(srv.URL, "https://")

	c := New(host, tc, "", "", nil)
	if err := c.ACRLogin(ctx, "aad-ok", "t1"); err != nil {
		t.Fatal(err)
	}
	if c.User != ACRUser || c.Password != "acr-refresh" {
		t.Errorf("login %q", c.User)
	}
	if tags, err := c.Tags(ctx, "app", 10); err != nil || strings.Join(tags, ",") != "1.0" {
		t.Errorf("tags %v %v", tags, err)
	}

	err := New(host, tc, "", "", nil).ACRLogin(ctx, "aad-ok", "other")
	if e, ok := err.(*Error); !ok || e.Status != 401 || !strings.Contains(e.Message, "another tenant") || strings.Contains(e.Error(), "aad-ok") {
		t.Errorf("refused: %v", err)
	}
	if err := New(host, TLS{Plain: true}, "", "", nil).ACRLogin(ctx, "aad-ok", "t1"); err == nil || !strings.Contains(err.Error(), "https") {
		t.Errorf("plain http: %v", err)
	}
	// with the certificate unchecked, anyone on the path could take the token
	if err := New(host, TLS{SkipVerify: true}, "", "", nil).ACRLogin(ctx, "aad-ok", "t1"); err == nil || !strings.Contains(err.Error(), "certificate") {
		t.Errorf("skip-verify: %v", err)
	}
}
