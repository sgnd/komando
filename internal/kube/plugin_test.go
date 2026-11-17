package kube

import (
	"context"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"net/http"
	"net/http/httptest"
	"runtime"
	"strings"
	"sync"
	"testing"
)

// authServer records the Authorization header of each request.
func authServer(t *testing.T, tls bool) (*httptest.Server, func() []string) {
	t.Helper()
	var mu sync.Mutex
	var seen []string
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		seen = append(seen, r.Header.Get("Authorization"))
		mu.Unlock()
		w.Write([]byte("{}"))
	})
	srv := httptest.NewServer(h)
	if tls {
		srv.Close()
		srv = httptest.NewTLSServer(h)
	}
	t.Cleanup(srv.Close)
	return srv, func() []string { mu.Lock(); defer mu.Unlock(); return append([]string(nil), seen...) }
}

// A token komando makes from this computer's cloud login (EKS, GKE) is
// good for the cloud account or the named cluster: it goes to the server
// only over https with the certificate checked, whoever asks.
func TestCloudTokenNeedsCheckedHTTPS(t *testing.T) {
	made := 0
	saved := gcpAccessToken
	defer func() { gcpAccessToken = saved }()
	gcpAccessToken = func(context.Context) (string, error) { made++; return "ya29.person", nil }
	gke := func(x *Context) *Context {
		x.User.Exec = &ExecAuth{Command: "gke-gcloud-auth-plugin"}
		return x
	}
	plain, plainSeen := authServer(t, false)
	secure, secureSeen := authServer(t, true)
	ca := base64.StdEncoding.EncodeToString(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: secure.Certificate().Raw}))

	for name, x := range map[string]*Context{
		"plain http":  gke(&Context{Cluster: Cluster{Server: plain.URL}}),
		"skip verify": gke(&Context{Cluster: Cluster{Server: secure.URL, InsecureSkipTLSVerify: true}}),
	} {
		k, err := New(x, nil)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := k.Do(context.Background(), "GET", "/version", nil, nil, ""); !errors.Is(err, ErrUncheckedLogin) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if made != 0 || len(plainSeen())+len(secureSeen()) != 0 {
		t.Errorf("a cloud token was made %d times, requests %q %q", made, plainSeen(), secureSeen())
	}
	k, err := New(gke(&Context{Cluster: Cluster{Server: secure.URL, CertificateAuthorityData: ca}}), nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := k.Do(context.Background(), "GET", "/version", nil, nil, ""); err != nil || made != 1 || secureSeen()[0] != "Bearer ya29.person" {
		t.Errorf("checked https: %v, made %d, %q", err, made, secureSeen())
	}
}

// A credential plugin runs with the environment its client was given (the
// command's, not whatever the process has), and with SearchPath as its
// PATH when the cli recorded one; the variables that load code into a
// program are then left out.
func TestPluginEnvironment(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the plugin is a /bin/sh script")
	}
	srv, seen := authServer(t, false)
	t.Setenv("KOMANDO_TEST_MARK", "process")
	run := func(e *ExecAuth, env []string) string {
		t.Helper()
		x := &Context{Cluster: Cluster{Server: srv.URL}}
		x.User.Exec = e
		k, err := New(x, nil)
		if err != nil {
			t.Fatal(err)
		}
		k.Env = env
		if _, err := k.Do(context.Background(), "GET", "/version", nil, nil, ""); err != nil {
			t.Fatal(err)
		}
		all := seen()
		return strings.TrimPrefix(all[len(all)-1], "Bearer ")
	}
	script := `printf '{"status":{"token":"%s|%s|%s|%s"}}' "$KOMANDO_TEST_MARK" "$PATH" "$LD_PRELOAD" "$NODE_OPTIONS"`
	e := func() *ExecAuth { return &ExecAuth{Command: "/bin/sh", Args: []string{"-c", script}} }
	env := []string{"KOMANDO_TEST_MARK=call", "PATH=/agent/bin:/usr/bin:/bin", "LD_PRELOAD=/tmp/x.so", "NODE_OPTIONS=--require /tmp/x.js"} // (macOS drops DYLD_* for /bin/sh by itself)
	if got := run(e(), env); got != "call|/agent/bin:/usr/bin:/bin|/tmp/x.so|--require /tmp/x.js" {
		t.Errorf("the client's environment: %q", got)
	}
	// a recorded PATH: only who, where and which language stay of the
	// caller's environment, and the home is the user's own
	t.Setenv("HOME", "/agent/home")
	home := `printf '{"status":{"token":"%s|%s|%s|%s|%s|%s"}}' "$KOMANDO_TEST_MARK" "$PATH" "$LD_PRELOAD" "$KUBECONFIG" "$LANG" "$HOME"`
	trusted := &ExecAuth{Command: "/bin/sh", Args: []string{"-c", home}, SearchPath: "/usr/bin:/bin"}
	env = append(env, "KUBECONFIG=/agent/kubeconfig", "LANG=C", "HOME=/agent/home", "HTTPS_PROXY=http://127.0.0.1:9")
	if got := run(trusted, env); got != "|/usr/bin:/bin|||C|"+userHome() || userHome() == "/agent/home" {
		t.Errorf("a recorded PATH: %q (home %q)", got, userHome())
	}
	// Check runs before the program and can stop it
	stopped := &ExecAuth{Command: "/bin/sh", Args: []string{"-c", home}, Check: func() error { return errors.New("the file changed") }}
	x := &Context{Cluster: Cluster{Server: srv.URL}}
	x.User.Exec = stopped
	k, _ := New(x, nil)
	if _, err := k.Do(context.Background(), "GET", "/version", nil, nil, ""); err == nil || !strings.Contains(err.Error(), "the file changed") {
		t.Errorf("Check: %v", err)
	}
}
