package kube

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

// fakeKubelet speaks the WebSocket exec and port-forward protocols the API
// server passes through.
func fakeKubelet(t *testing.T) *Client {
	t.Helper()
	up := websocket.Upgrader{Subprotocols: []string{"v4.channel.k8s.io"}}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer tok" {
			w.WriteHeader(http.StatusForbidden)
			io.WriteString(w, `{"reason":"Forbidden","message":"pods \"x\" is forbidden"}`)
			return
		}
		ws, err := up.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer ws.Close()
		send := func(ch byte, b []byte) { ws.WriteMessage(websocket.BinaryMessage, append([]byte{ch}, b...)) }
		switch {
		case strings.HasSuffix(r.URL.Path, "/exec"):
			cmd := r.URL.Query()["command"]
			if r.URL.Query().Get("stdin") == "true" {
				_, msg, _ := ws.ReadMessage()
				send(1, msg[1:]) // echo stdin
			}
			send(1, []byte("out:"+strings.Join(cmd, " ")))
			send(2, []byte("err"))
			if cmd[len(cmd)-1] == "fail" {
				send(3, []byte(`{"status":"Failure","reason":"NonZeroExitCode","details":{"causes":[{"reason":"ExitCode","message":"3"}]}}`))
			} else {
				send(3, []byte(`{"status":"Success"}`))
			}
		case strings.HasSuffix(r.URL.Path, "/portforward"):
			var port [2]byte
			binary.LittleEndian.PutUint16(port[:], 8080)
			send(0, port[:])
			send(1, port[:])
			for {
				_, msg, err := ws.ReadMessage()
				if err != nil {
					return
				}
				send(0, bytes.ToUpper(msg[1:]))
			}
		}
	}))
	t.Cleanup(srv.Close)
	x := &Context{Namespace: "shop"}
	x.Cluster.Server = srv.URL
	x.User.Token = "tok"
	c, err := New(x, nil)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestExec(t *testing.T) {
	c := fakeKubelet(t)
	var out, errb bytes.Buffer
	if err := c.Exec(context.Background(), ExecOptions{Namespace: "shop", Pod: "api-1", Command: []string{"cat", "/etc/hostname"}, Stdout: &out, Stderr: &errb}); err != nil {
		t.Fatalf("exec: %v", err)
	}
	if out.String() != "out:cat /etc/hostname" || errb.String() != "err" {
		t.Errorf("stdout %q stderr %q", out.String(), errb.String())
	}
	err := c.Exec(context.Background(), ExecOptions{Namespace: "shop", Pod: "api-1", Command: []string{"sh", "fail"}})
	var ee *ExitError
	if !errors.As(err, &ee) || ee.Code != 3 {
		t.Errorf("exit code: %v", err)
	}
	out.Reset()
	if err := c.Exec(context.Background(), ExecOptions{Namespace: "shop", Pod: "api-1", Command: []string{"cat"}, Stdin: strings.NewReader("hello"), Stdout: &out}); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(out.String(), "hello") {
		t.Errorf("stdin: %q", out.String())
	}
	c.token = "bad"
	var ae *APIError
	if err := c.Exec(context.Background(), ExecOptions{Namespace: "shop", Pod: "x", Command: []string{"true"}}); !errors.As(err, &ae) || ae.Code != 403 {
		t.Errorf("forbidden: %v", err)
	}
}

func TestPortForward(t *testing.T) {
	c := fakeKubelet(t)
	a, b := net.Pipe()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	go c.PortForward(ctx, "shop", "api-1", 8080, b)
	a.Write([]byte("ping"))
	buf := make([]byte, 4)
	a.SetReadDeadline(time.Now().Add(3 * time.Second))
	if _, err := io.ReadFull(a, buf); err != nil || string(buf) != "PING" {
		t.Errorf("forwarded %q %v", buf, err)
	}
	a.Close()
}

func TestBuiltinTokens(t *testing.T) {
	t.Setenv("AWS_ACCESS_KEY_ID", "AKIDTEST")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "secret")
	t.Setenv("AWS_SESSION_TOKEN", "")
	t.Setenv("AWS_PROFILE", "")
	t.Setenv("AWS_CONFIG_FILE", "/nonexistent")
	t.Setenv("AWS_SHARED_CREDENTIALS_FILE", "/nonexistent")
	e := &ExecAuth{Command: "/usr/local/bin/aws", Args: []string{"--region", "eu-west-1", "eks", "get-token", "--cluster-name", "prod", "--output", "json"}}
	tok, ok, err := builtinToken(context.Background(), e)
	if !ok || err != nil || !strings.HasPrefix(tok, "k8s-aws-v1.") {
		t.Fatalf("eks token %q %v %v", tok, ok, err)
	}
	raw, _ := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(tok, "k8s-aws-v1."))
	u, err := url.Parse(string(raw))
	if err != nil {
		t.Fatal(err)
	}
	q := u.Query()
	if u.Host != "sts.eu-west-1.amazonaws.com" || q.Get("Action") != "GetCallerIdentity" || q.Get("X-Amz-Expires") != "60" ||
		!strings.Contains(q.Get("X-Amz-SignedHeaders"), "x-k8s-aws-id") {
		t.Errorf("presigned URL %s", raw)
	}
	if _, ok, _ := builtinToken(context.Background(), &ExecAuth{Command: "kubelogin", Args: []string{"get-token"}}); ok {
		t.Error("other plugins must run as configured")
	}
	if _, ok, _ := builtinToken(context.Background(), &ExecAuth{Command: "aws", Args: []string{"sts", "get-caller-identity"}}); ok {
		t.Error("aws without eks get-token is not ours")
	}
}
