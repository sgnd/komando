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
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"github.com/moby/spdystream"
)

// fakeKubelet speaks the streaming protocols the API server passes
// through: WebSocket (v5 exec, v4 port-forward) like Kubernetes 1.30 and
// later, or with old, only SPDY, refusing the WebSocket like 1.29 does.
func fakeKubelet(t *testing.T, old bool) *Client {
	t.Helper()
	up := websocket.Upgrader{Subprotocols: []string{"v5.channel.k8s.io", "v4.channel.k8s.io"}}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer tok" {
			w.WriteHeader(http.StatusForbidden)
			io.WriteString(w, `{"reason":"Forbidden","message":"pods \"x\" is forbidden"}`)
			return
		}
		if strings.EqualFold(r.Header.Get("Upgrade"), "SPDY/3.1") {
			fakeSPDY(t, w, r)
			return
		}
		if old {
			w.WriteHeader(http.StatusBadRequest)
			io.WriteString(w, `{"reason":"BadRequest","message":"Upgrade request required"}`)
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
			if ws.Subprotocol() != "v5.channel.k8s.io" {
				t.Errorf("exec over %q", ws.Subprotocol())
			}
			cmd := r.URL.Query()["command"]
			if r.URL.Query().Get("stdin") == "true" {
				var in []byte
				for { // until the v5 close message
					_, msg, err := ws.ReadMessage()
					if err != nil || msg[0] == 255 {
						break
					}
					in = append(in, msg[1:]...)
				}
				send(1, in) // echo stdin
			}
			send(1, []byte("out:"+strings.Join(cmd, " ")))
			send(2, []byte("err"))
			if cmd[len(cmd)-1] == "fail" {
				send(3, []byte(exitStatus3))
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

const exitStatus3 = `{"status":"Failure","reason":"NonZeroExitCode","details":{"causes":[{"reason":"ExitCode","message":"3"}]}}`

// fakeSPDY is the kubelet's SPDY side: exec (v4.channel.k8s.io) and
// port-forward (portforward.k8s.io).
func fakeSPDY(t *testing.T, w http.ResponseWriter, r *http.Request) {
	exec := strings.HasSuffix(r.URL.Path, "/exec")
	want := "portforward.k8s.io"
	if exec {
		want = "v4.channel.k8s.io"
	}
	if !slices.Contains(r.Header.Values("X-Stream-Protocol-Version"), want) {
		t.Errorf("SPDY protocols %v", r.Header.Values("X-Stream-Protocol-Version"))
	}
	conn, _, err := w.(http.Hijacker).Hijack()
	if err != nil {
		return
	}
	io.WriteString(conn, "HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: SPDY/3.1\r\nX-Stream-Protocol-Version: "+want+"\r\n\r\n")
	sc, err := spdystream.NewConnection(conn, true)
	if err != nil {
		return
	}
	defer sc.Close()
	streams := make(chan *spdystream.Stream, 8)
	go sc.Serve(func(s *spdystream.Stream) {
		s.SendReply(http.Header{}, false)
		streams <- s
	})
	q := r.URL.Query()
	byType := map[string]*spdystream.Stream{}
	need := 2 // error, data
	if exec {
		need = 2 // error, stdout
		if q.Get("stdin") == "true" {
			need++
		}
		if q.Get("stderr") == "true" || q.Get("tty") == "true" { // stderr, or resize with a terminal
			need++
		}
	}
	for len(byType) < need {
		select {
		case s := <-streams:
			byType[s.Headers().Get("streamType")] = s
		case <-time.After(3 * time.Second):
			t.Errorf("streams %v", byType)
			return
		}
	}
	if !exec {
		if byType["data"].Headers().Get("port") != "8080" {
			t.Errorf("port header %v", byType["data"].Headers())
		}
		b, _ := io.ReadAll(byType["data"]) // until the client half-closes
		byType["data"].Write(bytes.ToUpper(b))
		byType["data"].Close()
		byType["error"].Close()
		time.Sleep(50 * time.Millisecond)
		return
	}
	cmd := q["command"]
	if in := byType["stdin"]; in != nil {
		b, _ := io.ReadAll(in) // until the client half-closes
		byType["stdout"].Write(b)
	}
	byType["stdout"].Write([]byte("out:" + strings.Join(cmd, " ")))
	if e := byType["stderr"]; e != nil {
		e.Write([]byte("err"))
		e.Close()
	}
	byType["stdout"].Close()
	if cmd[len(cmd)-1] == "fail" {
		byType["error"].Write([]byte(exitStatus3))
	}
	byType["error"].Close()
	time.Sleep(50 * time.Millisecond)
}

func TestExec(t *testing.T) {
	t.Run("websocket", func(t *testing.T) { testExec(t, fakeKubelet(t, false)) })
	t.Run("spdy", func(t *testing.T) { testExec(t, fakeKubelet(t, true)) })
}

func testExec(t *testing.T, c *Client) {
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
	if err := c.Exec(context.Background(), ExecOptions{Namespace: "shop", Pod: "api-1", Command: []string{"cat"}, Stdin: strings.NewReader("hellos"), Stdout: &out}); err != nil {
		t.Fatal(err)
	}
	if out.String() != "hellosout:cat" {
		t.Errorf("stdin: %q", out.String())
	}
	c.token = "bad"
	var ae *APIError
	if err := c.Exec(context.Background(), ExecOptions{Namespace: "shop", Pod: "x", Command: []string{"true"}}); !errors.As(err, &ae) || ae.Code != 403 {
		t.Errorf("forbidden: %v", err)
	}
}

func TestPortForward(t *testing.T) {
	c := fakeKubelet(t, false)
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

func TestPortForwardSPDY(t *testing.T) {
	c := fakeKubelet(t, true)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	errc := make(chan error, 1)
	go func() {
		b, err := ln.Accept()
		if err == nil {
			err = c.PortForward(ctx, "shop", "api-1", 8080, b)
		}
		errc <- err
	}()
	a, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	a.Write([]byte("ping"))
	a.(*net.TCPConn).CloseWrite() // the pod sees the end, then answers
	a.SetReadDeadline(time.Now().Add(3 * time.Second))
	got, err := io.ReadAll(a)
	if err != nil || string(got) != "PING" {
		t.Errorf("forwarded %q %v", got, err)
	}
	if err := <-errc; err != nil {
		t.Errorf("port-forward: %v", err)
	}
}

func TestTrySPDY(t *testing.T) {
	for _, c := range []struct {
		err  error
		want bool
	}{
		{&APIError{Code: 400}, true}, {&APIError{Code: 403}, true},
		{errOldProtocol, true}, {websocket.ErrBadHandshake, true}, {errors.New("dial tcp: refused"), false}, {nil, false},
	} {
		if got := trySPDY(c.err); got != c.want {
			t.Errorf("trySPDY(%v) = %v", c.err, got)
		}
	}
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
