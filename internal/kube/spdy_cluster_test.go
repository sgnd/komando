package kube

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"
)

// TestSPDYCluster runs every SPDY path against a real Kubernetes 1.29
// cluster (make e2e starts one): exec with exit code and stderr, stdin
// that ends, a terminal with a resize, and port-forward. The pod is the
// e2e "tools" deployment (busybox httpd on 8080).
func TestSPDYCluster(t *testing.T) {
	p := os.Getenv("KOMANDO_E2E_OLD_KUBECONFIG")
	if p == "" {
		t.Skip("set KOMANDO_E2E_OLD_KUBECONFIG to a Kubernetes 1.29 kubeconfig (make e2e does)")
	}
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := Parse(b)
	if err != nil {
		t.Fatal(err)
	}
	x, err := cfg.Resolve("")
	if err != nil {
		t.Fatal(err)
	}
	c, err := New(x, nil)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	var pods struct {
		Items []struct{ Metadata struct{ Name string } }
	}
	if err := c.Get(ctx, "/api/v1/namespaces/default/pods", url.Values{"labelSelector": {"app=tools"}}, &pods); err != nil || len(pods.Items) == 0 {
		t.Fatalf("tools pod: %v", err)
	}
	pod := pods.Items[0].Metadata.Name
	// the cluster must refuse the WebSocket, or this test proves nothing
	ws, _, err := c.dialWS(ctx, "/api/v1/namespaces/default/pods/"+pod+"/exec", url.Values{"command": {"true"}, "stdout": {"true"}}, []string{"v5.channel.k8s.io"})
	if err == nil {
		ws.Close()
		t.Fatal("this cluster speaks WebSocket v5; use one before 1.30")
	}

	var out, errb bytes.Buffer
	err = c.Exec(ctx, ExecOptions{Namespace: "default", Pod: pod, Command: []string{"sh", "-c", "cat /www/index.html; echo e >&2; exit 3"}, Stdout: &out, Stderr: &errb})
	var ee *ExitError
	if !errors.As(err, &ee) || ee.Code != 3 || out.String() != "hello-from-pod\n" || errb.String() != "e\n" {
		t.Errorf("exec: %q %q %v", out.String(), errb.String(), err)
	}

	out.Reset()
	err = c.Exec(ctx, ExecOptions{Namespace: "default", Pod: pod, Command: []string{"wc", "-c"}, Stdin: strings.NewReader("12345"), Stdout: &out})
	if err != nil || strings.TrimSpace(out.String()) != "5" {
		t.Errorf("stdin that ends: %q %v", out.String(), err)
	}

	out.Reset()
	pr, pw := io.Pipe() // a person's keyboard: open until the command ends
	defer pw.Close()
	size := make(chan TermSize, 1)
	size <- TermSize{Width: 77, Height: 22}
	err = c.Exec(ctx, ExecOptions{Namespace: "default", Pod: pod, Command: []string{"sh", "-c", "sleep 1; stty size"}, TTY: true, Stdin: pr, Stdout: &out, Resize: size})
	if err != nil || !strings.Contains(out.String(), "22 77") {
		t.Errorf("terminal: %q %v", out.String(), err)
	}

	a, b2 := net.Pipe()
	go c.forwardSPDY(ctx, "/api/v1/namespaces/default/pods/"+pod+"/portforward", 8080, b2)
	a.Write([]byte("GET / HTTP/1.0\r\n\r\n"))
	a.SetReadDeadline(time.Now().Add(10 * time.Second))
	got, _ := io.ReadAll(a)
	if !bytes.Contains(got, []byte("hello-from-pod")) {
		t.Errorf("port-forward: %q", got)
	}
}
