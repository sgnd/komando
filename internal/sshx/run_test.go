package sshx

import (
	"bytes"
	"io"
	"strings"
	"testing"

	"github.com/sgnd/komando/internal/store"
)

func TestBuildCommandRejectsBadEnvKeys(t *testing.T) {
	for _, k := range []string{"A;reboot;B", "1X", "A B", "A=B", "$(id)"} {
		if _, _, err := BuildCommand(nil, RunRequest{Command: "true", Env: map[string]string{k: "1"}}); err == nil {
			t.Errorf("env key %q must be refused", k)
		}
	}
	cmd, _, err := BuildCommand(&Client{Host: &store.Host{Env: map[string]string{"APP_ENV": "prod"}}}, RunRequest{Command: "true"})
	if err != nil || !strings.Contains(cmd, "export APP_ENV='prod'; ") {
		t.Errorf("valid env key: %q %v", cmd, err)
	}
}

// readAll collects what the gate lets through to the command's stdin.
func readAll(g *sudoGate) <-chan string {
	ch := make(chan string, 1)
	go func() { b, _ := io.ReadAll(g.stdin); ch <- string(b) }()
	return ch
}

func TestSudoGateNoPrompt(t *testing.T) {
	var out bytes.Buffer
	g := newSudoGate(&out, []byte("s3cret\n"), []byte("input"))
	got := readAll(g)
	g.Write([]byte(sudoReady + "\nwarning: x\n"))
	if s := <-got; s != "input" {
		t.Errorf("stdin = %q: the password must not reach a command sudo did not ask for", s)
	}
	g.flush()
	g.close()
	if out.String() != "warning: x\n" {
		t.Errorf("stderr = %q", out.String())
	}
}

func TestSudoGatePrompt(t *testing.T) {
	var out bytes.Buffer
	g := newSudoGate(&out, []byte("s3cret\n"), []byte("input"))
	got := readAll(g)
	g.Write([]byte(sudoPrompt))
	g.Write([]byte(sudoReady + "\r\n"))
	if s := <-got; s != "s3cret\ninput" {
		t.Errorf("stdin = %q", s)
	}
	g.flush()
	g.close()
	if out.Len() != 0 {
		t.Errorf("markers must be removed, stderr = %q", out.String())
	}
}

func TestSudoGateWrongPassword(t *testing.T) {
	var out bytes.Buffer
	g := newSudoGate(&out, []byte("wrong\n"), []byte("input"))
	g.Write([]byte(sudoPrompt))
	pass := make([]byte, len("wrong\n")) // sudo reads the password before it asks again
	if _, err := io.ReadFull(g.stdin, pass); err != nil || string(pass) != "wrong\n" {
		t.Fatalf("password = %q %v", pass, err)
	}
	got := readAll(g)
	g.Write([]byte("Sorry, try again.\n" + sudoPrompt))
	if s := <-got; s != "" {
		t.Errorf("stdin = %q: a second prompt must get end of input, not the command's stdin", s)
	}
	g.flush()
	g.close()
	if out.String() != "Sorry, try again.\n" {
		t.Errorf("stderr = %q", out.String())
	}
}
