package cli

import (
	"io"
	"net/http"
	"os"
	"testing"
)

// personAnswers makes this test a person at a terminal who types lines.
func personAnswers(t *testing.T, lines string) {
	t.Helper()
	saved, savedIn := tcl.terminal, tcl.stdin
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	go func() { io.WriteString(w, lines); w.Close() }()
	tcl.stdin = r
	tcl.terminal = true
	t.Cleanup(func() { tcl.terminal, tcl.stdin = saved, savedIn; r.Close(); resetApproval() })
}

// cluster rm at a person's terminal asks for the object's name, once: a
// wrong name (or the cluster's name) deletes nothing.
func TestClusterRmPersonTypesTheObjectName(t *testing.T) {
	invHome(t)
	l := newApplyLab(t)
	mustRun(t, "import", "kubeconfig", l.kubeconfig(t, "    token: test-token-abcdef"))
	deletes := 0
	inner := l.srv.Config.Handler
	l.srv.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "DELETE" {
			deletes++
			io.WriteString(w, `{}`)
			return
		}
		inner.ServeHTTP(w, r)
	})
	personAnswers(t, "prod\n")
	if _, e := cliRun(t, "cluster", "rm", "prod", "configmap", "web-cfg"); e == nil || e.Code != "POLICY_BLOCKED" {
		t.Fatalf("typing the cluster's name must not delete web-cfg: %+v", e)
	}
	if deletes != 0 {
		t.Fatalf("a wrong name deleted something")
	}
	personAnswers(t, "web-cfg\n")
	d, e := cliRun(t, "cluster", "rm", "prod", "configmap", "web-cfg")
	if e != nil {
		t.Fatalf("the object's name must delete it: %s %s", e.Code, e.Message)
	}
	if deletes != 1 || d["removed"] != "configmap/web-cfg" {
		t.Errorf("deletes %d, %v", deletes, d)
	}
}
