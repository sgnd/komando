package cli

import "testing"

// A shell or sudo that cannot find docker gives DOCKER_MISSING, not a
// generic DOCKER_ERROR, whatever it prints.
func TestDockerMissingFromShellText(t *testing.T) {
	for _, c := range []struct {
		msg  string
		code int
	}{
		{"", 127},
		{"bash: docker: command not found", 127},
		{"bash: line 1: docker: command not found", 127},
		{"zsh:1: command not found: docker", 127},
		{"sh: 1: docker: not found", 127},
		{"sh: docker: not found", 127},
		{"sudo: docker: command not found", 1},
		{"komando: docker not found", 127},
	} {
		if e := dockerErr(c.msg, c.code); e.Code != "DOCKER_MISSING" {
			t.Errorf("%q (exit %d): got %s, want DOCKER_MISSING", c.msg, c.code, e.Code)
		}
	}
	for _, msg := range []string{"Error: No such container: docker", "unknown flag: --docker", "image docker:latest not found"} {
		if e := dockerErr(msg, 1); e.Code == "DOCKER_MISSING" {
			t.Errorf("%q: got DOCKER_MISSING", msg)
		}
	}
}
