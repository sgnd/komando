package cli

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"regexp"
	"strings"
)

// formRunAll runs the commands here, each shown first, until one fails:
// its exit code and, when the one that failed is the check after an add
// (test, login, vpn up, cluster status), the last line it printed.
func formRunAll(cl *call, self string, cmds [][]string) (int, string, error) {
	for i, c := range cmds {
		fmt.Fprintf(cl.out.Err, "$ komando %s\n", pickCommandLine(c))
		var buf bytes.Buffer
		x := pickCommand(cl, self, c)
		x.Stderr = io.MultiWriter(cl.out.Err, &buf)
		code, err := formExitCode(x.Run())
		if err != nil || code == 0 {
			if err != nil {
				return 0, "", err
			}
			continue
		}
		reason := ""
		if i == len(cmds)-1 && i > 0 && formIsCheck(c) {
			reason = formLastLine(buf.String())
			if reason == "" {
				reason = "komando could not reach it"
			}
		}
		return code, reason, nil
	}
	return 0, "", nil
}

func formExitCode(err error) (int, error) {
	var ee *exec.ExitError
	switch {
	case err == nil:
		return 0, nil
	case errors.As(err, &ee):
		return ee.ExitCode(), nil
	}
	return 0, err
}

// formIsCheck: the command shows that what was just added works.
func formIsCheck(c []string) bool {
	switch {
	case len(c) >= 1 && (c[0] == "test" || c[0] == "login"):
		return true
	case len(c) >= 2 && (c[0] == "vpn" && c[1] == "up" || c[0] == "cluster" && c[1] == "status"):
		return true
	}
	return false
}

// formRemoveCmd takes out again what the add in cmds added (host rm, conn
// rm, vpn rm), or nil when it is not one add of one name.
func formRemoveCmd(cmds [][]string) []string {
	for _, c := range cmds {
		if len(c) >= 3 && c[1] == "add" && (c[0] == "host" || c[0] == "conn" || c[0] == "vpn") {
			return []string{c[0], "rm", c[2]}
		}
	}
	return nil
}

var formANSI = regexp.MustCompile(`\x1b\[[0-9;]*[A-Za-z]`)

// formLastLine is the last line of text with something in it, without
// colors.
func formLastLine(s string) string {
	lines := strings.Split(formANSI.ReplaceAllString(s, ""), "\n")
	for i := len(lines) - 1; i >= 0; i-- {
		if l := strings.TrimSpace(lines[i]); l != "" {
			return l
		}
	}
	return ""
}
