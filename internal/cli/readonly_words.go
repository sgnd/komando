package cli

import (
	"context"
	"strings"

	"github.com/sgnd/komando/internal/driver"
	"github.com/sgnd/komando/internal/sshx"
)

// docker exec and cluster exec run a command's words as given, with no
// shell added. Their --read-only is held to the same promise as exec's
// (readonly.go): a command that clearly changes something is refused
// (READ_ONLY_VIOLATION), and on a protected target it skips --yes only
// when komando knows every part of it only reads (the allowlist).

// readOnlyWords checks the words of a --read-only command (words, as run
// without a shell) and says whether a protected target still needs --yes.
func readOnlyWords(words []string) (mutating bool, err error) {
	q := make([]string, len(words))
	for i, w := range words {
		q[i] = sshx.Q(w)
	}
	command := strings.Join(q, " ")
	if err := checkReadOnly(command); err != nil {
		return true, err
	}
	return readOnlyMutates(command, nil), nil
}

// clusterExecRisk is how cluster exec rates its command (words): a change,
// unless it is declared --read-only and known to only read.
func clusterExecRisk(words []string, readOnly bool) (driver.Risk, error) {
	if !readOnly {
		return driver.RiskWrite, nil
	}
	mutating, err := readOnlyWords(words)
	if err != nil || mutating {
		return driver.RiskWrite, err
	}
	return driver.RiskRead, nil
}

// dockerExec runs `docker exec TARGET CONTAINER -- COMMAND...` (args): the
// policy sees the command as typed, and --read-only holds it to its promise.
func dockerExec(ctx context.Context, args []string, sudo, readOnly bool) error {
	st, err := loadState()
	if err == nil {
		if err := guard(st, nil, strings.Join(args[2:], " "), false); err != nil {
			return err
		}
	}
	mutating := !readOnly
	if readOnly {
		if mutating, err = readOnlyWords(args[2:]); err != nil {
			return err
		}
	}
	return runOne(ctx, "docker.exec", args[0], dockerExecLine(args[1], args[2:]), sudo, mutating)
}
