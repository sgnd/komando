package vault

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/sgnd/komando/internal/store"
)

// The generation number of a sealed store, kept in the OS keychain beside
// the store's key (docs/design/sync-security.md section 16): an old copy
// of the store put back (a restore from backup, or an attacker's) has a
// lower number than the keychain, and komando stops instead of quietly
// using old servers, rules and pins. It is a second keychain item of this
// home, holding a number, not a secret.

func init() {
	store.GenerationKeeper = store.GenerationKeep{Get: genGet, Set: genSet, Del: genDel}
}

// genService names this home's generation item.
func genService() string { return keychainService() + " generation" }

const genTimeout = 5 * time.Second

func genGet() (uint64, bool, error) {
	if _, err := autoKeychainTool(); err != nil {
		return 0, false, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), genTimeout)
	defer cancel()
	var b []byte
	switch keychainOS {
	case "windows":
		v, err := credRead(genService())
		if errors.Is(err, errNoKeychainKey) {
			return 0, false, nil
		}
		if err != nil {
			return 0, false, err
		}
		b = v
	default:
		var c *exec.Cmd
		if keychainOS == "darwin" {
			args := []string{"find-generic-password", "-a", keychainAccount, "-s", genService(), "-w"}
			if kc := keychainFile(); kc != "" {
				args = append(args, kc)
			}
			c = keychainCmdCtx(ctx, args...)
		} else {
			c = keychainCmdCtx(ctx, "lookup", "service", genService(), "account", keychainAccount)
		}
		var errb bytes.Buffer
		c.Stderr = &errb
		out, err := c.Output()
		var ee *exec.ExitError
		if err != nil && ctx.Err() == nil && errors.As(err, &ee) {
			code := ee.ExitCode()
			if (keychainOS == "darwin" && code == 44) || (keychainOS != "darwin" && code == 1 && len(bytes.TrimSpace(out)) == 0 && errb.Len() == 0) {
				return 0, false, nil
			}
		}
		if ctx.Err() != nil {
			return 0, false, store.ErrKeychainSlow
		}
		if err != nil {
			return 0, false, fmt.Errorf("the keychain did not give the store's change count (%s)", strings.TrimSpace(firstLine(strings.TrimSpace(errb.String()), err.Error())))
		}
		b = out
	}
	n, err := strconv.ParseUint(strings.TrimSpace(string(b)), 10, 64)
	if err != nil {
		return 0, false, errors.New("the keychain holds something else under komando's generation name")
	}
	return n, true, nil
}

func genSet(n uint64) error {
	if _, err := autoKeychainTool(); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), genTimeout)
	defer cancel()
	v := strconv.FormatUint(n, 10)
	switch keychainOS {
	case "darwin":
		// -U replaces the item when it is there
		line := fmt.Sprintf("add-generic-password -U -a %s -s %q -l %q -w %s", keychainAccount, genService(), genService(), v)
		if kc := keychainFile(); kc != "" {
			line += fmt.Sprintf(" %q", kc)
		}
		return run(keychainCmdCtx(ctx, "-i"), line+"\n")
	case "windows":
		return credWrite(genService(), keychainAccount, []byte(v))
	default:
		return run(keychainCmdCtx(ctx, "store", "--label="+genService(), "service", genService(), "account", keychainAccount), v)
	}
}

// genDel removes the generation item: the store's key left the keychain,
// so there is nothing to compare with.
func genDel() {
	if _, err := autoKeychainTool(); err != nil {
		return
	}
	switch keychainOS {
	case "windows":
		_ = credDelete(genService())
	case "darwin":
		args := []string{"delete-generic-password", "-a", keychainAccount, "-s", genService()}
		if kc := keychainFile(); kc != "" {
			args = append(args, kc)
		}
		_ = run(keychainCmd(args...), "")
	default:
		_ = run(keychainCmd("clear", "service", genService(), "account", keychainAccount), "")
	}
}
