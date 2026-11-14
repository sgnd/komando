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
// the store's key: an old copy
// of the store put back (a restore from backup, or an attacker's) has a
// lower number than the keychain, and komando stops instead of quietly
// using old servers, rules and pins. It is a second keychain item of this
// home, holding a number, not a secret.

func init() {
	store.GenerationKeeper = store.GenerationKeep{Get: genGet, Ask: genAsk, Set: genSet, Del: genDel}
	// an unset hook counts as an agent: a store starts beside a keychain
	// that cannot be read only for a caller known to be a person or a script
	store.AgentCaller = func() bool { return AgentCall == nil || AgentCall() }
}

// genService names this home's generation item.
func genService() string { return keychainService() + " generation" }

const genTimeout = 5 * time.Second

func genGet() (uint64, bool, error) { return genAsk()() }

// genAsk reads now everything genGet uses (who asks, which keychain and
// tool, this home's item name) and gives the read itself, which uses only
// that: the store's probe runs it on a goroutine it may stop waiting for,
// and that goroutine must read no setting changed after it started.
func genAsk() func() (uint64, bool, error) {
	// no keychain here at all: no count is kept. A keychain that is there
	// but cannot be used (no default keychain for this HOME) may hold one.
	if _, err := keychainTool(countOff()); err != nil {
		return func() (uint64, bool, error) { return 0, false, store.NoKeychain{Err: err} }
	}
	at, kc, service := keychainNow(), keychainFile(), genService()
	return func() (uint64, bool, error) { return genRead(at, kc, service) }
}

// genRead reads the count of item service with the tools at, from the
// keychain file kc ("" for the default keychain).
func genRead(at keychainAt, kc, service string) (uint64, bool, error) {
	if err := at.macDefault(kc); err != nil {
		return 0, false, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), genTimeout)
	defer cancel()
	var b []byte
	switch at.os {
	case "windows":
		v, err := credRead(service)
		if errors.Is(err, errNoKeychainKey) {
			return 0, false, nil
		}
		if err != nil {
			return 0, false, err
		}
		b = v
	default:
		var c *exec.Cmd
		if at.os == "darwin" {
			args := []string{"find-generic-password", "-a", keychainAccount, "-s", service, "-w"}
			if kc != "" {
				args = append(args, kc)
			}
			c = at.cmd(ctx, args...)
		} else {
			c = at.cmd(ctx, "lookup", "service", service, "account", keychainAccount)
		}
		var errb bytes.Buffer
		c.Stderr = &errb
		out, err := c.Output()
		var ee *exec.ExitError
		if err != nil && ctx.Err() == nil && errors.As(err, &ee) {
			code := ee.ExitCode()
			if (at.os == "darwin" && code == 44) || (at.os != "darwin" && code == 1 && len(bytes.TrimSpace(out)) == 0 && errb.Len() == 0) {
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
	kc := keychainFile()
	if _, err := autoKeychainToolFor(countOff(), kc); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), genTimeout)
	defer cancel()
	v := strconv.FormatUint(n, 10)
	switch keychainOS {
	case "darwin":
		// -U replaces the item when it is there
		line := fmt.Sprintf("add-generic-password -U -a %s -s %q -l %q -w %s", keychainAccount, genService(), genService(), v)
		if kc != "" {
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
	kc := keychainFile()
	if _, err := autoKeychainToolFor(keychainOff(), kc); err != nil {
		return
	}
	switch keychainOS {
	case "windows":
		_ = credDelete(genService())
	case "darwin":
		args := []string{"delete-generic-password", "-a", keychainAccount, "-s", genService()}
		if kc != "" {
			args = append(args, kc)
		}
		_ = run(keychainCmd(args...), "")
	default:
		_ = run(keychainCmd("clear", "service", genService(), "account", keychainAccount), "")
	}
}
