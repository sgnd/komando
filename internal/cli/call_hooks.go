package cli

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"sync"
	"sync/atomic"

	"github.com/sgnd/komando/internal/netx"
	"github.com/sgnd/komando/internal/out"
	"github.com/sgnd/komando/internal/sshx"
	"github.com/sgnd/komando/internal/store"
	"github.com/sgnd/komando/internal/vault"
)

// The packages under the cli (sshx, vault, netx) call back into it
// through hooks they keep in package variables: sshx.HostKeyPinned,
// vault.OnResolve and the others below. A hook gets no call, so it cannot
// tell which call it works for. Until those packages take the call along
// (docs/design/engine-per-call.md), each hook gives the safest answer over
// every call running in the process: a value read for one call is hidden
// in all of them, an AI agent's call among them makes a guard answer as for
// an agent, and a person is asked at the terminal only while theirs is
// the one call running.

// running are the calls that run a command in this process now.
var running struct {
	sync.Mutex
	calls map[*call]bool
}

// commands numbers the commands of the process (call.command).
var commands atomic.Uint64

// enter counts cl among the running calls, for a new command; leave takes
// it out. A value the command before hid with AddValue is forgotten here,
// before the call counts: from now on another call's vault.OnResolve adds
// to it, and nothing drops what it added until the next command.
func (cl *call) enter() {
	cl.out.ForgetAdded()
	cl.command.Store(commands.Add(1))
	running.Lock()
	defer running.Unlock()
	if running.calls == nil {
		running.calls = map[*call]bool{}
	}
	running.calls[cl] = true
}

func (cl *call) leave() {
	running.Lock()
	delete(running.calls, cl)
	running.Unlock()
	cl.command.Store(0)
}

// runningCalls are the calls running now.
func runningCalls() []*call {
	running.Lock()
	defer running.Unlock()
	calls := make([]*call, 0, len(running.calls))
	for c := range running.calls {
		calls = append(calls, c)
	}
	return calls
}

// soleCall is the call running now when it is the only one, else nil.
func soleCall() *call {
	if calls := runningCalls(); len(calls) == 1 {
		return calls[0]
	}
	return nil
}

func init() {
	// a value a reference resolved to is hidden in output, as vault values
	// are: in every running call, so no call shows another's
	vault.OnResolve = func(v string) {
		for _, cl := range runningCalls() {
			cl.out.AddValue(v)
		}
	}
	vault.RefGuard = func(kind, name string) error {
		if kind == "secret" {
			return reservedSecret(name)
		}
		for _, cl := range runningCalls() {
			if err := refGuard(cl, kind, name); err != nil {
				return err
			}
		}
		return nil
	}
	// an agent's KOMANDO_KEYCHAIN=off keeps the old-copy check
	vault.AgentCall = agentCallRunning
	store.OldCopyOK = oldCopyAllowed
	// a server's env values from the vault go along only when every
	// running call may send them
	sshx.HostSecretEnv = func(c *sshx.Client) bool {
		for _, cl := range runningCalls() {
			if !hostSecretEnv(cl, c) {
				return false
			}
		}
		return true
	}
	// a host key is pinned on first use only for a connection whose
	// context carries its call: the pin goes into that call's audit log
	// and JSON output (meta.host_keys_pinned), never another call's
	sshx.MayPin = func(ctx context.Context) error {
		if callFrom(ctx) == nil {
			return errNoCall("pin a new server's host key")
		}
		return nil
	}
	// sshx tells the person on stderr
	sshx.HostKeyPinned = func(ctx context.Context, k sshx.NewHostKey) {
		cl := callFrom(ctx)
		if cl == nil {
			return // MayPin refused it already
		}
		cl.out.HostKeyPinned(out.HostKey{Host: k.Host, Address: k.Address, Type: k.Type, Fingerprint: k.Fingerprint})
		auditPinnedKey(cl, k)
	}
	// a path through jump hosts serves only the command that opened it
	sshx.ChainOwner = chainOwner
	// HOSTKEY_MISMATCH tells a person how to check and re-trust the key;
	// an agent or a script is told to report it
	sshx.PersonAtTerminal = func() bool {
		cl := soleCall()
		return cl != nil && cl.interactive()
	}
	// a person at the terminal answers what an SSH login asks (a password,
	// a two-factor code); nobody else is asked
	sshx.Asker = func() func(host, text string, hidden bool) (string, error) {
		cl := soleCall()
		if cl == nil || !cl.interactive() {
			return nil
		}
		return func(host, text string, hidden bool) (string, error) { return askSSH(cl, host, text, hidden) }
	}
	// a note of the store (a new store beside a keychain that could not be
	// read) goes to the stderr of every running call
	store.Notice = storeNotice
	netx.LockBusy = func(name string) {
		for _, cl := range runningCalls() {
			noticef(cl, "another komando command is connecting or disconnecting vpn %s (a sign-in may be waiting in its browser window); waiting for it to end", name)
		}
	}
	// a dry run's VPN use changes nothing in the runtime record; with no
	// call in the context nothing is written either (no other call's
	// --dry-run is read)
	netx.WriteFor = func(ctx context.Context) store.Write {
		cl := callFrom(ctx)
		if cl == nil {
			return store.Preview()
		}
		return cl.storeWrite()
	}
	netx.StartSession = func(ctx context.Context, name string) error {
		cl := callFrom(ctx)
		if cl == nil {
			return errNoCall("start vpn " + name)
		}
		return startVpnFor(cl, ctx, name)
	}
}

// errNoCall is the error of a hook reached with a context that carries no
// call: a bug in komando. The hook refuses rather than answer for another
// running call.
func errNoCall(what string) error {
	return fmt.Errorf("komando was asked to %s outside a command, and refused; this is a bug in komando: report it at https://github.com/sgnd/komando/issues", what)
}

// unowned numbers the paths through jump hosts opened outside a command
// (chainOwner): each is its own.
var unowned atomic.Uint64

// chainOwner is sshx.ChainOwner: the command of ctx's call. A path opened
// with no command running in the context is shared with nobody.
func chainOwner(ctx context.Context) string {
	if cl := callFrom(ctx); cl != nil {
		if n := cl.command.Load(); n != 0 {
			return "command " + strconv.FormatUint(n, 10)
		}
	}
	return "nobody " + strconv.FormatUint(unowned.Add(1), 10)
}

// storeNotice is store.Notice: the note goes to the stderr of every
// running call, people and scripts alike (it says how the store is
// guarded), or to the process's when none runs.
func storeNotice(msg string) {
	line := "komando: " + cleanText(msg)
	calls := runningCalls()
	if len(calls) == 0 {
		fmt.Fprintln(os.Stderr, line)
	}
	for _, cl := range calls {
		fmt.Fprintln(cl.out.Err, line)
	}
}

// agentCallRunning is vault.AgentCall: an AI agent's call is among the
// running calls. A call counts from the first step of its command
// (execute), before anything can open the store or the vault.
func agentCallRunning() bool {
	for _, cl := range runningCalls() {
		if cl.isAgent() {
			return true
		}
	}
	return false
}

// oldCopyAllowed is store.OldCopyOK: an old copy of the store may be
// opened to be looked at only while every running call may look at one
// (doctor, a dry run). One call's allowance never opens it for a call
// beside it; the store hands a look-only handle only to a caller that
// may look (store.cachedDB).
func oldCopyAllowed() bool {
	calls := runningCalls()
	for _, cl := range calls {
		if !cl.oldCopy.Load() {
			return false
		}
	}
	return len(calls) > 0
}
