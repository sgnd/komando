package cli

import (
	"context"
	"fmt"
	"sync"

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

// enter counts cl among the running calls; leave takes it out.
func (cl *call) enter() {
	running.Lock()
	defer running.Unlock()
	if running.calls == nil {
		running.calls = map[*call]bool{}
	}
	running.calls[cl] = true
}

func (cl *call) leave() {
	running.Lock()
	defer running.Unlock()
	delete(running.calls, cl)
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
	// a host key pinned on first use goes into the audit log and the JSON
	// output (meta.host_keys_pinned) of the call that connected; sshx
	// tells the person on stderr
	sshx.HostKeyPinned = func(ctx context.Context, k sshx.NewHostKey) {
		calls := []*call{callFrom(ctx)}
		if calls[0] == nil { // a connection made outside a command: every call hears of it
			calls = runningCalls()
		}
		for i, cl := range calls {
			cl.out.HostKeyPinned(out.HostKey{Host: k.Host, Address: k.Address, Type: k.Type, Fingerprint: k.Fingerprint})
			if i == 0 {
				auditPinnedKey(cl, k)
			}
		}
	}
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
	netx.LockBusy = func(name string) {
		for _, cl := range runningCalls() {
			noticef(cl, "another komando command is connecting or disconnecting vpn %s (a sign-in may be waiting in its browser window); waiting for it to end", name)
		}
	}
	netx.StartSession = func(ctx context.Context, name string) error {
		cl := callFrom(ctx)
		if cl == nil {
			cl = soleCall()
		}
		if cl == nil {
			return fmt.Errorf("vpn %s: no komando command to start it for", name)
		}
		return startVpnFor(cl, ctx, name)
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

// storeMu guards storeDryRun.
var storeMu sync.Mutex

// storeDryRun sets store.DryRun and store.AllowOldCopy (a dry run may
// look at an old copy: it changes nothing). They are still the process's
// (docs/design/engine-per-call.md), so they are written only when they
// change: calls that are no dry run never touch them.
func storeDryRun(dry bool) {
	storeMu.Lock()
	defer storeMu.Unlock()
	if store.DryRun != dry {
		store.DryRun = dry
	}
	if store.AllowOldCopy != dry {
		store.AllowOldCopy = dry
	}
}
