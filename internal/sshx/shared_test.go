package sshx

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/sgnd/komando/internal/store"
)

// A path through jump hosts dialed with one host-key check is never shared
// with a command that checks keys another way: two calls in one process
// (an app) may use different --host-key-policy values.
func TestChainKeyHasHostKeyPolicy(t *testing.T) {
	hops := []*store.Host{{Name: "bastion", User: "ops", Address: "10.0.0.1"}}
	off, strict, acceptNew := chainKey("", nil, hops, "off"), chainKey("", nil, hops, "strict"), chainKey("", nil, hops, "accept-new")
	if off == strict || off == acceptNew || strict == acceptNew {
		t.Fatalf("policies share a path: off %q, strict %q, accept-new %q", off, strict, acceptNew)
	}
	if chainKey("", nil, hops, "") != acceptNew {
		t.Fatal("the default policy (accept-new) got a path of its own")
	}
}

type ownerKey struct{}

// A path through jump hosts serves only the command that opened it
// (ChainOwner): a person's command and an AI agent's, dialing the same
// server behind the same bastion at the same time in one process (an
// app), each log in to the bastion on a path of their own, while the
// servers of one command still share one (run with -race).
func TestChainServesOneOwner(t *testing.T) {
	dialHome(t)
	saved := ChainOwner
	ChainOwner = func(ctx context.Context) string { s, _ := ctx.Value(ownerKey{}).(string); return s }
	t.Cleanup(func() { ChainOwner = saved })
	key := clientKey(t)
	bh, bp := testSSHD(t, newSigner(t))
	th, tp := testSSHD(t, newSigner(t))
	tgt := &store.Host{Name: "target", Address: th, Port: tp, User: "u", Identity: key, Via: "bastion"}
	st := newState(&store.Host{Name: "bastion", Address: bh, Port: bp, User: "u", Identity: key}, tgt)
	o := Options{ConnectTimeout: 5 * time.Second, HostKeyPolicy: "off"}

	owners := []string{"person command 1", "agent command 2", "person command 1", "agent command 2"}
	clients := make([]*Client, len(owners))
	errs := make([]error, len(owners))
	var wg sync.WaitGroup
	for i, owner := range owners {
		wg.Add(1)
		go func() {
			defer wg.Done()
			clients[i], errs[i] = Dial(context.WithValue(context.Background(), ownerKey{}, owner), st, tgt, o)
		}()
	}
	wg.Wait()
	for i, c := range clients {
		if errs[i] != nil {
			t.Fatalf("%s: %v", owners[i], errs[i])
		}
		defer c.Close()
	}
	if clients[0].chain == clients[1].chain {
		t.Error("an agent's command was handed the path a person's command opened")
	}
	if clients[0].chain != clients[2].chain || clients[1].chain != clients[3].chain {
		t.Error("the servers of one command did not share its path")
	}
	// each command's keys leave no dial lock behind
	chains.Lock()
	left := len(chains.dialing)
	chains.Unlock()
	if left != 0 {
		t.Errorf("%d dial locks left after the dials", left)
	}
}
