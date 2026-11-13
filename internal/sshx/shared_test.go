package sshx

import (
	"testing"

	"github.com/sgnd/komando/internal/store"
)

// A path through jump hosts dialed with one host-key check is never shared
// with a command that checks keys another way: two calls in one process
// (an app) may use different --host-key-policy values.
func TestChainKeyHasHostKeyPolicy(t *testing.T) {
	hops := []*store.Host{{Name: "bastion", User: "ops", Address: "10.0.0.1"}}
	off, strict, acceptNew := chainKey(nil, hops, "off"), chainKey(nil, hops, "strict"), chainKey(nil, hops, "accept-new")
	if off == strict || off == acceptNew || strict == acceptNew {
		t.Fatalf("policies share a path: off %q, strict %q, accept-new %q", off, strict, acceptNew)
	}
	if chainKey(nil, hops, "") != acceptNew {
		t.Fatal("the default policy (accept-new) got a path of its own")
	}
}
