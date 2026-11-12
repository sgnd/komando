package cachex

import (
	"context"
	"sort"
	"strconv"
	"strings"
	"sync"

	"github.com/redis/go-redis/v9"

	"github.com/sgnd/komando/internal/out"
)

// In a Redis Cluster each master holds part of the keys: listing scans
// every master, and the summary adds up what each one has.

// clusterKeys scans every master for pattern, up to limit keys in all.
func clusterKeys(ctx context.Context, cc *redis.ClusterClient, pattern string, limit int) ([]string, bool, error) {
	var mu sync.Mutex
	keys := []string{}
	more := false
	err := cc.ForEachMaster(ctx, func(ctx context.Context, node *redis.Client) error {
		k, m, err := Keys(ctx, node, pattern, limit)
		mu.Lock()
		defer mu.Unlock()
		keys = append(keys, k...)
		more = more || m
		return err
	})
	if err != nil {
		return nil, false, cmdErr(err)
	}
	sort.Strings(keys)
	if len(keys) > limit {
		keys, more = keys[:limit], true
	}
	return keys, more, nil
}

// clusterInfo is one master's INFO with the counts of all masters added
// up (memory, clients, hits, keys), and the cluster's own state.
func clusterInfo(ctx context.Context, cc *redis.ClusterClient, section string) (map[string]map[string]string, error) {
	var mu sync.Mutex
	var all []map[string]map[string]string
	err := cc.ForEachMaster(ctx, func(ctx context.Context, node *redis.Client) error {
		info, err := Info(ctx, node, section)
		mu.Lock()
		all = append(all, info)
		mu.Unlock()
		return err
	})
	if err != nil {
		return nil, cmdErr(err)
	}
	res := sumInfo(all)
	if s, err := cc.ClusterInfo(ctx).Result(); err == nil {
		res["cluster"] = map[string]string{"masters": strconv.Itoa(len(all))}
		for _, line := range strings.Split(s, "\n") {
			if k, v, ok := strings.Cut(strings.TrimSpace(line), ":"); ok {
				res["cluster"][k] = v
			}
		}
	}
	return res, nil
}

// summed are the INFO fields a cluster's summary adds up over its masters.
var summed = map[string][]string{
	"memory":  {"used_memory", "maxmemory"},
	"clients": {"connected_clients"},
	"stats":   {"keyspace_hits", "keyspace_misses"},
}

func sumInfo(all []map[string]map[string]string) map[string]map[string]string {
	if len(all) == 0 {
		return map[string]map[string]string{}
	}
	res := map[string]map[string]string{}
	for sec, kv := range all[0] {
		res[sec] = map[string]string{}
		for k, v := range kv {
			res[sec][k] = v
		}
	}
	for sec, keys := range summed {
		for _, k := range keys {
			var total int64
			found := false
			for _, info := range all {
				if v, ok := info[sec][k]; ok {
					n, _ := strconv.ParseInt(v, 10, 64)
					total, found = total+n, true
				}
			}
			if found {
				res[sec][k] = strconv.FormatInt(total, 10)
			}
		}
	}
	keys, expires := int64(0), int64(0) // keyspace: db0:keys=12,expires=3,avg_ttl=0
	for _, info := range all {
		for _, kv := range strings.Split(info["keyspace"]["db0"], ",") {
			k, v, _ := strings.Cut(kv, "=")
			n, _ := strconv.ParseInt(v, 10, 64)
			switch k {
			case "keys":
				keys += n
			case "expires":
				expires += n
			}
		}
	}
	if keys > 0 || res["keyspace"] != nil {
		res["keyspace"] = map[string]string{"db0": "keys=" + strconv.FormatInt(keys, 10) + ",expires=" + strconv.FormatInt(expires, 10)}
	}
	return res
}

// clusterRun answers DBSIZE for the whole Cluster (the sum over its
// masters) and refuses the other whole-key-space commands, which would
// reach one master only.
func clusterRun(ctx context.Context, cc *redis.ClusterClient, args []string) (any, error) {
	if err := ClusterWideProblem(args); err != nil {
		return nil, err
	}
	var mu sync.Mutex
	var total int64
	err := cc.ForEachMaster(ctx, func(ctx context.Context, node *redis.Client) error {
		n, err := node.DBSize(ctx).Result()
		mu.Lock()
		total += n
		mu.Unlock()
		return err
	})
	if err != nil {
		return nil, cmdErr(err)
	}
	return total, nil
}

// ClusterWideProblem refuses a whole-key-space command other than DBSIZE
// for a Redis Cluster, before any approval is asked for it.
func ClusterWideProblem(args []string) error {
	if len(args) == 0 {
		return nil
	}
	cmd := strings.ToUpper(args[0])
	if !clusterWide[cmd] || cmd == "DBSIZE" {
		return nil
	}
	hint := "list keys with `komando cache keys CONN 'pattern*'`, which scans every master"
	if cmd == "FLUSHALL" || cmd == "FLUSHDB" || cmd == "SWAPDB" {
		hint = "to run it on every master, add each master as its own conn (without ?cluster=1) and run it on each, with the user's yes"
	}
	return out.Errf(out.ExitUsage, "NOT_SUPPORTED", hint,
		"%s in a Redis Cluster reaches one master only, so it would cover part of the keys", cmd)
}
