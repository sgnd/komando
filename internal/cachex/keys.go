package cachex

import (
	"context"
	"errors"
	"time"

	"github.com/redis/go-redis/v9"
)

// KeyInfo is a listed key with its type and time to live, never its value.
type KeyInfo struct {
	Key  string  `json:"key"`
	Type *string `json:"type"`        // the store's own type name; null = unknown
	TTL  *int64  `json:"ttl_seconds"` // -1 = no expiry; null = unknown
}

// Keys lists keys matching pattern with SCAN (never KEYS), up to limit,
// with each key's type and time to live: TYPE and PTTL for the whole page
// go in one pipeline, so one round trip (one per master in a Cluster).
func Keys(ctx context.Context, c redis.UniversalClient, pattern string, limit int) ([]KeyInfo, bool, error) {
	if pattern == "" {
		pattern = "*"
	}
	var names []string
	var more bool
	var err error
	if cc, ok := c.(*redis.ClusterClient); ok {
		names, more, err = clusterKeys(ctx, cc, pattern, limit)
	} else {
		names, more, err = scanKeys(ctx, c, pattern, limit)
	}
	if err != nil {
		return nil, false, err
	}
	keys, err := describeKeys(ctx, c, names)
	return keys, more, err
}

// describeKeys reads TYPE and PTTL of every key in one pipeline. A command
// the server refuses (an ACL without TYPE, say) leaves that field null; a
// key deleted since the scan is type "none" with no time to live.
func describeKeys(ctx context.Context, c redis.UniversalClient, names []string) ([]KeyInfo, error) {
	keys := make([]KeyInfo, len(names))
	if len(names) == 0 {
		return keys, nil
	}
	types := make([]*redis.StatusCmd, len(names))
	ttls := make([]*redis.DurationCmd, len(names))
	_, err := c.Pipelined(ctx, func(p redis.Pipeliner) error {
		for i, k := range names {
			types[i] = p.Type(ctx, k)
			ttls[i] = p.PTTL(ctx, k)
		}
		return nil
	})
	var re redis.Error
	if err != nil && !errors.As(err, &re) {
		return nil, cmdErr(err)
	}
	for i, k := range names {
		keys[i].Key = k
		if t, err := types[i].Result(); err == nil {
			keys[i].Type = &t
		}
		if d, err := ttls[i].Result(); err == nil {
			keys[i].TTL = ttlSeconds(d)
		}
	}
	return keys, nil
}

// ttlSeconds turns a PTTL reply into whole seconds, rounded as TTL does:
// -1 (no expiry) stays -1, -2 (no such key) is unknown.
func ttlSeconds(d time.Duration) *int64 {
	var s int64
	switch {
	case d == -1:
		s = -1
	case d < 0:
		return nil
	default:
		s = (d.Milliseconds() + 500) / 1000
	}
	return &s
}

// scanKeys lists up to limit key names matching pattern on one server.
func scanKeys(ctx context.Context, c redis.UniversalClient, pattern string, limit int) (keys []string, more bool, err error) {
	keys = []string{}
	var cur uint64
	for {
		batch, next, err := c.Scan(ctx, cur, pattern, 500).Result()
		if err != nil {
			return nil, false, cmdErr(err)
		}
		for _, k := range batch {
			if len(keys) >= limit {
				return keys, true, nil
			}
			keys = append(keys, k)
		}
		if next == 0 {
			return keys, false, nil
		}
		cur = next
	}
}
