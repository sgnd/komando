package cachex

import (
	"context"
	"time"

	"github.com/redis/go-redis/v9"

	"github.com/sgnd/komando/internal/driver"
)

// Store is what the cache commands need from a cache server: Redis (and
// Valkey) or memcached.
type Store interface {
	Get(ctx context.Context, key string, limit int64, maxBytes int) (*Value, error)
	Keys(ctx context.Context, pattern string, limit int) ([]KeyInfo, bool, error)
	Info(ctx context.Context, section string) (map[string]map[string]string, error)
	Set(ctx context.Context, key, value string, ttl time.Duration) error
	Exists(ctx context.Context, key string) (bool, error)
	Del(ctx context.Context, keys ...string) (int64, error)
	Run(ctx context.Context, args []string) (any, error)
	Close() error
}

// OpenStore connects to a cache conn of either kind.
func OpenStore(ctx context.Context, t driver.Target, password string, dial DialFunc, timeout time.Duration) (Store, error) {
	if t.Kind.Name == "memcached" {
		return openMemcache(ctx, t, password, dial, timeout)
	}
	c, err := Open(ctx, t, password, dial, timeout)
	if err != nil {
		return nil, err
	}
	return redisStore{c}, nil
}

// ClassifyFor rates a raw command for the conn's kind.
func ClassifyFor(kind string, args []string) driver.Verdict {
	if kind == "memcached" {
		return ClassifyMemcache(args)
	}
	return Classify(args)
}

// SectionsFor are the info sections the kind takes.
func SectionsFor(kind string) []string {
	if kind == "memcached" {
		return MemcacheSections
	}
	return InfoSections
}

// SummarizeFor is Summarize for the kind.
func SummarizeFor(kind string, info map[string]map[string]string) Summary {
	if kind == "memcached" {
		return memcacheSummary(info)
	}
	return Summarize(info)
}

type redisStore struct{ c redis.UniversalClient }

func (r redisStore) Get(ctx context.Context, key string, limit int64, maxBytes int) (*Value, error) {
	return Get(ctx, r.c, key, limit, maxBytes)
}
func (r redisStore) Keys(ctx context.Context, pattern string, limit int) ([]KeyInfo, bool, error) {
	return Keys(ctx, r.c, pattern, limit)
}
func (r redisStore) Info(ctx context.Context, section string) (map[string]map[string]string, error) {
	return Info(ctx, r.c, section)
}
func (r redisStore) Set(ctx context.Context, key, value string, ttl time.Duration) error {
	return cmdErr0(r.c.Set(ctx, key, value, ttl).Err())
}
func (r redisStore) Exists(ctx context.Context, key string) (bool, error) {
	n, err := r.c.Exists(ctx, key).Result()
	return n > 0, cmdErr0(err)
}
func (r redisStore) Del(ctx context.Context, keys ...string) (int64, error) {
	if _, ok := r.c.(*redis.ClusterClient); ok {
		// a Cluster refuses one DEL over keys in different slots (CROSSSLOT)
		var n int64
		for _, k := range keys {
			d, err := r.c.Del(ctx, k).Result()
			if err != nil {
				return n, cmdErr(err)
			}
			n += d
		}
		return n, nil
	}
	n, err := r.c.Del(ctx, keys...).Result()
	return n, cmdErr0(err)
}
func (r redisStore) Run(ctx context.Context, args []string) (any, error) { return Run(ctx, r.c, args) }
func (r redisStore) Close() error                                        { return r.c.Close() }

func cmdErr0(err error) error {
	if err == nil {
		return nil
	}
	return cmdErr(err)
}
