# Caches

Read and change Redis-compatible caches (Redis, Valkey, KeyDB, Dragonfly)
safely. [All features](README.md)

## Quick start

```bash
komando secret set cache-pass
komando conn add cache redis://default@10.0.0.7:6379/0 --via web1 --password-ref secret:cache-pass
komando cache info cache                      # version, role, memory, clients, keys, hit rate
komando cache keys cache 'session:*'          # find keys (safe on big caches)
komando cache get cache session:42            # value, type and time to live
```

## Add a cache

Add the cache as a conn. The URL is `redis://USER@HOST:PORT/DB`; use
`rediss://` for TLS. The password goes in the vault, never in the URL:

```bash
komando conn add cache redis://default@10.0.0.7:6379/0 --via web1 --password-ref secret:cache-pass
komando conn add sessions rediss://default@cache.internal:6379/1 --password-ref secret:sessions-pass
```

`--via` reaches a cache through a bastion or a VPN, like any other conn (see
[Tunnels](tunnels.md)).

## Look at data

These commands only read:

```bash
komando cache info cache                      # a summary
komando cache info cache memory               # one raw INFO section
komando cache info cache --all                # every field of the default INFO sections
komando cache keys cache 'session:*'          # keys matching a pattern (up to 100; --limit 1000)
komando cache get cache session:42            # any type: string, hash, list, set, sorted set
komando cache get cache leaderboard --limit 10   # at most 10 items of a big hash or list
```

`cache keys` uses `SCAN`, so it is safe on big caches. Never use `KEYS`.

## Change data

```bash
komando cache set cache maintenance on --ttl 30m       # --ttl takes 30m, 24h, 7d
komando cache set cache feature:dark-mode on           # no --ttl: never expires
komando cache rm cache session:42 --dry-run            # which of these keys exist
komando cache rm cache session:42 session:43 --allow-dangerous
```

- `cache set` stores a string and replaces any old value. `--ttl` must be
  positive. `set` and `get` both report `ttl_seconds` (`null` when the key
  never expires).
- `cache rm` deletes keys by exact name (no patterns). Deleting needs
  `--allow-dangerous`.
- A protected conn needs `--yes` for every change.
- Redis cannot undo, so `--dry-run` sends no change at all: `cache set` says
  whether the key exists and would be replaced, `cache rm` which keys exist.

## Any other Redis command

`cache run` sends any command. **It only reads unless you add `--write`:**

```bash
komando cache run cache -- HGETALL user:42
komando cache run cache -- ZREVRANGE leaderboard 0 9 WITHSCORES
komando cache run cache --write -- EXPIRE session:42 3600
```

Commands that delete, wipe, block, run scripts or reconfigure the server
(`DEL`, `FLUSHALL`, `KEYS`, `EVAL`, `CONFIG SET`, `SHUTDOWN`, ...) also need
`--allow-dangerous`. The error tells you the safer command to use instead
(`cache keys` for `KEYS`, `cache rm` for `DEL`).

## Output

- **Text** (`-o text`) looks like `redis-cli`: one item per line, numbered,
  nested replies indented. Strings are quoted when they hold spaces, quotes
  or control characters (a newline shows as `\n`), so a value never breaks
  the layout.
- **JSON** keeps values exactly as they are; binary values come as
  `{"base64": "..."}`.
