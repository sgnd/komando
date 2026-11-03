# Caches

Read and change Redis and Valkey safely. [All features](README.md)

`komando cache` works with Redis and compatible caches (Valkey, KeyDB,
Dragonfly) added with `komando conn add`.

```bash
komando cache info cache                      # summary: version, role, memory, clients, keys, hit rate
komando cache info cache memory               # one raw INFO section (--all for every field)
komando cache keys cache 'session:*'          # list keys (safe on big caches)
komando cache get cache session:42            # any type: value, type, time to live
komando cache set cache maintenance on --ttl 30m    # --ttl takes 30m, 24h, 7d
komando cache rm cache session:42 --dry-run   # which of these keys exist
komando cache rm cache session:42 --allow-dangerous   # deleting needs --allow-dangerous
```

Anything else goes through `cache run`. **It only reads unless you add
`--write`:**

```bash
komando cache run cache -- HGETALL user:42
komando cache run cache --write -- EXPIRE session:42 3600
```

Commands that delete, wipe, block, run scripts or reconfigure the server
(`DEL`, `FLUSHALL`, `KEYS`, `EVAL`, `CONFIG SET`, `SHUTDOWN`, ...) also need
`--allow-dangerous`; the error says what to use instead (`cache keys` for
`KEYS`, `cache rm` for `DEL`). A protected conn needs `--yes` for every
change. Redis cannot undo, so `--dry-run` sends no change: `cache set` says
whether the key exists and would be replaced, `cache rm` which keys exist.

`--ttl` must be positive; without it the key never expires. `cache set` and
`cache get` both report `ttl_seconds` (`null` when there is none).

Text output (`-o text`) looks like `redis-cli`: one item per line, numbered,
nested replies indented, and strings in quotes when they hold spaces, quotes
or control characters (a newline shows as `\n`), so a value never breaks
the layout. JSON keeps the values as they are (binary as `{"base64": ...}`).
