# Caches

Read and change Redis and Valkey safely. [All features](README.md)

`komando cache` works with Redis and compatible caches (Valkey, KeyDB,
Dragonfly) added with `komando conn add`.

```bash
komando cache info cache                      # version, memory, clients
komando cache keys cache 'session:*'          # list keys (safe on big caches)
komando cache get cache session:42            # any type: value, type, time to live
komando cache set cache maintenance on --ttl 30m
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
`--allow-dangerous`. A protected
conn needs `--yes` for every change. Redis cannot undo, so `--dry-run` only
shows that a change would be allowed; nothing is sent.
