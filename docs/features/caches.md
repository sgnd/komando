# Caches

Read and change Redis-compatible caches (Redis, Valkey, KeyDB, Dragonfly)
and memcached safely. [All features](README.md)

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
komando secret set cache-pass                 # each password once, typed hidden
komando conn add cache redis://default@10.0.0.7:6379/0 --via web1 --password-ref secret:cache-pass
komando conn add sessions rediss://default@cache.internal:6379/1 --ask-password   # or type it now
```

`--via` reaches a cache through a bastion or a VPN, like any other conn (see
[Tunnels](tunnels.md) and [VPNs](vpn.md)).

`redis://` straight over the network (no `--via`, not to this computer)
sends the password and the data unencrypted, so `conn add` (and
`conn edit --url`) refuses it with `INSECURE_PROTOCOL`: use `rediss://` or
`--via`, or add `?insecure=1` to accept that the traffic is readable on the
way (for an AI agent that needs a person's yes). The same goes for
`memcached://`. Conns saved before keep working; `komando doctor` warns
about them and prints the line that changes them. `rediss://` checks the server's certificate against your computer's
trusted CAs, or against your own with `?ca=secret:NAME` (a private CA, or a
cloud's own), as `memcacheds://` does:

```bash
komando secret set cache-ca < ca.pem
komando conn add sessions 'rediss://default@cache.internal:6380/1?ca=secret:cache-ca' --password-ref secret:sessions-pass
```

### Redis Cluster and Sentinel

A **Redis Cluster** (or Valkey cluster, ElastiCache and MemoryDB in cluster
mode) is added by one node's address with `?cluster=1`: komando finds the
other nodes from it. Behind **Sentinels**, add a Sentinel's address with
`?sentinel=` and the master's name: komando asks the Sentinels where the
master is now, so a failover needs no change.

```bash
komando conn add sessions 'rediss://default@clustercfg.sessions.abc123.cache.amazonaws.com:6379?cluster=1' --password-ref secret:sessions-pass
komando conn add queue 'redis://default@sentinel1:26379/0?sentinel=mymaster&sentinels=sentinel2,sentinel3' --via web1 --password-ref secret:queue-pass
```

- In a Cluster, `cache keys` scans every master and `cache info` adds up
  memory, clients and keys over them, with the cluster's state
  (`cluster_state`, `masters`). A command for one key goes to the node that
  holds it. A Cluster has only database 0.
- Sentinels listen on 26379 when the URL names no port. More Sentinels go
  in `sentinels=HOST[:PORT],...`. The password is for Redis; when the
  Sentinels want it too, add `&sentinel_auth=same`.
- Through `--via`, every node and Sentinel is reached through the same
  bastion or VPN, with TLS for `rediss://`.

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

- Read-only scripts (`EVAL_RO`, `EVALSHA_RO`, `FCALL_RO`) count as scripts:
  they cannot write, but one that loops makes Redis answer `BUSY` to every
  client until someone sends `SCRIPT KILL` (`FUNCTION KILL` for `FCALL_RO`).
- Module code counts too: Redis Stack functions (`TFCALL`, `TFCALLASYNC`)
  and RedisGears (`RG.PYEXECUTE`, `RG.TRIGGER`).
- `FUNCTION LOAD REPLACE` and `TFUNCTION LOAD REPLACE` count too: they swap
  the code behind functions the application already calls. A plain
  `FUNCTION LOAD` only needs `--write`.
- `CONFIG GET` only reads. For AI agents, the values of password settings
  (`requirepass`, `masterauth`, `tls-key-file-pass`, ...) and the password
  hashes in `ACL LIST` and `ACL GETUSER` show as `[hidden]`, even when a
  password is a word like `yes`. A hash field named like a secret
  (`password`, `token`, ...) is hidden the same over RESP2 and RESP3.

## memcached

The same commands work with memcached. The URL is
`memcached://HOST:11211`; use `memcacheds://` for TLS. For a server started
with `memcached -Y`, give a user in the URL and the password as a reference:

```bash
komando conn add mc memcached://cache.internal:11211 --via web1
komando conn add mc2 memcached://app@cache.internal:11211 --via web1 --password-ref secret:mc-pass
komando cache get mc session:42               # the value, and on 1.6+ its time to live
komando cache keys mc 'session:*'             # through memcached's LRU crawler
komando cache info mc                         # a summary of `stats`; `info mc items` for one section
komando cache run mc -- stats slabs
```

- `cache set` and `cache rm` work as for Redis, with the same safety rules.
- `cache run` sends one command line and only reads unless `--write`.
  `flush_all` and commands that change or stop the server also need
  `--allow-dangerous`. Store values with `cache set`.

## Output

- **Text** (`-o text`) looks like `redis-cli`: one item per line, numbered,
  nested replies indented. Strings are quoted when they hold spaces, quotes
  or control characters (a newline shows as `\n`), so a value never breaks
  the layout. A hash or map entry shows as `name: value`.
- **JSON** keeps values exactly as they are; binary values come as
  `{"base64": "..."}`.
