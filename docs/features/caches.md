# Caches

Read and change keys in Redis-compatible caches (Redis, Valkey, KeyDB,
Dragonfly) and memcached safely. [All docs](README.md)

## Add a cache

```bash
komando cache add prod-redis redis://default@10.0.0.7:6379/0 --via web1 --ask-password
komando test prod-redis                       # can komando reach it and log in?
```

Typed alone, `komando cache add` asks for each part step by step.

The URL is `redis://USER@HOST:PORT/DB`; use `rediss://` for TLS. The
password goes in the vault, never in the URL: `--ask-password` asks for it
(hidden), or store it first and point at it:

```bash
komando secret set prod-redis-pass            # each password once, typed hidden
komando cache add prod-redis redis://default@10.0.0.7:6379/0 --via web1 --password-ref secret:prod-redis-pass
```

`--via` reaches a cache through a bastion or a VPN, like any other conn (see
[Tunnels](tunnels.md) and [VPNs](vpn.md)).

At a terminal, a command with the cache or the key left out asks for just
that, with a list of your caches to pick from, then shows the full
command. Typed alone, `komando cache get` asks which cache, then the key.
An AI agent, a script or a pipe never gets a question: the same command
stops with `USAGE` (exit 2) and a hint with an example
(`komando cache get prod-redis session:42`).

### Encryption (TLS)

`redis://` straight over the network (no `--via`, not to this computer)
sends the password and the data unencrypted, so `cache add` (and
`conn edit --url`) refuses it with `INSECURE_PROTOCOL`: use `rediss://` or
`--via`, or add `?insecure=1` to accept that the traffic is readable on the
way (for an AI agent that needs a person's yes). The same goes for
`memcached://`. A conn like that that is already in your list keeps
working; `komando doctor` warns about it and prints the line that changes
it.

`rediss://` and `memcacheds://` check the server's certificate against your
computer's trusted CAs, or against your own with `?ca=secret:NAME` (a
private CA, or a cloud's own):

```bash
komando secret set prod-redis-ca < ca.pem
komando cache add prod-redis 'rediss://default@cache.internal:6380/1?ca=secret:prod-redis-ca' --password-ref secret:prod-redis-pass
```

### Redis Cluster and Sentinel

Add a Redis Cluster (or a Valkey cluster, or ElastiCache and MemoryDB in
cluster mode) by one node's address with `?cluster=1`: komando finds the
other nodes from it. Behind Sentinels, add a Sentinel's address with
`?sentinel=` and the master's name: komando asks the Sentinels where the
master is now, so a failover needs no change.

```bash
komando cache add sessions 'rediss://default@clustercfg.sessions.abc123.cache.amazonaws.com:6379?cluster=1' --password-ref secret:sessions-pass
komando cache add jobs-redis 'redis://default@sentinel1:26379/0?sentinel=mymaster&sentinels=sentinel2,sentinel3' --via web1 --password-ref secret:jobs-redis-pass
```

- In a Cluster, `cache keys` scans every master and `cache info` adds up
  memory, clients and keys over them, with the cluster's state
  (`cluster_state`, `masters`). A command for one key goes to the node that
  holds it, and `cache rm` deletes keys of different slots one by one.
  `cache run -- DBSIZE` adds up every master.
- Sentinels listen on 26379 when the URL names no port. More Sentinels go
  in `sentinels=HOST[:PORT],...`. The password is for Redis; when the
  Sentinels want it too, add `&sentinel_auth=same`.
- Through `--via`, every node and Sentinel is reached through the same
  bastion or VPN, with TLS for `rediss://`.

What a Cluster cannot do is under [Limits](#limits).

## Look at data

```bash
komando cache get prod-redis session:42       # any type: string, hash, list, set, sorted set
```

```text
key:   session:42
type:  string
ttl:   1740s
size:  9 bytes
value: logged-in
```

These commands only read:

```bash
komando cache info prod-redis                 # a summary
komando cache info prod-redis memory          # one raw INFO section
komando cache info prod-redis --all           # every field of the default INFO sections
komando cache keys prod-redis 'session:*'     # keys matching a pattern (up to 100; --limit 1000)
komando cache get prod-redis leaderboard --limit 10   # at most 10 items of a big hash or list
```

```text
version:   7.2.4 (standalone)
role:      master
uptime:    12d
memory:    1.2 GiB used of 4.0 GiB (eviction: allkeys-lru)
clients:   37
keys db0:  48210 (31002 with a ttl)
hit rate:  94.1% (1830211 hits, 114502 misses)
(all fields: --all, or a section such as memory or stats)
```

`cache keys` uses `SCAN`, so it is safe on big caches. Never use `KEYS`.
Each key shows its type and time to live, never its value:

```text
KEY        TYPE    TTL
queue      list    2s
session:1  string  1h
session:2  hash    none
```

In JSON, `items` lists the same keys as `keys`, in the same order, each as
`{"key", "type", "ttl_seconds"}`: `ttl_seconds` is -1 for no expiry and
null when unknown, and `type` is null when the server refuses `TYPE` (an
ACL without it). Redis reads `TYPE` and `PTTL` of the whole page in one
round trip (one per master in a Cluster). On memcached every type is
`string` and the time to live comes from the LRU crawler's listing.
A `--limit` below 1 is a `USAGE` error. When more keys match, the list
ends with `(first 100 keys; more match: narrow the pattern or raise
--limit)`.

## Change data

```bash
komando cache set prod-redis maintenance on --ttl 30m       # --ttl takes 30m, 24h, 7d
komando cache set prod-redis feature:dark-mode on           # no --ttl: never expires
```

```text
set maintenance (expires in 30m)
```

- `cache set` stores a string and replaces any old value. `--ttl` must be
  positive. `set` and `get` both report `ttl_seconds` (`null` when the key
  never expires).
- A protected conn asks a person at a terminal before every change; an AI
  agent or a script adds `--yes` after a person agrees
  (`PROTECTED_TARGET`, exit 6, without it).
- Redis cannot undo, so `--dry-run` sends no change at all: `cache set` says
  whether the key exists and would be replaced, `cache rm` which keys exist.

### Delete keys

```bash
komando cache rm prod-redis session:42 session:43 --dry-run   # which of these keys exist
komando cache rm prod-redis session:42 session:43
```

```text
would delete 1 key:
  session:42
  session:43 (does not exist)
```

`cache rm` deletes keys by exact name (no patterns), and a deleted key
cannot come back. At your terminal komando asks you first: you type the
key's name (for several keys, how many). An AI agent or a script adds
`--allow-dangerous` after a person agrees; without it, it gets
`POLICY_BLOCKED` (exit 6). See [Safety](safety.md#what-needs-a-yes).

## Any other Redis command

`cache run` sends any command. It only reads unless you add `--write`:

```bash
komando cache run prod-redis -- HGETALL user:42
komando cache run prod-redis -- ZREVRANGE leaderboard 0 9 WITHSCORES
komando cache run prod-redis --write -- EXPIRE session:42 3600
komando cache run prod-redis -- "GET feature:dark-mode"   # one quoted line, split like redis-cli
```

Commands that delete, wipe, block, run scripts or reconfigure the server
(`DEL`, `FLUSHALL`, `KEYS`, `EVAL`, `CONFIG SET`, `SHUTDOWN`, ...) are
destructive, so they ask as `cache rm` does (`--allow-dangerous` for an
agent). The error tells you the safer command to use instead
(`cache keys` for `KEYS`, `cache rm` for `DEL`).

- Read-only scripts (`EVAL_RO`, `EVALSHA_RO`, `FCALL_RO`) count as scripts:
  they cannot write, but one that loops makes Redis answer `BUSY` to every
  client until someone sends `SCRIPT KILL` (`FUNCTION KILL` for `FCALL_RO`).
- Module code counts too: Redis Stack functions (`TFCALL`, `TFCALLASYNC`)
  and RedisGears (`RG.PYEXECUTE`, `RG.TRIGGER`).
- Cluster and Sentinel administration counts too: `CLUSTER MEET`,
  `ADDSLOTS`, `FLUSHSLOTS`, `REPLICATE` (the node drops its own data),
  `SENTINEL SET`, `FAILOVER`, `REMOVE`, `CONFIG SET` and the like.
  `CLUSTER NODES`, `CLUSTER REPLICAS`, `SENTINEL MASTERS`,
  `SENTINEL GET-MASTER-ADDR-BY-NAME` and `SENTINEL CONFIG GET` only read.
- So do commands that delete keys another way: `FT.DROPINDEX ... DD`,
  `FT.DROP` without `KEEPDOCS`, and `SET` or `GETEX` with an `EXAT` or
  `PXAT` time already past.
- `FUNCTION LOAD REPLACE` and `TFUNCTION LOAD REPLACE` count too: they swap
  the code behind functions the application already calls. A plain
  `FUNCTION LOAD` only needs `--write`.
- `CONFIG GET` only reads. For AI agents, the values of password settings
  (`requirepass`, `masterauth`, `tls-key-file-pass`, ...) and the password
  hashes in `ACL LIST` and `ACL GETUSER` show as `[hidden]`, even when a
  password is a word like `yes`. A hash field named like a secret
  (`password`, `token`, ...) is hidden the same over RESP2 and RESP3.

## Check, change, rename or remove a cache

A cache is a conn, so the conn commands work on it:

```bash
komando test prod-redis                       # can komando reach it and log in?
komando conn show prod-redis                  # its URL, way in and password reference
komando conn edit prod-redis --via web2       # reach it another way
komando conn edit prod-redis --protected      # every change then needs a person's yes
komando conn rename prod-redis sessions-redis
komando conn rm prod-redis                    # remove it from your list (the cache is untouched)
```

### Back up a cache

komando has no backup command for caches. Redis saves its own snapshot,
which you can then fetch from its server:

```bash
komando cache run prod-redis --write -- BGSAVE
komando download web1 /var/lib/redis/dump.rdb --sudo --to ./
```

## memcached

The same commands work with memcached. The URL is
`memcached://HOST:11211`; use `memcacheds://` for TLS. For a server started
with `memcached -Y`, give a user in the URL and the password as a reference:

```bash
komando cache add prod-memcached memcached://cache.internal:11211 --via web1
komando cache add app-memcached memcached://app@cache.internal:11211 --via web1 --password-ref secret:app-memcached-pass
komando cache get prod-memcached session:42   # the value, and on 1.6+ its time to live
komando cache keys prod-memcached 'session:*' # through memcached's LRU crawler
komando cache info prod-memcached             # a summary of `stats`; `info prod-memcached items` for one section
komando cache run prod-memcached -- stats slabs
```

- `cache set` and `cache rm` work as for Redis, with the same safety rules.
- `cache run` sends one command line and only reads unless `--write`.
  `flush_all` and commands that change or stop the server are destructive.
  Store values with `cache set`.
- The line is split at spaces the way memcached reads it, and the command
  word is sent in lower case.

## Limits

- `cache rm` takes exact key names, never a pattern.
- `cache run` prints one reply, so commands that never stop sending
  (`MONITOR`, `SUBSCRIBE`, `PSUBSCRIBE`, `XREAD ... BLOCK`) stop with
  `NOT_SUPPORTED`. On memcached, `watch` never returns, so it stops the
  same way.
- On memcached, a newline or other control character in a `cache run`
  line stops with `USAGE` (it would start a second command).
- A Cluster has only database 0.
- In a Cluster, `SCAN`, `RANDOMKEY`, `KEYS`, `FLUSHALL`, `FLUSHDB` and
  `SWAPDB` would reach one master only, so they stop with `NOT_SUPPORTED`
  (use `cache keys`; to flush, add each master as its own conn). A command
  over several keys of different slots (`MGET a b`) fails with
  `CROSSSLOT`: use one command per key, or a common `{tag}` in the key
  names.
- `cache keys` on memcached needs the LRU crawler (on by default since
  memcached 1.5).
- komando has no backup command for caches (see
  [Back up a cache](#back-up-a-cache)).

## Troubleshooting

| Error | What it means | What to do |
|-------|---------------|------------|
| `CACHE_CONNECT` | komando cannot reach the cache, or cannot check its certificate | `komando test prod-redis`; for a private CA add `?ca=secret:NAME`, or reach it `--via` a server |
| `CACHE_AUTH` | the cache refused the login | check the user in the URL and the password reference (`komando conn show prod-redis`) |
| `CACHE_ERROR` | memcached cannot list keys | start memcached with the LRU crawler on; `cache get` works without it |
| `INSECURE_PROTOCOL` | `redis://` or `memcached://` crosses the network unencrypted | use `rediss://` or `memcacheds://`, or `--via`, or add `?insecure=1` |
| `NOT_FOUND` | `cache info` asked for a section the server does not have | `komando cache info prod-redis --all` |
| `NOT_SUPPORTED` | a command that never returns, or one a Cluster cannot run on all masters | the hint says what to use instead |
| `POLICY_BLOCKED` | a destructive command without `--allow-dangerous` (exit 6) | run it at a terminal, or add the flag after a person agrees |
| `PROTECTED_TARGET` | a change on a protected cache without `--yes` (exit 6) | run it at a terminal, or add the flag after a person agrees |
| `USAGE` | an argument is missing or wrong (exit 2) | the hint shows a full example |

Every code is in [Error codes](error-codes.md).

## Reference

### Output

Text output (`-o text`) looks like `redis-cli`: one item per line,
numbered, nested replies indented. Strings are quoted when they hold
spaces, quotes or control characters (a newline shows as `\n`), so a value
never breaks the layout. A hash or map entry shows as `name: value`.

JSON keeps values exactly as they are; binary values come as
`{"base64": "..."}`.
