# Caches

Read and change keys in Redis-compatible caches (Redis, Valkey, KeyDB,
Dragonfly) and memcached safely. [All docs](README.md)

A cache command is `komando cache PROVIDER VERB NAME`: the provider is
`redis` or `memcached`, and NAME is the cache's name in komando's list.
Everything you do with the keys goes through one verb, `raw`: the cache's
own command language, as in `redis-cli`.

## Add a cache

```bash
komando credential password add prod-redis-pass --user default   # asks for the password, hidden
komando cache redis add prod-redis redis://10.0.0.7:6379/0 --via web1 --credential prod-redis-pass
komando test prod-redis                       # can komando reach it and log in?
```

Typed alone, `komando cache redis add` asks for each part step by step.

The URL is `redis://HOST:PORT/DB`; use `rediss://` for TLS. The user and the
password live in a credential, never in the URL (see
[Credentials](credentials.md)). Make the credential first, once, and point the
cache at it with `--credential`.

TODO(cut): the typed flags of each provider's `add` that replace the URL
wait on the `Options` of each leaf in the table (PR B).

`--via` reaches a cache through a bastion or a VPN, like any other entry
(see [Tunnels](tunnels.md) and [VPNs](vpn.md)).

At a terminal, a command with the cache or the Redis command left out asks
for just that, with a list of your caches to pick from, then shows the full
command. Typed alone, `komando cache redis raw` asks which cache, then the
command. An AI agent, a script or a pipe never gets a question: the same
command stops with `USAGE` (exit 2) and a hint with an example
(`komando cache redis raw prod-redis -- GET session:42`).

### Encryption (TLS)

`redis://` straight over the network (no `--via`, not to this computer)
sends the password and the data unencrypted, so `cache redis add` (and
`cache redis edit --url`) refuses it with `INSECURE_PROTOCOL`: use
`rediss://` or `--via`, or add `?insecure=1` to accept that the traffic is
readable on the way (for an AI agent that needs a person's yes). The same
goes for `memcached://`. An entry like that that is already in your list
keeps working; `komando doctor` warns about it and prints the line that
changes it.

`rediss://` and `memcacheds://` check the server's certificate against your
computer's trusted CAs, or against your own with `?ca=credential:NAME` (a
private CA, or a cloud's own):

```bash
komando credential certificate add prod-redis-ca       # the CA bundle, ca.pem
komando cache redis add prod-redis 'rediss://cache.internal:6380/1?ca=credential:prod-redis-ca' --credential prod-redis-pass
```

TODO(cut): how a certificate file is given to `credential certificate add`
waits on the `Options` of that leaf (PR B).

### Redis Cluster and Sentinel

Add a Redis Cluster (or a Valkey cluster, or ElastiCache and MemoryDB in
cluster mode) by one node's address with `?cluster=1`: komando finds the
other nodes from it. Behind Sentinels, add a Sentinel's address with
`?sentinel=` and the master's name: komando asks the Sentinels where the
master is now, so a failover needs no change.

```bash
komando cache redis add sessions 'rediss://clustercfg.sessions.abc123.cache.amazonaws.com:6379?cluster=1' --credential sessions-pass
komando cache redis add jobs-redis 'redis://sentinel1:26379/0?sentinel=mymaster&sentinels=sentinel2,sentinel3' --via web1 --credential jobs-redis-pass
```

- In a Cluster, a command for one key goes to the node that holds it.
  `DBSIZE` adds up every master.
- Sentinels listen on 26379 when the URL names no port. More Sentinels go
  in `sentinels=HOST[:PORT],...`. The password is for Redis; when the
  Sentinels want it too, add `&sentinel_auth=same`.
- Through `--via`, every node and Sentinel is reached through the same
  bastion or VPN, with TLS for `rediss://`.

What a Cluster cannot do is under [Limits](#limits).

## Look at data

`raw` sends a Redis command. It only reads unless you add `--write`.
Everything after `--` is the command, and komando's own flags go before it:

```bash
komando cache redis raw prod-redis -- GET session:42           # a string
komando cache redis raw prod-redis -- HGETALL user:42          # a hash
komando cache redis raw prod-redis -- ZREVRANGE leaderboard 0 9 WITHSCORES
komando cache redis raw prod-redis -- TYPE session:42
komando cache redis raw prod-redis -- TTL session:42
komando cache redis raw prod-redis -- INFO memory              # one raw INFO section
komando cache redis raw prod-redis -- SCAN 0 MATCH 'session:*' COUNT 100   # keys matching a pattern
komando cache redis raw prod-redis -- "GET feature:dark-mode"  # one quoted line, split like redis-cli
```

```text
1) "logged-in"
```

Use `SCAN`, never `KEYS`: `SCAN` is safe on big caches, and `KEYS` stops
as destructive (see below). A `SCAN` returns a cursor and a page of keys;
send the cursor back to read the next page.

Text output (`-o text`) looks like `redis-cli`: one item per line,
numbered, nested replies indented. Strings are quoted when they hold
spaces, quotes or control characters (a newline shows as `\n`), so a value
never breaks the layout. A hash or map entry shows as `name: value`.
JSON keeps values exactly as they are; binary values come as
`{"base64": "..."}`.

## Change data

```bash
komando cache redis raw prod-redis --write --dry-run -- SET maintenance on EX 1800
komando cache redis raw prod-redis --write -- SET maintenance on EX 1800   # expires in 30 minutes
komando cache redis raw prod-redis --write -- SET feature:dark-mode on     # no EX: never expires
komando cache redis raw prod-redis --write -- EXPIRE session:42 3600
```

```text
OK
```

- `SET` stores a string and replaces any old value. `EX` takes seconds.
- A protected cache asks a person at a terminal before every change; an AI
  agent or a script adds `--yes` after a person agrees
  (`PROTECTED_TARGET`, exit 6, without it).
- Redis cannot undo, so `--dry-run` sends no change at all: it shows the
  plan and how komando rated the command.

### Delete keys

```bash
komando cache redis raw prod-redis --write --dry-run -- DEL session:42 session:43   # the plan, nothing is sent
komando cache redis raw prod-redis --write -- DEL session:42 session:43
```

`DEL` deletes keys by exact name (no patterns), and a deleted key cannot
come back. It is destructive: an AI agent or a script adds
`--allow-dangerous` after a person agrees; without it, it gets
`POLICY_BLOCKED` (exit 6). See [Safety](safety.md#what-needs-a-yes).

One loss to know: through `raw`, a person at a terminal is asked only for
`--allow-dangerous`, no longer to type the key's name. For a cache that
matters, mark it protected (`komando cache redis edit prod-redis
--protected`), which adds a person's yes to every change.

## Commands that stop as destructive

Commands that delete, wipe, block, run scripts or reconfigure the server
(`DEL`, `FLUSHALL`, `KEYS`, `EVAL`, `CONFIG SET`, `SHUTDOWN`, ...) are
destructive, so they ask for `--allow-dangerous` (an AI agent gets
`POLICY_BLOCKED` until a person agrees). The error tells you the safer
command to use instead (`SCAN` for `KEYS`).

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

```bash
komando test prod-redis                       # can komando reach it and log in?
komando cache redis show prod-redis           # its URL, way in and credential name
komando cache redis edit prod-redis --via web2        # reach it another way
komando cache redis edit prod-redis --protected       # every change then needs a person's yes
komando cache redis rename prod-redis sessions-redis
komando cache redis remove prod-redis         # remove it from your list (the cache is untouched)
komando cache redis list                      # your Redis caches
```

### Back up a cache

komando has no backup command for caches. Redis saves its own snapshot,
which you can then fetch from its server:

```bash
komando cache redis raw prod-redis --write -- BGSAVE
komando copy web1:/var/lib/redis/dump.rdb ./ --sudo
```

## memcached

The same verbs work with memcached, with the provider `memcached`. The URL
is `memcached://HOST:11211`; use `memcacheds://` for TLS. For a server
started with `memcached -Y`, give the user and the password in a
credential:

```bash
komando cache memcached add prod-memcached memcached://cache.internal:11211 --via web1
komando credential password add app-memcached-pass --user app
komando cache memcached add app-memcached memcached://cache.internal:11211 --via web1 --credential app-memcached-pass
komando cache memcached raw prod-memcached -- get session:42     # the value
komando cache memcached raw prod-memcached -- stats
komando cache memcached raw prod-memcached -- stats slabs
komando cache memcached raw prod-memcached -- lru_crawler metadump hash   # the keys, through the LRU crawler
```

- `raw` sends one command line and only reads unless `--write`. `flush_all`
  and commands that change or stop the server are destructive. Store
  values with `set` and `--write`.
- The line is split at spaces the way memcached reads it, and the command
  word is sent in lower case.

## Limits

- `DEL` takes exact key names, never a pattern.
- `raw` prints one reply, so commands that never stop sending
  (`MONITOR`, `SUBSCRIBE`, `PSUBSCRIBE`, `XREAD ... BLOCK`) stop with
  `NOT_SUPPORTED`. On memcached, `watch` never returns, so it stops the
  same way.
- On memcached, a newline or other control character in a `raw` line stops
  with `USAGE` (it would start a second command).
- A Cluster has only database 0.
- In a Cluster, `SCAN`, `RANDOMKEY`, `KEYS`, `FLUSHALL`, `FLUSHDB` and
  `SWAPDB` would reach one master only, so they stop with `NOT_SUPPORTED`
  (to flush, add each master as its own entry). A command over several keys
  of different slots (`MGET a b`) fails with `CROSSSLOT`: use one command
  per key, or a common `{tag}` in the key names.
- Listing memcached keys needs the LRU crawler (on by default since
  memcached 1.5).
- komando has no backup command for caches (see
  [Back up a cache](#back-up-a-cache)).

## Troubleshooting

| Error | What it means | What to do |
|-------|---------------|------------|
| `CACHE_CONNECT` | komando cannot reach the cache, or cannot check its certificate | `komando test prod-redis`; for a private CA add `?ca=credential:NAME`, or reach it `--via` a server |
| `CACHE_AUTH` | the cache refused the login | check the credential (`komando cache redis show prod-redis`) |
| `CACHE_ERROR` | memcached cannot list keys | start memcached with the LRU crawler on; `get` works without it |
| `INSECURE_PROTOCOL` | `redis://` or `memcached://` crosses the network unencrypted | use `rediss://` or `memcacheds://`, or `--via`, or add `?insecure=1` |
| `NOT_SUPPORTED` | a command that never returns, or one a Cluster cannot run on all masters | the hint says what to use instead |
| `POLICY_BLOCKED` | a destructive command without `--allow-dangerous` (exit 6) | run it at a terminal, or add the flag after a person agrees |
| `PROTECTED_TARGET` | a change on a protected cache without `--yes` (exit 6) | run it at a terminal, or add the flag after a person agrees |
| `USAGE` | an argument is missing or wrong, or the command came without `--` (exit 2) | the hint shows a full example |

Every code is in [Error codes](error-codes.md).
