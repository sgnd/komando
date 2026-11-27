# Caches

Read and change keys in Redis-compatible caches (Redis, Valkey, KeyDB,
Dragonfly) and memcached safely. [All docs](README.md)

## Add a cache

```bash
komando cache redis add prod-redis redis://default@10.0.0.7:6379/0 --via web1 --ask-password
komando test prod-redis                       # can komando reach it and log in?
```

Typed alone, `komando cache redis add` asks for each part step by step.

The URL is `redis://USER@HOST:PORT/DB`; use `rediss://` for TLS. The
password goes in the vault, never in the URL: `--ask-password` asks for it
(hidden), or store it first and point at it:

```bash
komando secret set prod-redis-pass            # each password once, typed hidden
komando cache redis add prod-redis redis://default@10.0.0.7:6379/0 --via web1 --credential prod-redis-pass
```

`--via` reaches a cache through a bastion or a VPN, like any other conn (see
[Tunnels](tunnels.md) and [VPNs](vpn.md)).

At a terminal, a command with the cache left out asks for just that, with a
list of your caches to pick from, then shows the full command. An AI agent,
a script or a pipe never gets a question: the same command stops with
`USAGE` (exit 2) and a hint with an example
(`komando cache redis raw prod-redis -- GET session:42`).

### Encryption (TLS)

`redis://` straight over the network (no `--via`, not to this computer)
sends the password and the data unencrypted, so `cache redis add` (and
`conn edit --url`) refuses it with `INSECURE_PROTOCOL`: use `rediss://` or
`--via`, or add `?insecure=1` to accept that the traffic is readable on the
way (for an AI agent that needs a person's yes). The same goes for
`memcached://`. A conn like that that is already in your list keeps
working; `komando doctor` warns about it and prints the line that changes
it.

`rediss://` and `memcacheds://` check the server's certificate against your
computer's trusted CAs, or against your own with `?ca=credential:NAME` (a
private CA, or a cloud's own):

```bash
komando secret set prod-redis-ca < ca.pem
komando cache redis add prod-redis 'rediss://default@cache.internal:6380/1?ca=credential:prod-redis-ca' --credential prod-redis-pass
```

### Redis Cluster and Sentinel

Add a Redis Cluster (or a Valkey cluster, or ElastiCache and MemoryDB in
cluster mode) by one node's address with `?cluster=1`: komando finds the
other nodes from it. Behind Sentinels, add a Sentinel's address with
`?sentinel=` and the master's name: komando asks the Sentinels where the
master is now, so a failover needs no change.

```bash
komando cache redis add sessions 'rediss://default@clustercfg.sessions.abc123.cache.amazonaws.com:6379?cluster=1' --credential sessions-pass
komando cache redis add jobs-redis 'redis://default@sentinel1:26379/0?sentinel=mymaster&sentinels=sentinel2,sentinel3' --via web1 --credential jobs-redis-pass
```

- In a Cluster, a command for one key goes to the node that holds it, and
  `DEL` of keys in different slots goes one by one. `cache redis raw -- DBSIZE`
  adds up every master.
- Sentinels listen on 26379 when the URL names no port. More Sentinels go
  in `sentinels=HOST[:PORT],...`. The password is for Redis; when the
  Sentinels want it too, add `&sentinel_auth=same`.
- Through `--via`, every node and Sentinel is reached through the same
  bastion or VPN, with TLS for `rediss://`.

What a Cluster cannot do is under [Limits](#limits).

## Look at data and change it

Every cache command is `cache redis raw` (or `cache memcached raw`) with the
native command after `--`. It only reads unless you add `--write`:

```bash
komando cache redis raw prod-redis -- GET session:42
komando cache redis raw prod-redis -- HGETALL user:42
komando cache redis raw prod-redis -- INFO memory
komando cache redis raw prod-redis -- SCAN 0 MATCH 'session:*' COUNT 100
komando cache redis raw prod-redis --write -- SET maintenance on EX 1800
```

- A protected conn asks a person at a terminal before every change; an AI
  agent or a script adds `--yes` after a person agrees
  (`PROTECTED_TARGET`, exit 6, without it).
- Redis cannot undo, so `--dry-run` sends no change at all: it shows what
  would be sent.
- Never use `KEYS`: it blocks the server on a big cache. Use `SCAN`.
- A command that deletes keys (`DEL`, `UNLINK`, `FLUSHALL`, ...) needs
  `--allow-dangerous` as well, and a deleted key cannot come back. At your
  terminal komando does not ask you to type the key's name any more: the
  `--allow-dangerous` flag is the person's extra yes. See
  [Safety](safety.md#what-needs-a-yes).

## Any other Redis command

`cache redis raw` sends any command. It only reads unless you add `--write`:

```bash
komando cache redis raw prod-redis -- HGETALL user:42
komando cache redis raw prod-redis -- ZREVRANGE leaderboard 0 9 WITHSCORES
komando cache redis raw prod-redis --write -- EXPIRE session:42 3600
komando cache redis raw prod-redis -- "GET feature:dark-mode"   # one quoted line, split like redis-cli
```

Commands that delete, wipe, block, run scripts or reconfigure the server
(`DEL`, `FLUSHALL`, `KEYS`, `EVAL`, `CONFIG SET`, `SHUTDOWN`, ...) are
destructive, so they need `--allow-dangerous`. The error tells you the safer
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
komando cache redis raw prod-redis --write -- BGSAVE
komando download web1 /var/lib/redis/dump.rdb --sudo --to ./
```

## memcached

The same commands work with memcached. The URL is
`memcached://HOST:11211`; use `memcacheds://` for TLS. For a server started
with `memcached -Y`, give a user in the URL and the password as a reference:

```bash
komando cache memcached add prod-memcached memcached://cache.internal:11211 --via web1
komando cache memcached add app-memcached memcached://app@cache.internal:11211 --via web1 --credential app-memcached-pass
komando cache memcached raw prod-memcached -- get session:42
komando cache memcached raw prod-memcached -- lru_crawler metadump all   # the keys, through memcached's LRU crawler
komando cache memcached raw prod-memcached -- stats slabs
```

- `cache memcached raw` sends one command line and only reads unless
  `--write`. `flush_all` and commands that change or stop the server are
  destructive.
- A store command (`set`, `add`, `replace`, `append`, `cas`, ...) needs a data
  block, which raw does not send: komando cannot store a memcached value
  (a known loss of the removal of `cache set`, row C496). Redis `SET` works.
- The line is split at spaces the way memcached reads it, and the command
  word is sent in lower case.

## Limits

- `cache redis raw` prints one reply, so commands that never stop sending
  (`MONITOR`, `SUBSCRIBE`, `PSUBSCRIBE`, `XREAD ... BLOCK`) stop with
  `NOT_SUPPORTED`. On memcached, `watch` never returns, so it stops the
  same way.
- On memcached, a newline or other control character in a `cache memcached raw`
  line stops with `USAGE` (it would start a second command).
- A Cluster has only database 0.
- In a Cluster, `SCAN`, `RANDOMKEY`, `KEYS`, `FLUSHALL`, `FLUSHDB` and
  `SWAPDB` would reach one master only, so they stop with `NOT_SUPPORTED`
  (to scan or flush, add each master as its own conn). A command
  over several keys of different slots (`MGET a b`) fails with
  `CROSSSLOT`: use one command per key, or a common `{tag}` in the key
  names.
- Listing keys on memcached needs the LRU crawler (on by default since
  memcached 1.5).
- komando has no backup command for caches (see
  [Back up a cache](#back-up-a-cache)).

## Troubleshooting

| Error | What it means | What to do |
|-------|---------------|------------|
| `CACHE_CONNECT` | komando cannot reach the cache, or cannot check its certificate | `komando test prod-redis`; for a private CA add `?ca=credential:NAME`, or reach it `--via` a server |
| `CACHE_AUTH` | the cache refused the login | check the user in the URL and the password reference (`komando conn show prod-redis`) |
| `CACHE_ERROR` | memcached cannot list keys | start memcached with the LRU crawler on; `get KEY` works without it |
| `INSECURE_PROTOCOL` | `redis://` or `memcached://` crosses the network unencrypted | use `rediss://` or `memcacheds://`, or `--via`, or add `?insecure=1` |
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
