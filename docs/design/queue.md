# Design: `komando queue`

The big goal and the roadmap for all families are in [vision.md](vision.md);
the rules for commands and flags are in [ux.md](ux.md). The user guide is
[docs/features/queues.md](../features/queues.md).

Status: **Apache Kafka done** (and anything that speaks the Kafka protocol:
Redpanda, Amazon MSK, Confluent Cloud, Aiven, WarpStream). Other engines
(RabbitMQ, NATS JetStream, Amazon SQS) come later behind the same verbs.

## One family, a human word

The command is `komando queue`, a human word like `cache`, `storage` and
`cluster`. Product names only appear as URL schemes (`kafka://`) and as an
alias (`komando kafka` is `komando queue`). Every engine gets the same verbs
where they make sense; a verb an engine cannot do answers `NOT_SUPPORTED`
with a hint, never a different meaning.

In Kafka words a queue is a **topic**. The docs say "topic" for Kafka and
"queue" for the family; the JSON field is `topic` for Kafka output.

## Conn URL

```
kafka://[USER@]HOST[:PORT][,HOST[:PORT]...][?OPTIONS]
```

- `HOST:PORT,...` are the seed brokers. One is enough; komando asks it for
  the others. The port defaults to 9092. `conn test` and `conn show` use
  the first one; the client gets them all.
- `USER` is the SASL user. Its password comes from `--password-ref` (or
  `--ask-password`), never from the URL (`URL_HAS_PASSWORD`).
- The path must be empty: a Kafka cluster has no databases.

| Option | Meaning |
|---|---|
| `tls=true` | TLS, checking the brokers' certificates against this computer's CAs |
| `ca=secret:NAME` | also trust the PEM CA certificate in the vault (a private CA, a cloud's own); needs `tls=true` |
| `tls=skip-verify` | TLS without checking the certificate (doctor warns; prefer `ca=`) |
| `sasl=plain` | SASL PLAIN login (needs USER; use it with TLS) |
| `sasl=scram-sha-256`, `sasl=scram-sha-512` | SASL SCRAM login (needs USER) |
| `insecure=1` | accept a plain (no TLS) connection that crosses the network |

Examples:

```
kafka://broker1.internal:9092                                   # --via an SSH server
kafka://app@b1.example.com:9093,b2.example.com:9093?tls=true&sasl=scram-sha-512
kafka://app@kafka.internal:9093?tls=true&ca=secret:kafka-ca&sasl=plain
```

Rules, the same as for caches:

- A USER without `sasl=` is refused (komando does not guess the mechanism),
  and so is `sasl=` without a USER.
- `kafka://` without `tls=true` straight over the network (no `--via`, not
  this computer) is refused by `conn add` and `conn edit --url` with
  `INSECURE_PROTOCOL` unless `?insecure=1`; `komando doctor` warns about
  older conns and about `tls=skip-verify`. The weak settings need a person's
  yes for an AI agent, as everywhere.

### `--via` and VPNs

Kafka clients first talk to a seed broker, then to the brokers it
*advertises*. komando dials every one of them through the conn's `--via`
path (an SSH server, a chain, or a VPN), so the advertised names are looked
up there, where they mean something. TLS is added on top of that dial, with
the broker's own name, so certificates are checked against the name the
broker advertises. This is the same `DialFunc` the caches use.

## Verbs

| Verb | What it does | Risk |
|---|---|---|
| `queue info CONN` | cluster id, controller, brokers (id, address, rack), Kafka version guess, topic count | read |
| `queue ls CONN [PATTERN]` | topics with partitions, replication factor and message count (end minus start offset); `--internal` adds `__consumer_offsets` and friends | read |
| `queue describe CONN TOPIC` | partitions (leader, replicas, in-sync replicas, offsets, messages), the settings that differ from the defaults, and the consumer groups reading it with their lag | read |
| `queue peek CONN TOPIC` | the newest `-n` messages (default 10), or the first ones with `--oldest`; `--partition` for one | read |
| `queue groups CONN` | consumer groups: state, members, topics, total lag | read |
| `queue lag CONN GROUP` | one group's lag per topic and partition, and which member reads it | read |
| `queue send CONN TOPIC` | publish one message from `--value`, `--from FILE` or stdin, with `--key`, `--header K=V`, `--partition` | change |
| `queue create CONN TOPIC` | a new topic, `--partitions`, `--replicas`, `--config K=V` | change |
| `queue rm CONN TOPIC...` | delete topics and every message in them | destructive |
| `queue purge CONN TOPIC` | delete every message in a topic, keep the topic | destructive |

### Reading never changes anything

`peek` reads like a consumer without a group: it asks each partition for
the offsets it wants and reads them directly. It never joins a group and
never commits an offset, so no application's position moves and no message
is removed (Kafka never removes on read anyway). It stops once it has the
messages that were there when it started, or after `--timeout`.

Message values are shown as text when they are UTF-8, otherwise as base64
with `"encoding": "base64"`. When nothing arrives for `--wait` (a window can
have holes: compacted messages, transaction markers) peek stops and says
`partial`. Long values are cut at `max_output` like every
other output (`value_truncated`). Secrets in messages are hidden like in
any other output (`[hidden]`), and personal data on protected conns too.

### Changes

ux.md's polarity rule applies: a clear verb is the statement of intent, so
`send` and `create` need no `--write` (like `cache set` and
`storage upload`), and `--write` keeps its one meaning, "let a raw command
change things". There is no raw command in this family yet; when one comes
(`queue run`), it will only read unless `--write`.

- Every change on a protected conn needs a person's yes (`--yes`).
- `rm` and `purge` are destructive: they need `--allow-dangerous` (rules
  `queue-delete` and `queue-purge`, listed by `komando policy list`).
- `--dry-run` is real where the server allows it: `create` asks the broker
  to validate the topic without creating it (`validate_only`); `send`
  checks that the topic exists and which partition; `rm` and `purge` list
  what would go (topics and message counts). Nothing is sent.
- `send` refuses a value, key or header that holds a value komando hid
  (`HIDDEN_VALUE`), as every write does. A topic that does not exist is
  `TOPIC_NOT_FOUND` (komando never lets the broker create topics on the fly).
- The audit log records the conn, the topic, sizes and counts, never the
  message key, value or headers.

## Errors

| Code | When |
|---|---|
| `QUEUE_CONNECT` | the brokers cannot be reached or do not speak Kafka (TLS hints as for caches) |
| `QUEUE_AUTH` | the SASL login failed |
| `QUEUE_DENIED` | the user lacks the ACL for this (topic, group or cluster); exit 5, not a komando seatbelt |
| `TOPIC_NOT_FOUND`, `CONSUMER_GROUP_NOT_FOUND`, `PARTITION_NOT_FOUND` | no such topic, group or partition |
| `TOPIC_EXISTS` | `create` of a topic that is there |
| `QUEUE_ERROR` | anything else the broker says, with its message |

## Engines later

The verbs map like this; an engine adds a kind with `Family: "queue"`
and fills the same `queuex` interface.

| Verb | RabbitMQ | NATS JetStream | SQS |
|---|---|---|---|
| ls | queues (messages, consumers) | streams | queues |
| peek | basic.get + requeue (marks redelivered: documented) | direct get | not possible without hiding the message: `NOT_SUPPORTED` |
| send | publish to an exchange | publish | SendMessage |
| groups / lag | consumers per queue | consumers and pending | `NOT_SUPPORTED` |
| purge | queue.purge | stream purge | PurgeQueue |
