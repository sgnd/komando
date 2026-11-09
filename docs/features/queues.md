# Queues

Look at and work with message queues safely: Apache Kafka, and what speaks
its protocol (Redpanda, Amazon MSK, Confluent Cloud, Aiven), and RabbitMQ.
[All features](README.md)

The same commands work for both. Kafka keeps messages in **topics**;
RabbitMQ keeps them in **queues**. Where this page says "topic", read
"queue" for RabbitMQ. What is different for RabbitMQ is in
[RabbitMQ](#rabbitmq) below.

## Quick start

```bash
komando secret set kafka-pass
komando conn add events 'kafka://app@b1.example.com:9093,b2.example.com:9093?tls=true&sasl=scram-sha-512' --password-ref secret:kafka-pass
komando queue info events                     # brokers, controller, Kafka version
komando queue ls events                       # topics, partitions, message counts
komando queue peek events orders              # the newest 10 messages; no consumer group moves
komando queue lag events billing              # how far a consumer group is behind
```

In Kafka a queue is a **topic**: messages are kept in order in its
**partitions**, and a **consumer group** is an application that reads them
and remembers how far it got (its committed offset). **Lag** is how many
messages a group still has to read.

## Add a Kafka cluster

The URL lists one or more brokers (`HOST:PORT`, comma-separated; the port
defaults to 9092). One is enough: komando asks it for the others. The user
is for the SASL login and its password goes in the vault, never in the URL:

```bash
komando conn add events 'kafka://app@b1.example.com:9093?tls=true&sasl=scram-sha-512' --password-ref secret:kafka-pass
komando conn add events2 'kafka://app@kafka.internal:9093?tls=true&ca=secret:kafka-ca&sasl=plain' --ask-password
komando conn add local kafka://broker1.internal:9092 --via web1          # no TLS, through an SSH server
```

| Option | What it does |
|---|---|
| `tls=true` | TLS; the brokers' certificates are checked against your computer's CAs |
| `ca=secret:NAME` | also trust your own CA (a company CA, a cloud's own); store it with `komando secret set NAME < ca.pem` |
| `tls=skip-verify` | TLS without checking the certificate (`komando doctor` warns; prefer `ca=`) |
| `sasl=plain`, `sasl=scram-sha-256`, `sasl=scram-sha-512` | how to log in; needs a user in the URL |
| `insecure=1` | accept a connection without TLS that crosses the network |

- `kafka://` without `tls=true`, straight over the network (no `--via`,
  not this computer), would send the login and the messages unencrypted,
  so `conn add` refuses it with `INSECURE_PROTOCOL`: add `tls=true`, or
  `--via`, or `?insecure=1` to accept it (for an AI agent that needs a
  person's yes).
- A user without `sasl=`, or `sasl=` without a user, is refused: komando
  does not guess how the brokers want you to log in.
- `komando conn test events` logs in and shows the Kafka version.

### Through a bastion or a VPN

Kafka clients first ask a broker for the cluster's brokers, then connect to
the addresses the brokers **advertise**. With `--via`, komando reaches
every one of them through the bastion or the VPN, so names that only work
inside the network still work. If `conn test` stops with
`QUEUE_CONNECT`, check that the advertised addresses are reachable from the
`--via` server (`komando queue info` lists them).

## Look at topics and groups

These commands only read:

```bash
komando queue info events                     # brokers (id, address, rack), controller, version
komando queue ls events                       # every topic, with partitions, replicas, messages
komando queue ls events 'orders-*'            # topics matching a pattern
komando queue ls events --internal            # also __consumer_offsets and friends
komando queue describe events orders          # partitions, offsets, settings, the groups reading it
komando queue groups events                   # consumer groups: state, members, topics, lag
komando queue lag events billing              # one group, per topic and partition
```

- The message count is the end offset minus the start offset of each
  partition. On a compacted topic (`cleanup.policy=compact`) fewer messages
  may be left.
- `describe` shows only the settings that differ from the brokers'
  defaults (for example `retention.ms`).

## Read messages

```bash
komando queue peek events orders              # the newest 10 messages over all partitions
komando queue peek events orders -n 50 --partition 2
komando queue peek events orders --oldest -n 5   # the first ones still kept
```

`peek` reads straight from the partitions. **It never joins a consumer
group and never commits an offset**, so no application's position moves
and no message is removed. It stops once it has the messages that were
there when it started; if nothing comes for `--wait` (5 seconds), it stops
and says some may be missing.

- Values that are UTF-8 text are shown as they are; others come as base64
  (`"encoding": "base64"`). A value longer than `max_output` is cut
  (`value_truncated`, with its real `size`).
- For AI agents, secrets in messages show as `[hidden]`, and personal data
  on protected conns as `[hidden: email]` and the like.

## Send a message

```bash
komando queue send events orders --value '{"id": 42, "status": "paid"}' --key 42
komando queue send events orders --from ./order.json --header source=support
komando queue send events orders --value test --dry-run   # checks the topic, sends nothing
```

- The topic must exist (`TOPIC_NOT_FOUND`): komando never lets the brokers
  create one on the fly. Create it with `queue create`.
- `--key` picks the partition the usual way: the same key always goes to
  the same partition. `--partition N` picks one itself.
- The value comes from `--value`, from `--from FILE` (`-` for stdin), or
  from data piped on stdin. Kafka takes about 1 MiB per message by default.
- A protected conn needs `--yes`.
- The audit log records the topic and the size, never the message.

## Create, delete and empty topics

```bash
komando queue create events orders --partitions 6 --replicas 3 --dry-run
komando queue create events orders --partitions 6 --replicas 3 --config retention.ms=604800000
komando queue purge events orders-retry --dry-run         # how many messages would go
komando queue purge events orders-retry --allow-dangerous # delete every message, keep the topic
komando queue rm events old-orders --dry-run
komando queue rm events old-orders --allow-dangerous      # delete the topic and its messages
```

- `create --dry-run` asks the brokers to check the topic without making it,
  so a bad setting or more replicas than brokers shows now.
- Without `--partitions` and `--replicas` the brokers' defaults apply.
- `purge` and `rm` cannot be undone, so they need `--allow-dangerous`
  (rules `queue-purge` and `queue-delete` in `komando policy list`). Their
  `--dry-run` lists what would go.

## RabbitMQ

### Add a RabbitMQ server

```bash
komando secret set rabbit-pass
komando conn add jobs 'amqps://app@rabbit.example.com:5671/%2F?management=15671' --password-ref secret:rabbit-pass
komando conn add jobs2 'amqp://app@rabbit.internal:5672/prod?management=15672' --via web1 --password-ref secret:rabbit-pass
komando queue info jobs                       # version, cluster, nodes, totals
komando queue ls jobs                         # queues: messages, ready, unacked, consumers
komando queue peek jobs emails                # the first 10 messages; all of them go back
```

- `amqps://` is AMQP with TLS (port 5671 by default); `amqp://` has no
  TLS (port 5672). Like `redis://`, `amqp://` straight over the network
  (no `--via`, not this computer) is refused with `INSECURE_PROTOCOL`
  unless you add `?insecure=1`.
- The path is the **virtual host** (vhost). The default vhost is `/`,
  written `%2F` or left out (`amqp://app@rabbit.internal/`).
- The user's password goes in the vault (`--password-ref`), never in the
  URL. A URL without a user logs in as `guest` (password `guest`, or the
  one `--password-ref` gives). RabbitMQ lets `guest` in only from the
  server itself, so that works `--via` the server's SSH.

| Option | What it does |
|---|---|
| `management=PORT` | also use the management HTTP API on this port of the same host (HTTPS for `amqps://`), for `ls`, the nodes and the totals in `info`, and the details in `describe` |
| `ca=secret:NAME` | `amqps://`: also trust your own CA (`komando secret set NAME < ca.pem`) |
| `tls=skip-verify` | `amqps://` without checking the certificate (`komando doctor` warns; prefer `ca=`) |
| `insecure=1` | accept `amqp://` across the network without TLS |

The management API is the `rabbitmq_management` plugin. It takes users
with the `management`, `monitoring` or `administrator` tag; komando only
reads from it. Without `?management=`, komando uses AMQP alone: `info`
shows the server's version and `describe` shows how many messages wait and
how many consumers a queue has, but `ls` cannot list queues
(`NOT_SUPPORTED`).

### What each command does on RabbitMQ

```bash
komando queue describe jobs emails            # type, state, messages, arguments, consumers
komando queue peek jobs emails -n 5           # the first 5 messages; nothing is removed
komando queue send jobs emails --value '{"to": "a@example.com"}' --header source=support
komando queue create jobs emails --type quorum --config x-max-length=10000 --dry-run
komando queue purge jobs emails --dry-run     # how many messages wait
komando queue rm jobs emails --allow-dangerous
```

- **`peek` takes messages from the front of the queue and gives every one
  back.** It reads with `basic.get` and does not acknowledge, then returns
  them all (`nack` with requeue), so **nothing is removed**. Good to know:
  - RabbitMQ marks the messages it gets back as **redelivered**. A consumer
    that treats redelivered messages differently will see that flag.
  - For the moment peek holds them, no consumer gets them, and a busy
    queue may hand them out in a slightly different order afterwards.
  - If the connection breaks, RabbitMQ puts the messages back by itself.
  - A **quorum queue** counts each peek as one delivery
    (`x-delivery-count`). After its delivery limit (20 by default since
    RabbitMQ 4.0, or the queue's own `x-delivery-limit` or policy) it drops
    a message or sends it to its dead-letter queue. So peek shows the count
    (`deliveries`) and **stops with `DELIVERY_LIMIT_NEAR`** once a message
    has fewer than 3 deliveries left: do not peek that queue again. Only
    the management API tells a queue's type and its own limit, so **peek
    needs `?management=`** in the conn's URL: without it (or when the
    management API fails) peek stops before it takes a message
    (`NOT_SUPPORTED`, or the management API's error).
  - A **stream** queue cannot be peeked this way (`NOT_SUPPORTED`).
  - peek always reads from the front (`"from": "front"`); `--oldest`,
    `--partition` and `--wait` are for Kafka.
- `send` puts the message straight into the queue (through the default
  exchange), as a persistent message, and waits until the server confirms
  it. `--header KEY=VALUE` sets its headers; there is no `--key` or
  `--partition`.
- `create` makes a **durable** queue. `--type` picks `classic`, `quorum`
  or `stream` (left out: the vhost's default). `--config KEY=VALUE` sets
  the queue's arguments, such as `x-max-length=10000` or
  `x-overflow=reject-publish`. RabbitMQ cannot check a queue without
  making it, so `create --dry-run` only checks that the name is free. A
  queue that is there already is `QUEUE_EXISTS`.
- `purge` deletes the messages that wait (ready). Messages a consumer
  holds and has not acknowledged yet stay. `rm` deletes the queue and its
  messages, and cancels its consumers; `--dry-run` shows how many of each.
  Both need `--allow-dangerous`.
- `groups` and `lag` answer `NOT_SUPPORTED`: RabbitMQ has no consumer
  groups. `describe` shows a queue's consumers, the messages waiting for
  them (ready) and those not acknowledged yet (unacked).

## Troubleshooting

| Code | What to do |
|---|---|
| `QUEUE_CONNECT` | the brokers cannot be reached, or want TLS (`?tls=true`) or a login (`?sasl=`); with `--via`, the advertised addresses must be reachable from there |
| `QUEUE_AUTH` | check the user, the `sasl=` mechanism and the password (`komando conn show NAME`) |
| `QUEUE_DENIED` | the user lacks a Kafka ACL for the topic, group or cluster, or a RabbitMQ permission on the vhost or queue: ask the admin |
| `TOPIC_NOT_FOUND`, `CONSUMER_GROUP_NOT_FOUND`, `PARTITION_NOT_FOUND` | check the name with `queue ls`, `queue groups` or `queue describe` |
| `TOPIC_EXISTS` | `queue create` of a topic that is there |
| `QUEUE_NOT_FOUND`, `QUEUE_EXISTS` | RabbitMQ: no such queue in the conn's vhost, or one is there already; check the vhost in the URL's path |
| `DELIVERY_LIMIT_NEAR` | a message of a RabbitMQ quorum queue is close to its delivery limit: stop peeking that queue and let its consumers take the message |
| `NOT_SUPPORTED` | the engine cannot do this (RabbitMQ: `groups`, `lag`, `ls` and `peek` without `?management=`); the hint says what works instead |

The design behind these commands is in
[docs/design/queue.md](../design/queue.md).
