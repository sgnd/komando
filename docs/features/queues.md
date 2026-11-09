# Queues

Look at and work with message queues safely: Apache Kafka, and what speaks
its protocol (Redpanda, Amazon MSK, Confluent Cloud, Aiven).
[All features](README.md)

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

## Troubleshooting

| Code | What to do |
|---|---|
| `QUEUE_CONNECT` | the brokers cannot be reached, or want TLS (`?tls=true`) or a login (`?sasl=`); with `--via`, the advertised addresses must be reachable from there |
| `QUEUE_AUTH` | check the user, the `sasl=` mechanism and the password (`komando conn show NAME`) |
| `QUEUE_DENIED` | the user lacks a Kafka ACL for the topic, group or cluster: ask the cluster's admin |
| `TOPIC_NOT_FOUND`, `CONSUMER_GROUP_NOT_FOUND`, `PARTITION_NOT_FOUND` | check the name with `queue ls`, `queue groups` or `queue describe` |
| `TOPIC_EXISTS` | `queue create` of a topic that is there |

The design behind these commands is in
[docs/design/queue.md](../design/queue.md).
