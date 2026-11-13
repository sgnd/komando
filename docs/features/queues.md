# Queues

Look at and work with message queues safely: Apache Kafka, and what speaks
its protocol (Redpanda, Amazon MSK, Confluent Cloud, Aiven), RabbitMQ,
NATS with JetStream, Amazon SQS and Google Cloud Pub/Sub.
[All docs](README.md)

The same commands work for all five. Kafka keeps messages in **topics**;
RabbitMQ and SQS keep them in **queues**; NATS keeps them in **streams**;
Pub/Sub keeps them in **subscriptions** of a topic. Where this page says
"topic", read "queue" for RabbitMQ and SQS and "stream" for NATS. What is
different for each is in [RabbitMQ](#rabbitmq),
[NATS JetStream](#nats-jetstream), [Amazon SQS](#amazon-sqs) and
[Google Cloud Pub/Sub](#google-cloud-pubsub) below.

## Quick start

```bash
komando secret set kafka-pass
komando conn add events 'kafka://app@b1.example.com:9093,b2.example.com:9093?tls=true&sasl=scram-sha-512' --password-ref secret:kafka-pass
komando queue info events                     # brokers, controller, Kafka version
komando queue list events                       # topics, partitions, message counts
komando queue peek events orders              # the newest 10 messages; no consumer group moves
komando queue lag events billing              # how far a consumer group is behind
```

In Kafka a queue is a topic: messages are kept in order in its
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
the addresses the brokers advertise. With `--via`, komando reaches
every one of them through the bastion or the VPN, so names that only work
inside the network still work. If `conn test` stops with
`QUEUE_CONNECT`, check that the advertised addresses are reachable from the
`--via` server (`komando queue info` lists them).

## Look at topics and groups

These commands only read:

```bash
komando queue info events                     # brokers (id, address, rack), controller, version
komando queue list events                       # every topic, with partitions, replicas, messages
komando queue list events 'orders-*'            # topics matching a pattern
komando queue list events --internal            # also __consumer_offsets and friends
komando queue list events -n 50                 # only the first 50 by name
komando queue describe events orders          # partitions, offsets, settings, the groups reading it
komando queue groups events                   # consumer groups: state, members, topics, lag
komando queue lag events billing              # one group, per topic and partition
```

- `ls` shows at most 1000 topics (or queues, or streams), the first by
  name; `-n` changes that. A longer list says so (`"truncated": true`, and
  a line in the text) so you can narrow it with a pattern.
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

`peek` reads straight from the partitions. It never joins a consumer
group and never commits an offset, so no application's position moves
and no message is removed. It stops once it has the messages that were
there when it started; if nothing comes for `--idle` (5 seconds), it stops
and says some may be missing. `--idle` is for Kafka only (`--wait` still works in this release); the other kinds
refuse it (`NOT_SUPPORTED`).

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
- A person at a terminal can leave `--allow-dangerous` out: komando says
  what would be deleted and asks for the topic's or queue's name instead
  (the count, when several go).

  ```
  $ komando queue purge events orders-retry
  This deletes every message in orders-retry (it stays).
  Type the name orders-retry to continue: orders-retry
  ```

  Anything else stops it and changes nothing. An AI agent gets
  `POLICY_BLOCKED` (exit 6) with the same reason, and adds
  `--allow-dangerous` only after the person agrees.

## RabbitMQ

### Add a RabbitMQ server

```bash
komando secret set rabbit-pass
komando conn add jobs 'amqps://app@rabbit.example.com:5671/%2F?management=15671' --password-ref secret:rabbit-pass
komando conn add jobs2 'amqp://app@rabbit.internal:5672/prod?management=15672' --via web1 --password-ref secret:rabbit-pass
komando queue info jobs                       # version, cluster, nodes, totals
komando queue list jobs                         # queues: messages, ready, unacked, consumers
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
  them all (`nack` with requeue), so nothing is removed. Good to know:
  - RabbitMQ marks the messages it gets back as redelivered. A consumer
    that treats redelivered messages differently will see that flag.
  - For the moment peek holds them, no consumer gets them, and a busy
    queue may hand them out in a slightly different order afterwards.
  - If the connection breaks, RabbitMQ puts the messages back by itself.
  - A **quorum queue** counts each peek as one delivery
    (`x-delivery-count`). After its delivery limit (20 by default since
    RabbitMQ 4.0, or the queue's own `x-delivery-limit` or policy) it drops
    a message or sends it to its dead-letter queue. So peek shows the count
    (`deliveries`) and stops with `DELIVERY_LIMIT_NEAR` once a message
    has fewer than 3 deliveries left: do not peek that queue again. It
    takes no message after that one, so the messages behind it are not
    counted down too. Only
    the management API tells a queue's type and its own limit, so peek
    needs `?management=` in the conn's URL: without it (or when the
    management API fails) peek stops before it takes a message
    (`NOT_SUPPORTED`, or the management API's error).
  - A stream queue cannot be peeked this way (`NOT_SUPPORTED`).
  - peek always reads from the front (`"from": "front"`), which is
    already the oldest; `--partition` and `--idle` are for Kafka.
- `send` puts the message straight into the queue (through the default
  exchange), as a persistent message, and waits until the server confirms
  it. `--header KEY=VALUE` sets its headers; there is no `--key` or
  `--partition`.
- `create` makes a durable queue. `--type` picks `classic`, `quorum`
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

## NATS JetStream

### Add a NATS server

```bash
komando secret set nats-pass
komando conn add stream 'tls://app@nats1.example.com:4222,nats2.example.com:4222' --password-ref secret:nats-pass
komando conn add stream2 nats://nats.internal:4222 --via web1 --password-ref secret:nats-pass
komando secret set ngs-creds < user.creds
komando conn add cloud 'tls://connect.ngs.global?creds=secret:ngs-creds'
komando queue info stream                     # version, server, the account's streams and limits
komando queue list stream                       # streams: subjects, messages, size, consumers
komando queue peek stream ORDERS              # the newest 10 messages; none is taken away
```

- `tls://` is NATS with TLS; `nats://` has no TLS. The port is 4222 by
  default. Like `redis://`, `nats://` straight over the network (no
  `--via`, not this computer) is refused with `INSECURE_PROTOCOL` unless
  you add `?insecure=1`.
- List several servers of a cluster with commas. komando tries them in
  that order and talks only to the servers in the URL (with `--via`, all
  of them are reached through the bastion or the VPN). It tries each server
  once and does not reconnect or follow the servers the cluster
  advertises.
- How komando logs in:
  - a user in the URL and `--password-ref`: user and password;
  - `--password-ref` without a user: the password is sent as a token;
  - `?creds=secret:NAME`: a `.creds` file (from `nsc`, NGS or Synadia
    Cloud) that you keep in the vault with `komando secret set NAME < user.creds`;
  - none of these: no login.
- `komando conn test stream` logs in and shows the server's version.

| Option | What it does |
|---|---|
| `creds=secret:NAME` | log in with the `.creds` file kept in the vault |
| `domain=NAME` | the JetStream domain, for a leaf node with its own JetStream |
| `ca=secret:NAME` | `tls://`: also trust your own CA (`komando secret set NAME < ca.pem`) |
| `tls=skip-verify` | `tls://` without checking the certificate (`komando doctor` warns; prefer `ca=`) |
| `insecure=1` | accept `nats://` across the network without TLS |

### Streams, subjects and consumers

Plain NATS forgets a message once it is delivered. **JetStream** keeps
messages in **streams**: a stream keeps every message sent to its
**subjects** (for example `orders.>`, every subject that starts with
`orders.`), numbered with a **sequence**. A **consumer** is an
application's place in a stream: what it has been given and what it has
acknowledged.

```bash
komando queue describe stream ORDERS          # settings, limits, sequences, cluster, consumers
komando queue groups stream                   # every consumer: pending, ack pending, waiting
komando queue lag stream ORDERS/billing       # one consumer (the name alone works when only one stream has it)
komando queue peek stream ORDERS -n 5         # the newest 5 messages
komando queue peek stream ORDERS --oldest     # the first ones still kept
komando queue send stream orders.new --value '{"id": 42}' --header source=support
komando queue create stream ORDERS --config subjects='orders.>' --config max_age=7d --dry-run
komando queue purge stream ORDERS --dry-run   # how many messages would go
komando queue rm stream ORDERS --allow-dangerous
```

- **`peek` reads messages by their sequence number.** It makes no consumer
  and acknowledges nothing, so no application notices and nothing is
  removed, also from a work-queue stream (where an acknowledgement
  deletes the message). By default it shows the newest `-n` messages;
  `--oldest` shows the first ones. Deleted messages in between are
  skipped. In a stream with more than 100000 deleted messages the newest
  may come out incomplete, and peek says so; `--oldest` always works.
- `send` takes a subject, not a stream name: `orders.new`, not
  `ORDERS`. komando first checks which stream keeps that subject; when
  none does, it stops with `STREAM_NOT_FOUND` (plain NATS would drop the
  message without a word). It then waits for the stream's acknowledgement
  and says the message's sequence. A `Nats-Msg-Id` header
  (`--header Nats-Msg-Id=order-42`) lets the stream drop duplicates.
  There is no `--key` or `--partition`.
- `create` makes a stream on disk (`storage=file`) that keeps messages
  until a limit (`retention=limits`). Its subjects are the stream's name
  unless you give `--config subjects=a.>,b.*`. Other settings:
  `storage=memory`, `retention=interest|workqueue`, `discard=old|new`,
  `max_msgs`, `max_bytes`, `max_age` (`24h`, `7d`), `max_msg_size`,
  `max_msgs_per_subject`, `max_consumers`, `duplicate_window`,
  `description`. `--replicas 3` keeps 3 copies on a cluster. JetStream
  cannot check a stream without making it, so `create --dry-run` checks
  the name and the settings only. A stream that is there already is
  `STREAM_EXISTS`.
- `purge` deletes every message of a stream; the stream and its consumers
  stay. `rm` deletes the stream, its messages and its consumers. Both need
  `--allow-dangerous`.
- `groups` lists consumers. **Pending** is what a consumer has not been
  given yet (shown as its lag); **ack pending** is what it was given and
  has not acknowledged yet. `state` is `active` (a push consumer with a
  subscriber, or a pull consumer with requests waiting), `idle` or
  `paused`.
- Key-value buckets (`KV_NAME`) and object stores (`OBJ_NAME`) are streams
  too, and `ls` lists them.
- A server or account without JetStream: `info` says `jetstream: false`,
  and the other commands answer `NOT_SUPPORTED`.

## Amazon SQS

### Add an SQS region

An SQS conn is one AWS region of one account. You give the queue's name to
each command, not in the URL. komando logs in with your AWS login, the
same way as for S3 buckets and ECR registries, and needs no aws CLI:

```bash
komando conn add sqs sqs://eu-west-1 --option aws_profile=prod   # a profile in ~/.aws (SSO, a role, keys)
komando login aws --profile prod              # a person renews an SSO login when it runs out
komando conn add sqs2 sqs://eu-west-1          # no profile: AWS_* variables, ~/.aws default, or the server's role
komando secret set sqs-secret                  # or: keys of an IAM user
komando conn add sqs3 sqs://AKIAIOSFODNN7EXAMPLE@eu-west-1 --password-ref secret:sqs-secret
komando queue info sqs                         # region, account, how many queues
komando queue list sqs                           # queues: waiting, in flight, delayed, dead-letter queue
komando queue peek sqs orders                  # up to 10 messages; none is hidden or deleted
```

- How komando logs in, in this order: the conn's `aws_profile` option
  (from `~/.aws/config` and `~/.aws/credentials`, SSO included); the
  access key ID in the URL with the secret key from `--password-ref`; or,
  with neither, the usual AWS chain (the `AWS_ACCESS_KEY_ID` and
  `AWS_PROFILE` variables, the default profile, an EC2 or ECS role).
- An expired SSO login stops with `AWS_LOGIN_REQUIRED`: a person runs
  `komando login aws --profile NAME` once.
- `komando conn test sqs` logs in and lists one queue.

| Option | What it does |
|---|---|
| `endpoint=URL` | another SQS server: a VPC endpoint, or an emulator such as LocalStack or moto (`http://localhost:4566`; at localhost with no key or profile, komando logs in with the key `test`) |
| `account=ID` | the 12-digit AWS account that owns the queues, to use queues another account shared with you |
| `insecure=1` | accept an `http://` endpoint across the network (no `--via`, not this computer) |

An `http://` endpoint straight over the network is refused with
`INSECURE_PROTOCOL` unless you add `?insecure=1`: the messages and a
temporary login's session token would travel unencrypted.

### What each command does on SQS

```bash
komando queue describe sqs orders             # counts, settings, dead-letter queue, tags
komando queue send sqs orders --value '{"id": 42}' --header source=support
komando queue send sqs orders.fifo --key customer-7 --value '{"id": 42}'
komando queue create sqs orders.fifo --config ContentBasedDeduplication=true --dry-run
komando queue create sqs jobs --config VisibilityTimeout=120 --config MessageRetentionPeriod=86400
komando queue purge sqs orders --dry-run      # about how many messages would go
komando queue rm sqs old-jobs --allow-dangerous
```

- **`peek` receives messages with a visibility timeout of 0 and never
  deletes them.** Normally a received message is hidden from other
  consumers for a while and then deleted by the consumer that got it.
  With a visibility timeout of 0 nothing is hidden, and komando never
  deletes, so every message stays and consumers can receive it at once.
- SQS hands out messages in no set order (a FIFO queue: in order within a
  message group), so `peek` shows a sample of what waits, not the
  newest. There is no `--oldest` or `--partition`.
- **Every receive counts.** SQS raises each message's receive count, also
  for a peek. A queue with a dead-letter queue moves a message there after
  `maxReceiveCount` receives (its `RedrivePolicy`). So peek refuses a queue
  whose limit is 3 or less, and stops with `DELIVERY_LIMIT_NEAR` once a
  message it showed has fewer than 3 receives left. Peek the dead-letter
  queue instead, or let the consumers take the message.
- The counts SQS gives are approximate. **Messages** are waiting to be
  received; **in flight** were received and not yet deleted; **delayed**
  were sent with a delay that has not passed yet.
- `send` takes text only; `--header` values become message attributes.
  A FIFO queue (its name ends in `.fifo`) needs `--key`, the message
  group: messages of one group are received in order. komando gives each
  FIFO message a new deduplication ID, unless the queue deduplicates by
  content.
- `create` makes a standard queue, or a FIFO queue when the name ends in
  `.fifo`. `--config` takes SQS's own setting names (`VisibilityTimeout`,
  `MessageRetentionPeriod`, `DelaySeconds`, `MaximumMessageSize`,
  `ReceiveMessageWaitTimeSeconds`, `RedrivePolicy`, `KmsMasterKeyId`,
  `ContentBasedDeduplication`, ...). SQS cannot check a queue without making
  it, so `create --dry-run` checks the name and the setting names only. A
  queue that is there already is `QUEUE_EXISTS`.
- `purge` deletes every message, also those in flight, and keeps the queue;
  SQS allows one purge per queue every 60 seconds. `rm` deletes the queue;
  SQS needs 60 seconds before a queue of the same name can be made again.
  Both need `--allow-dangerous`.
- `groups` and `lag` answer `NOT_SUPPORTED`: SQS has no consumer groups.
  `describe` shows how many messages are in flight.

## Google Cloud Pub/Sub

### Add a Pub/Sub project

A Pub/Sub conn is one Google Cloud project. You give the topic's or the
subscription's name to each command, not in the URL. komando logs in the
same way as for gs:// buckets and needs no gcloud or Google SDK:

```bash
komando conn add pubsub pubsub://my-project      # gcloud's login (application default credentials)
komando secret set pubsub-key < key.json      # or: a service account key
komando conn add pubsub2 pubsub://my-project --password-ref secret:pubsub-key
komando conn add local 'pubsub://test-project?endpoint=http://localhost:8085'   # the emulator: no login
komando queue info pubsub                         # how many topics and subscriptions
komando queue list pubsub                           # topics and how many subscriptions each has
komando queue groups pubsub                       # subscriptions: topic, delivery, ack deadline
komando queue peek pubsub billing                 # up to 10 messages of subscription billing; all given back
```

- How komando logs in: the service account key in `--password-ref`, or
  else your application default credentials (the
  `GOOGLE_APPLICATION_CREDENTIALS` file, the one
  `gcloud auth application-default login` makes, or the server's own
  account on Google Cloud). Give the login the role it needs:
  `roles/pubsub.viewer` to look, `roles/pubsub.subscriber` to peek,
  `roles/pubsub.publisher` to send, `roles/pubsub.editor` to create and
  delete.
- A login only ever travels over HTTPS. The emulator (`http://`) takes
  none, so komando sends none there: a key in `--password-ref` on an
  `http://` endpoint is refused (`USAGE`).
- `komando conn test pubsub` logs in and lists one topic.

| Option | What it does |
|---|---|
| `endpoint=URL` | another Pub/Sub server: a regional endpoint (`https://europe-west1-pubsub.googleapis.com`), a private one, or the emulator (`http://localhost:8085`) |
| `insecure=1` | accept an `http://` endpoint across the network (no `--via`, not this computer) |

An `http://` endpoint straight over the network is refused with
`INSECURE_PROTOCOL` unless you add `?insecure=1`: the messages would
travel unencrypted.

### Topics and subscriptions

In Pub/Sub you send to a topic, and the topic hands each message to
every one of its subscriptions. Messages wait in a subscription until a
program that pulls from it acknowledges them. So a subscription is where
the messages are, and also what other systems call a consumer group.

A name you give is a topic or a subscription:

- `peek` and `purge` take a subscription (`billing`).
- `describe`, `send`, `create` and `rm` take a topic (`orders`);
  `describe` also finds a subscription when there is no topic of that
  name.
- Write `subscriptions/NAME` (or `topics/NAME`) to say which, for example
  to delete a subscription: topics and subscriptions often share a name.

Pub/Sub does not count waiting messages (Cloud Monitoring does), so
`messages` is `-1` in the JSON and the text says "does not count". `lag`
answers `NOT_SUPPORTED`.

### What each command does on Pub/Sub

```bash
komando queue describe pubsub orders              # a topic and its subscriptions
komando queue describe pubsub subscriptions/billing
komando queue send pubsub orders --value '{"id": 42}' --header source=support --key customer-7
komando queue create pubsub orders --config messageRetentionDuration=7d --dry-run
komando queue create pubsub subscriptions/billing --config topic=orders --config ackDeadlineSeconds=60
komando queue purge pubsub billing --dry-run      # empties subscription billing
komando queue rm pubsub subscriptions/billing old-orders --dry-run
```

- **`peek` pulls messages and gives every one back unacknowledged.** It
  never acknowledges, so nothing is removed: when it is done it sets each
  message's ack deadline to 0 and Pub/Sub delivers it again at once. For
  the second or two peek runs, the messages it holds are not handed to
  other programs; if komando is stopped halfway, Pub/Sub hands them out
  again after the subscription's ack deadline. Pub/Sub gives no set order,
  so there is no `--oldest` or `--partition`.
- **With a dead-letter topic every delivery counts.** After
  `maxDeliveryAttempts` deliveries Pub/Sub moves a message to the
  dead-letter topic, and a peek is a delivery. So peek stops with
  `DELIVERY_LIMIT_NEAR` once a message it showed has fewer than 3 left.
  A subscription whose limit is 3 or less is refused before peek pulls
  anything.
  Let the subscribers take the message, or peek a subscription of the
  dead-letter topic.
- Push, BigQuery and Cloud Storage subscriptions are delivered by Pub/Sub
  itself: peek a pull subscription of the same topic instead.
- `send` publishes to a topic. `--header` values become attributes and
  `--key` is the ordering key (a subscription with ordering gets the
  messages of one key in order).
- `create NAME` makes a topic; `create subscriptions/NAME --config
  topic=TOPIC` makes a subscription. `--config` takes Pub/Sub's own
  setting names: `messageRetentionDuration` (`7d`, `36h`), `kmsKeyName`;
  for subscriptions also `ackDeadlineSeconds`, `retainAckedMessages`,
  `enableMessageOrdering`, `enableExactlyOnceDelivery`, `filter`,
  `deadLetterTopic`, `maxDeliveryAttempts` and `pushEndpoint`;
  `labels.KEY=VALUE` on both. Pub/Sub cannot check a topic without making
  it, so `create --dry-run` checks the names and settings only.
- `purge` empties a subscription and keeps it: every message published
  until now counts as acknowledged (a "seek" to now), also those a program
  pulled and has not acknowledged. The topic's other subscriptions keep
  theirs.
- `rm` deletes topics, or subscriptions written `subscriptions/NAME`.
  Deleting a topic does not delete its subscriptions: they keep their
  messages, cut off from the topic. Deleting a subscription deletes the
  messages waiting in it. Both `purge` and `rm` need `--allow-dangerous`.

## Limits

- RabbitMQ: a vhost whose name holds `/` is written URL-encoded (`%2F`);
  a path with a second `/` is refused.
- RabbitMQ and NATS: `ca=` and `tls=skip-verify` cannot be used together.
- NATS: a user in the URL and `creds=` together are refused: pick one.
- SQS: komando does not read `AWS_ENDPOINT_URL` or `AWS_ENDPOINT_URL_SQS`:
  the conn's URL says where it goes. Use `?endpoint=` for another server.
- Pub/Sub: the URL has no user. Google logins have none, and a user is
  refused. Topics of another project need a conn of their own.
- Pub/Sub: an empty message with no `--header` is refused.
- Pub/Sub: `pushEndpoint` must be an `https://` address.

## Troubleshooting

| Code | What to do |
|---|---|
| `QUEUE_CONNECT` | the brokers cannot be reached, or want TLS (`?tls=true`) or a login (`?sasl=`); with `--via`, the advertised addresses must be reachable from there |
| `QUEUE_AUTH` | check the user, the `sasl=` mechanism and the password (`komando conn show NAME`); SQS: the AWS profile or keys; Pub/Sub: the service account key, or `gcloud auth application-default login` |
| `AWS_LOGIN_REQUIRED`, `AWS_PROFILE_NOT_FOUND` | SQS: a person runs `komando login aws --profile NAME`, or fix the conn's `aws_profile` option |
| `QUEUE_DENIED` | the user lacks a Kafka ACL for the topic, group or cluster, a RabbitMQ permission on the vhost or queue, a NATS permission on the subject or the JetStream API, an IAM permission for SQS (`sqs:ReceiveMessage`, ...), or a Pub/Sub role (`roles/pubsub.subscriber`, ...; or the Pub/Sub API is not enabled): ask the admin |
| `TOPIC_NOT_FOUND`, `CONSUMER_GROUP_NOT_FOUND`, `PARTITION_NOT_FOUND` | check the name with `queue list`, `queue groups` or `queue describe` |
| `TOPIC_EXISTS` | `queue create` of a topic that is there |
| `QUEUE_NOT_FOUND`, `QUEUE_EXISTS` | RabbitMQ: no such queue in the conn's vhost, or one is there already; check the vhost in the URL's path. SQS: check the region (the URL's host) and, for another account's queue, `?account=` |
| `SUBSCRIPTION_NOT_FOUND`, `SUBSCRIPTION_EXISTS` | Pub/Sub: no such subscription (`queue groups` lists them; peek takes a subscription, not a topic), or one is there already |
| `DELIVERY_LIMIT_NEAR` | a message of a RabbitMQ quorum queue is close to its delivery limit, an SQS message close to its queue's `maxReceiveCount`, or a Pub/Sub message close to its subscription's `maxDeliveryAttempts`: stop peeking and let its consumers take the message |
| `STREAM_NOT_FOUND`, `STREAM_EXISTS`, `CONSUMER_NOT_FOUND` | NATS: no such stream (for `send`: no stream keeps that subject), one is there already, or no such consumer; `queue list` and `queue groups` show the names |
| `NOT_SUPPORTED` | the engine cannot do this (RabbitMQ: `groups`, `lag`, `ls` and `peek` without `?management=`; NATS without JetStream; SQS: `groups`, `lag`, `peek --oldest`; Pub/Sub: `lag`, `peek --oldest`, peek of a push subscription); the hint says what works instead |

The design behind these commands is in
[docs/design/queue.md](../design/queue.md).
