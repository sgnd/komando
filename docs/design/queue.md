# Design: `komando queue`

The big goal and the roadmap for all families are in [vision.md](vision.md);
the rules for commands and flags are in [ux.md](ux.md). The user guide is
[docs/features/queues.md](../features/queues.md).

Status: **Apache Kafka done** (and anything that speaks the Kafka protocol:
Redpanda, Amazon MSK, Confluent Cloud, Aiven, WarpStream), **RabbitMQ
done** (AMQP 0-9-1, [below](#rabbitmq)), **NATS JetStream done**
([below](#nats-jetstream)), **Amazon SQS done** ([below](#amazon-sqs)),
**Google Cloud Pub/Sub done** ([below](#google-cloud-pubsub)).

## One family, a human word

The command is `komando queue`, a human word like `cache`, `storage` and
`cluster`. Product names only appear as URL schemes (`kafka://`) and as an
alias (`komando kafka` is `komando queue`). Every engine gets the same verbs
where they make sense; a verb an engine cannot do answers `NOT_SUPPORTED`
with a hint, never a different meaning.

In Kafka words a queue is a **topic**; in NATS words a **stream**. The
docs say "topic" for Kafka and "queue" for the family; the JSON field is
`topic` for Kafka output, `queue` for RabbitMQ and SQS, `stream` for
NATS, and `topic` or `subscription` for Pub/Sub. The
shared result types (queuex `Info`, `Topic`, `TopicDetail`, `Group`,
`GroupLag`, `Received`, `Sent`, `Created`) embed one part per engine
(`KafkaInfo`, `RabbitInfo`, `NatsInfo`, `SqsInfo`, `PubsubInfo`, ...), so each engine's JSON holds
only its own fields, and `info` says `"engine"`. Two engines' parts sit at
the same level of the JSON, so a field name one engine uses with another
meaning gets a name of its own (NATS: `consumer_count`, `num_replicas`,
`consumer_info`, `time`; SQS: `account_id`, `created_at`, `sent_at`;
Pub/Sub: `api_endpoint`, `topic_count`, `id`, `kms_key_name`). A field
two parts share at the same level would vanish from the JSON (Go drops
both), so even the same meaning needs its own name.

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
| `QUEUE_NOT_FOUND`, `QUEUE_EXISTS` | RabbitMQ: no such queue in the vhost, or `create` of one that is there |
| `STREAM_NOT_FOUND`, `STREAM_EXISTS`, `CONSUMER_NOT_FOUND` | NATS: no such stream (or no stream keeps the subject `send` was given), `create` of one that is there, no such consumer |
| `SUBSCRIPTION_NOT_FOUND`, `SUBSCRIPTION_EXISTS` | Pub/Sub: no such subscription, or `create` of one that is there |
| `DELIVERY_LIMIT_NEAR` | RabbitMQ quorum queue, SQS queue with a dead-letter queue, or Pub/Sub subscription with a dead-letter topic: a message peek showed is close to its delivery (receive) limit (exit 8) |
| `NOT_SUPPORTED` | a verb or flag the engine cannot do, with what works instead |
| `QUEUE_ERROR` | anything else the broker says, with its message |

## RabbitMQ

The engine is internal/queuex/rabbitmq on github.com/rabbitmq/amqp091-go
(BSD-2, pure Go); it registers itself with queuex for the kind `rabbitmq`.

```
amqp[s]://[USER@]HOST[:PORT][/VHOST][?OPTIONS]
```

- `amqps://` is TLS, port 5671; `amqp://` is plain, port 5672. TLS is added
  on top of the conn's dial (direct, `--via`, VPN), checked against the
  host's name.
- The path is one vhost, URL-encoded: nothing, `/` or `%2F` is the default
  vhost `/`. A path with a second `/` is refused.
- `USER` logs in with PLAIN; the password comes from `--password-ref`. No
  user is RabbitMQ's `guest` (password `guest` unless a reference says
  otherwise), which RabbitMQ only lets in from the server itself (`--via`).
- Options: `management=PORT` (the management HTTP API on the same host,
  HTTPS for `amqps://`, same CA and login; only a port, so the password
  never goes to a host the URL does not name), `ca=secret:NAME` and
  `tls=skip-verify` (amqps only, not together), `insecure=1`.
- `amqp://` straight over the network is refused like `redis://`
  (`INSECURE_PROTOCOL`); doctor suggests the `amqps://` URL on port 5671.

| Verb | RabbitMQ |
|---|---|
| info | server properties of the AMQP login (product, version, cluster name, Erlang); with management also `/api/overview` totals and `/api/nodes` |
| ls | management only (`/api/queues/VHOST`): type, durable, messages, ready, unacked, consumers, state; otherwise `NOT_SUPPORTED` with the hint to add `?management=` |
| describe | management: `/api/queues/VHOST/NAME` (arguments, policy, node or leader, consumer details); otherwise a passive `queue.declare` (ready messages and consumers) |
| peek | `basic.get` without ack up to `-n`, then one `nack(multiple, requeue)`: see below |
| send | `basic.publish` to the default exchange with the queue as routing key, `mandatory`, persistent, in confirm mode; waits for the ack. A passive declare first gives `QUEUE_NOT_FOUND` and the dry run |
| create | a passive declare first (`QUEUE_EXISTS`, since a second declare would say "ok"), then a durable `queue.declare` with `--type` as `x-queue-type` and `--config` as arguments (numbers and booleans typed). The dry run makes nothing: RabbitMQ has no validate-only declare |
| rm | passive declares (messages, consumers), every name must exist, then `queue.delete` |
| purge | `queue.purge`: only ready messages; unacked ones stay |
| groups, lag | `NOT_SUPPORTED`: no consumer groups; `describe` shows consumers |

AMQP calls take no context, so every call runs on its own channel and a
`--timeout` closes the connection. A passive declare of a missing queue
closes its channel, which is why each call gets a fresh one.

### peek does not lose messages

peek holds the messages it took (unacked) and gives them all back, also
after an error; if the connection drops, RabbitMQ requeues them itself.
Requeued messages are marked **redelivered**, which consumers may see.

Quorum queues count every return as a delivery (`x-delivery-count`), and
since RabbitMQ 4.0 drop or dead-letter a message after 20 deliveries by
default (tested: a message peeked 21 times is gone). A return without the
count does not exist in AMQP 0-9-1, so peek guards instead: it reads the
queue's type and limit from the management API (`x-delivery-limit` or the
policy's `delivery-limit`; otherwise 20 on RabbitMQ 4 and none before),
shows each message's `deliveries`, and stops with `DELIVERY_LIMIT_NEAR`
(exit 8) once a message it gave back has fewer than 3 deliveries left.
AMQP shows neither the type nor the queue's own limit, and assuming the
default would lose a message on a queue with a lower one, so without
`?management=` (or when the management API fails) peek refuses before it
takes a message (`NOT_SUPPORTED`). A stream queue would end the whole
connection on `basic.get`, which this check also prevents.

## NATS JetStream

The engine is internal/queuex/nats on github.com/nats-io/nats.go and its
`jetstream` package (Apache-2.0, pure Go; NKeys from
github.com/nats-io/nkeys, Apache-2.0); it registers itself with queuex for
the kind `nats`. A queue is a JetStream **stream**: it keeps the messages
sent to its subjects. Plain (core) NATS keeps no messages, so there is
nothing to list or peek without JetStream.

```
nats://[USER@]HOST[:PORT][,HOST[:PORT]...][?OPTIONS]
tls://[USER@]HOST[:PORT][,HOST[:PORT]...][?OPTIONS]
```

- `tls://` is TLS, `nats://` is plain; the port defaults to 4222 for both.
  TLS is checked against the name of the server komando dials. A server
  that requires TLS gets it on `nats://` too (nats.go upgrades), checked
  against this computer's CAs.
- The servers are tried in the order written, once each; komando does not
  reconnect and does not use the servers a cluster advertises
  (`IgnoreDiscoveredServers`), so every connection goes where the URL and
  `--via` say. `conn test` and `conn show` use the first one.
- The path must be empty.
- The login: `USER` with `--password-ref` (user and password); a password
  reference without a user is sent as a **token**; `?creds=secret:NAME`
  logs in with a `.creds` file (a user JWT and the NKey seed that signs
  the server's challenge, as NGS and Synadia Cloud give) kept in the
  vault. A user and `creds=` together are refused.
- Options: `creds=secret:NAME`, `domain=NAME` (the JetStream domain, for a
  leaf node), `ca=secret:NAME` and `tls=skip-verify` (tls:// only, not
  together), `insecure=1`.
- `nats://` straight over the network is refused like `redis://`
  (`INSECURE_PROTOCOL`); doctor suggests the `tls://` URL.

| Verb | NATS |
|---|---|
| info | the server's INFO (version, name, id, cluster, max payload) and the account's JetStream use and limits (`$JS.API.INFO`); `jetstream: false` when the server or account has none |
| ls | streams (`STREAM.LIST`): subjects, messages, bytes, consumer count, storage, retention, replicas; key-value buckets (`KV_*`) and object stores (`OBJ_*`) are streams and are listed; `--internal` is `NOT_SUPPORTED` |
| describe | one stream (`STREAM.INFO`): settings, limits, sequence range, deleted count, cluster leader and replicas, mirror and sources, and its consumers (`CONSUMER.LIST`) |
| peek | `STREAM.MSG.GET` (or the direct get when the stream allows it) by sequence: see below |
| send | look up the stream that keeps the subject (`STREAM.NAMES` with the subject); `STREAM_NOT_FOUND` when none does, then a JetStream publish that waits for the stream's ack (sequence, duplicate). The dry run stops after the lookup |
| create | a stream: subjects (`--config subjects=a.>,b.*`, by default the stream's name), `storage`, `retention`, `discard`, `max_msgs`, `max_bytes`, `max_age` (24h, 7d), `max_msg_size`, `max_msgs_per_subject`, `max_consumers`, `duplicate_window`, `description`; `--replicas` is `num_replicas`. A name that is there is `STREAM_EXISTS`. JetStream has no validate-only create, so the dry run checks the name and komando's reading of the settings and makes nothing |
| rm | every name must exist (dry run: messages and consumers), then `STREAM.DELETE`; its consumers go with it |
| purge | `STREAM.PURGE`: every message; the stream and its consumers stay |
| groups | every stream's consumers: name, stream, pull or push, ack policy, filter subjects, pending (not given yet; this is `lag`), ack pending, redelivered, waiting pull requests. `state` is paused, active (a push consumer with a subscriber, or waiting pull requests) or idle |
| lag | one consumer, named `STREAM/CONSUMER`, or by its name alone when one stream has it (two: `USAGE` with both). `partitions` is empty: a stream has none |

`--key`, `--partition`, `--type` and `create --partitions` answer
`NOT_SUPPORTED` with what to use instead.

### peek reads by sequence

Every message in a stream has a sequence number. peek asks the stream for
messages by number: no consumer is made, nothing is acknowledged, so
nothing moves and nothing is removed, also on a work-queue stream (where a
consumer's ack would delete the message). `--oldest` asks for the first
message at or after the stream's first sequence, again and again
(`next_by_subj: ">"`), so deleted messages in between cost nothing. The
newest are the last `-n` sequences when the stream has no deleted messages
in the middle; with some, komando asks the stream which ones
(`deleted_details`) and reads only the others. Past 100000 deleted ones it
reads the last `-n` sequences only and says `partial` when that gave fewer.
The headers a direct get adds (`Nats-Stream`, `Nats-Sequence`, ...) are left
out: the result says the stream, the subject, the sequence and the time.

### Errors

A JetStream request the user may not make shows as no answer (the server
says why on its own, as an asynchronous `Permissions Violation`); komando
keeps that reason and answers `QUEUE_DENIED`. No JetStream at all is
`NOT_SUPPORTED` (with the hint about `?domain=` for leaf nodes).

## Amazon SQS

The engine is internal/queuex/sqs. It speaks the SQS JSON API
(`POST /` with `X-Amz-Target: AmazonSQS.<Action>`) over komando's own HTTP
client, so every request goes through the conn's dial (direct, `--via`,
VPN), and signs it with the SigV4 signer of the AWS SDK core
(github.com/aws/aws-sdk-go-v2/aws/signer/v4, Apache-2.0), which komando
already builds in for Secrets Manager, ECR and Session Manager. No SQS SDK
module is added. It registers itself with queuex for the kind `sqs`.

```
sqs://[ACCESS_KEY_ID@]REGION[?OPTIONS]
```

- The conn is one region of one account; queues are given to each
  command, like Kafka topics. Putting the queue in the URL
  (`sqs://REGION/QUEUE`) was left out: one conn would then reach one
  queue only, unlike every other engine, and `ls` would mean nothing.
  The account is not in the URL either: SQS finds a queue by name in the
  login's own account; `?account=ID` names another one
  (`QueueOwnerAWSAccountId`).
- The endpoint is `https://sqs.REGION.amazonaws.com` (`.amazonaws.com.cn`
  for `cn-` regions), or `?endpoint=URL` (a VPC endpoint, LocalStack,
  moto). An `http://` endpoint straight over the network is refused with
  `INSECURE_PROTOCOL` unless `?insecure=1`: the messages and a session
  token would travel in the clear (the secret key never does: SigV4 only
  sends a signature). doctor flags it like an `http://` S3 endpoint.
- The login, as for komando's other AWS clients (internal/cloud/aws.go):
  1. `--option aws_profile=NAME`: the profile's current keys from
     `~/.aws` (SSO included; `komando login aws --profile NAME` renews it;
     `AWS_LOGIN_REQUIRED` and `AWS_PROFILE_NOT_FOUND` as for S3 and ECR);
  2. `ACCESS_KEY_ID@` in the URL with the secret key from
     `--password-ref` (a password reference without a key ID is refused);
  3. neither: the SDK's usual chain (`AWS_*` variables, the default
     profile, the instance's or task's role through IMDS).
  The CLI resolves 1 and 3 (internal/cli/queue_sqs.go) and hands the keys
  to `sqs.OpenKeys`; the keys live only in memory for the command.
- The endpoint's own `AWS_ENDPOINT_URL` variables are not read: the URL
  says where the conn goes, so `--via` and the audit log name the right
  place.

| Verb | SQS |
|---|---|
| info | region, endpoint, the account (from the queues' URLs or `?account=`), queue count (`ListQueues`, every page) |
| ls | `ListQueues` with the pattern's literal start as `QueueNamePrefix`, then `GetQueueAttributes` per queue (8 at a time): waiting, in flight, delayed, FIFO, dead-letter queue and `maxReceiveCount`; `--internal` is `NOT_SUPPORTED` |
| describe | `GetQueueUrl`, `GetQueueAttributes` (All): counts, visibility timeout, retention, delay, size limit, receive wait, encryption, redrive policy, the rest as `attributes`; `ListDeadLetterSourceQueues` and `ListQueueTags` when the login may (otherwise left out) |
| peek | `ReceiveMessage` with `VisibilityTimeout: 0`, never `DeleteMessage`: see below |
| send | `GetQueueUrl` and the queue's attributes (`QUEUE_NOT_FOUND`, FIFO, size limit), then `SendMessage`; `--header` as String message attributes; FIFO: `--key` is the `MessageGroupId` (required), and a random `MessageDeduplicationId` unless the queue deduplicates by content. Bodies that are not SQS text are refused before sending. The dry run stops after the checks |
| create | `GetQueueUrl` first (`QUEUE_EXISTS`: `CreateQueue` with the same settings would answer with the queue that is there), then `CreateQueue`; `.fifo` names get `FifoQueue=true`; `--config` takes SQS attribute names (any case), FIFO-only ones are refused for standard queues. The dry run makes nothing: SQS has no validate-only create |
| rm | every name must exist (dry run: messages, in flight and delayed), then `DeleteQueue` |
| purge | `PurgeQueue`: every message, in flight too; SQS allows one per 60 seconds (`QUEUE_ERROR` with that hint) |
| groups, lag | `NOT_SUPPORTED`: SQS has no consumer groups |

`--key` on a standard queue, `--partition`, `--type`, `--oldest` and
`create --partitions`/`--replicas` answer `NOT_SUPPORTED` with what to
use instead.

### peek hides nothing and deletes nothing

A normal receive hides the message for the queue's visibility timeout and
the consumer deletes it when done. peek asks for a visibility timeout of 0
and never deletes, so every message stays visible and in the queue, and
consumers can receive it at once. It long-polls one second per call (so a
queue with few messages still answers) and stops when a call brings no
message it has not seen, or when it has as many as SQS counted: SQS gives
no set order and hands the same messages out again, and every extra call
would raise their receive counts. `from` is `sample`.

Each receive raises a message's `ApproximateReceiveCount`, and a queue with
a redrive policy moves a message to its dead-letter queue once the count
passes `maxReceiveCount`. peek guards like the RabbitMQ quorum queue
check: it refuses a queue whose `maxReceiveCount` is 3 or less before
receiving anything, and stops with `DELIVERY_LIMIT_NEAR` (exit 8) once a
message it showed has fewer than 3 receives left. The result says the
limit (`delivery_limit`) and each message's `receive_count`.

### Errors

SQS answers `{"__type": "...#Code", "message": ...}` (or the older
`x-amzn-query-error` header). `QueueDoesNotExist` is `QUEUE_NOT_FOUND`,
`QueueNameExists` is `QUEUE_EXISTS`, `AccessDenied` and `KmsAccessDenied`
are `QUEUE_DENIED` (exit 5), keys SQS does not take
(`InvalidClientTokenId`, `SignatureDoesNotMatch`, `ExpiredToken`, ...) are
`QUEUE_AUTH`, the 60-second rules (`QueueDeletedRecently`,
`PurgeQueueInProgress`) and the rest are `QUEUE_ERROR` with a hint. An
endpoint that does not answer SQS JSON is `QUEUE_CONNECT`.

## Google Cloud Pub/Sub

The engine is internal/queuex/pubsub. It speaks the Pub/Sub REST API (v1,
JSON) over komando's own HTTP client, so every request goes through the
conn's dial (direct, `--via`, VPN). The login uses golang.org/x/oauth2 and
its google package (BSD-3), which komando already builds in for gs://
storage and `gcp-sm:` secrets. No Google Cloud SDK module is added. It
registers itself with queuex for the kind `pubsub`.

```
pubsub://PROJECT[?OPTIONS]
```

- The conn is one Google Cloud project (its ID: 6 to 30 lowercase
  letters, digits and hyphens); topics and subscriptions are given to each
  command. A user in the URL is refused: Google logins have no user name.
- The endpoint is `https://pubsub.googleapis.com`, or `?endpoint=URL`: a
  regional endpoint (`https://europe-west1-pubsub.googleapis.com`), a
  Private Service Connect one, or the emulator
  (`http://localhost:8085`). An `http://` endpoint straight over the
  network is refused with `INSECURE_PROTOCOL` unless `?insecure=1`;
  doctor flags it like an `http://` S3 or SQS endpoint.
- The login is the one gs:// storage uses: the conn's `--password-ref`
  holds a service account key (the JSON file from the console), or else
  gcloud's application default credentials
  (`GOOGLE_APPLICATION_CREDENTIALS`, the file
  `gcloud auth application-default login` writes, or the metadata server
  on Google Cloud). The scope asked for is Pub/Sub only. Tokens are
  fetched through the conn's dial too.
- **A login only travels over HTTPS.** The emulator takes no login, so an
  `http://` endpoint gets none: a key in `--password-ref` there is refused
  (`USAGE`), and application default credentials are not used. On
  Google's own endpoints a missing login is `QUEUE_AUTH`; an HTTPS
  endpoint of its own may go without one.

### Topics and subscriptions

Pub/Sub keeps messages in **subscriptions**, not in topics: a topic hands
every message to each of its subscriptions, and the programs that pull
from one subscription share its messages. So a subscription is what the
family calls a consumer group, and also what holds the messages to read.

A name given to a command is `NAME`, `topics/NAME`, `subscriptions/NAME`
or the full `projects/PROJECT/topics/NAME` of the conn's project (another
project needs its own conn). A bare name means:

- a **topic** for `describe` (falling back to a subscription of that name
  when there is no such topic), `send`, `create` and `rm`;
- a **subscription** for `peek` and `purge`, the verbs that read or empty
  messages. A topic there gets a hint that lists its subscriptions.

Topics and subscriptions often share a name (`orders` and `orders`), so
`rm` never guesses: deleting a subscription is written
`subscriptions/NAME`.

The REST API does not count messages (Cloud Monitoring has the backlog as
`subscription/num_undelivered_messages`, a separate API and role). The
shared `messages` fields are `-1` ("not known") for Pub/Sub, and the text
says so instead of a number. `lag` answers `NOT_SUPPORTED` for the same
reason.

| Verb | Pub/Sub |
|---|---|
| info | project, endpoint, topic and subscription counts (`topics.list` and `subscriptions.list`, every page) |
| ls | `topics.list`, with each topic's subscription count (one `subscriptions.list`) and its own message retention; `--internal` is `NOT_SUPPORTED` |
| describe | a topic: labels, retention, KMS key, schema, allowed regions and its subscriptions with their settings; a subscription: topic, delivery (pull, push, bigquery, cloud-storage), ack deadline, retention, ordering, exactly-once, filter, dead-letter topic and `maxDeliveryAttempts`, state |
| peek | `subscriptions.pull` without ack, then `modifyAckDeadline` 0: see below |
| groups | `subscriptions.list`: each subscription as a line (`members` 0 and `lag` -1: Pub/Sub does not say) |
| send | `topics.get` (`TOPIC_NOT_FOUND`, and the dry run), then `topics.publish`: the value as data, `--header` as attributes, `--key` as the ordering key. An empty message without attributes is refused |
| create | a topic, or a subscription when the name is `subscriptions/NAME` or `--config topic=TOPIC` is given. `--config` takes Pub/Sub's names (any case): topics `messageRetentionDuration`, `kmsKeyName`; subscriptions `topic`, `ackDeadlineSeconds`, `messageRetentionDuration`, `retainAckedMessages`, `enableMessageOrdering`, `enableExactlyOnceDelivery`, `filter`, `deadLetterTopic`, `maxDeliveryAttempts`, `pushEndpoint` (https only); `labels.KEY` on both. Durations take `7d`, `36h` or `600s`. A get first gives `TOPIC_EXISTS` or `SUBSCRIPTION_EXISTS` and, for a subscription, `TOPIC_NOT_FOUND` for its topic. The dry run makes nothing: Pub/Sub has no validate-only create |
| rm | every name must exist (dry run: which do, and a topic's subscription count), then delete. Deleting a topic leaves its subscriptions and their messages (their topic becomes `_deleted-topic_`); deleting a subscription deletes its messages |
| purge | `subscriptions.seek` to now: every message published before now counts as acknowledged, also those a subscriber pulled and has not acknowledged; the subscription stays, and other subscriptions keep theirs |
| lag | `NOT_SUPPORTED`: see above |

`--partition`, `--oldest`, `--type` and `create --partitions`/`--replicas`
answer `NOT_SUPPORTED` with what to use instead.

### peek gives every message back

A pull hands messages out for the subscription's ack deadline: until then
no other subscriber gets them, and a subscriber that acknowledges one
removes it. peek never acknowledges. It pulls with `returnImmediately`
(so no pull is left waiting on the server to take messages after peek is
done), 8 at a time, holds what it got until it has `-n` or a few pulls in
a row bring nothing new, and then gives every one back with
`modifyAckDeadline` 0, also after an error or a timeout (with a little
time of its own). Pub/Sub then delivers them again at once. While peek
runs (a second or two) the messages it holds are not given to other
subscribers; if komando stops before giving them back, Pub/Sub gives them
out again after the ack deadline anyway. The result says `requeued`, and
`from` is `pulled`. A pull that returns at once can come back empty while
messages wait, so `no messages` says so; `more` is true when peek got as
many as it asked for, since Pub/Sub does not say how many wait.

With a dead-letter policy every delivery counts (`deliveryAttempt`), and
after `maxDeliveryAttempts` (5 to 100, default 5) Pub/Sub moves the message
to the dead-letter topic. peek guards like SQS and RabbitMQ quorum queues:
it refuses a subscription whose limit is 3 or less, and stops with
`DELIVERY_LIMIT_NEAR` (exit 8) once a message it showed has fewer than 3
deliveries left, after giving back what it pulled. Push, BigQuery and
Cloud Storage subscriptions are delivered by Pub/Sub itself, so peek
answers `NOT_SUPPORTED` there.

### Errors

Google answers `{"error": {"code", "status", "message"}}`. A 404 is
`TOPIC_NOT_FOUND` or `SUBSCRIPTION_NOT_FOUND` (on `conn test`: the project
ID is wrong); 409 `TOPIC_EXISTS` or `SUBSCRIPTION_EXISTS`; 401 and a token
Google would not give are `QUEUE_AUTH`; 403 `QUEUE_DENIED` (exit 5; the
hint names the IAM roles, and that the API may need enabling); 429 and
`RESOURCE_EXHAUSTED`, 400 (bad settings) and the rest are `QUEUE_ERROR`
with a hint. An endpoint that does not answer Pub/Sub JSON is
`QUEUE_CONNECT`. The service account key never appears in an error.
