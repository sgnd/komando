package cli

import (
	"context"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/sgnd/komando/internal/capability"
	"github.com/sgnd/komando/internal/driver"
	"github.com/sgnd/komando/internal/out"
	"github.com/sgnd/komando/internal/queuex"
	_ "github.com/sgnd/komando/internal/queuex/nats"     // nats:// and tls:// conns
	_ "github.com/sgnd/komando/internal/queuex/pubsub"   // pubsub:// conns
	_ "github.com/sgnd/komando/internal/queuex/rabbitmq" // amqp:// and amqps:// conns
	_ "github.com/sgnd/komando/internal/queuex/sqs"      // sqs:// conns
	"github.com/sgnd/komando/internal/store"
)

// Queue commands (docs/features/queues.md), for Kafka, RabbitMQ, NATS
// JetStream, Amazon SQS and Google Cloud Pub/Sub: reading never moves a
// consumer group or removes a message; send and create change, so
// protected conns need --yes; rm and purge delete messages, so they also
// need --allow-dangerous. Every change has a real --dry-run.

func queueCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "queue",
		Short: "Queues (Kafka, RabbitMQ, NATS, SQS, Pub/Sub): read, send, manage",
		Long: `Read and send messages on Kafka, RabbitMQ, NATS, SQS and Pub/Sub. Add a queue
with ` + "`komando queue kafka add`" + ` (or rabbitmq, nats, sqs, pubsub).

info, topic list and show, message list and consumer list and show only
read: message list reads Kafka messages without joining a consumer group,
gives RabbitMQ and Pub/Sub messages straight back, reads NATS stream
messages by their number, and receives SQS messages without hiding or
deleting them, so nothing is removed. message create and topic create
change (production queues ask first); topic delete and message delete
--all delete messages, so they also need --allow-dangerous. Try any change
with --dry-run first. In RabbitMQ words a topic is a queue; in NATS words
it is a stream. Pub/Sub keeps messages in subscriptions: message list and
message delete --all take a subscription, and consumer list lists them.`,
		Example: `  komando queue kafka add prod-kafka kafka://10.0.0.8:9092 --via web1
  komando queue kafka topic list prod-kafka
  komando queue kafka message list prod-kafka orders -n 5
  komando queue kafka message create prod-kafka orders --value '{"id": 42}' --dry-run
  komando queue kafka consumer show prod-kafka billing`,
	}
}

// queueRules are the rules of the destructive queue commands (rm, purge),
// listed by `komando policy list`.
var queueRules = []driver.Rule{
	{ID: "queue-delete", Reason: "deletes topics (or queues, or streams) and every message in them"},
	{ID: "queue-purge", Reason: "deletes every message in a topic, queue or stream (it stays)"},
}

// queueRisk is the verdict of a queue change. For rm and purge the reason
// names the topics, so the person's prompt, the approval window and the
// agent's POLICY_BLOCKED message all say what would be deleted, not only
// on which conn.
func queueRisk(id string, topics ...string) driver.Verdict {
	for _, r := range queueRules {
		if r.ID != id {
			continue
		}
		reason := r.Reason
		switch {
		case len(topics) == 0:
		case id == "queue-purge":
			reason = "deletes every message in " + topics[0] + " (it stays)"
		case len(topics) == 1:
			reason = "deletes " + topics[0] + " and every message in it"
		default:
			reason = "deletes " + strings.Join(topics, ", ") + " and every message in them"
		}
		return driver.Verdict{Risk: driver.RiskDestructive, RuleIDs: []string{r.ID}, Reasons: []string{reason}}
	}
	return driver.Verdict{Risk: driver.RiskWrite}
}

type queueFn func(st *store.State, c *store.Conn, q queuex.Queue) (any, error)

// withQueue opens the conn's client, runs fn, and audits the action. A
// change is checked by GuardConns first; fn itself honours --dry-run.
func withQueue(cl *call, ctx context.Context, name, connExpr string, v driver.Verdict, rec map[string]any, fn queueFn) error {
	st, err := loadState()
	if err != nil {
		return err
	}
	c, err := singleConn(cl, st, connExpr, "queue")
	if err != nil {
		return err
	}
	if rec == nil {
		rec = map[string]any{}
	}
	rec["conns"], rec["risk"] = []string{c.Name}, v.Risk.String()
	fail := func(err error) error {
		rec["error"] = toErr(err).Code
		audit(cl, st, name, nil, "", false, rec)
		return err
	}
	if v.Risk > driver.RiskRead {
		if err := GuardConns(cl, st, []*store.Conn{c}, v); err != nil {
			return fail(err)
		}
	}
	a, err := openAccess(cl, ctx, st, c)
	if err != nil {
		return fail(err)
	}
	defer a.Close()
	timeout := dbTimeout(cl)
	cctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	q, err := openQueue(cl, cctx, c, a, timeout)
	if err != nil {
		return fail(viaTimeout(c, err))
	}
	defer q.Close()
	data, err := fn(st, c, q)
	if err != nil {
		return fail(err)
	}
	audit(cl, st, name, nil, "", true, rec)
	cl.out.Print(name, data, nil)
	return nil
}

// queueCtx is the command's context with the --timeout limit.
func queueCtx(cmd *cobra.Command) (context.Context, context.CancelFunc) {
	cl := callOf(cmd)
	return context.WithTimeout(cmd.Context(), dbTimeout(cl))
}

func queueInfoCmd() *cobra.Command {
	return &cobra.Command{
		Use:     "info CONN",
		Short:   "Server summary: version, brokers or nodes, topic, queue or stream count",
		Example: `  komando queue kafka info prod-kafka`,
		Args:    cobra.ExactArgs(1),
		RunE: inCall(func(cl *call, cmd *cobra.Command, args []string) error {
			return withQueue(cl, cmd.Context(), "queue.info", args[0], driver.Verdict{}, nil,
				func(_ *store.State, c *store.Conn, q queuex.Queue) (any, error) {
					ctx, cancel := queueCtx(cmd)
					defer cancel()
					inf, err := q.Info(ctx)
					if err != nil {
						return nil, err
					}
					return queueInfo{Conn: c.Name, Info: inf}, nil
				})
		}),
	}
}

func queueLsCmd() *cobra.Command {
	var internal bool
	var limit int
	c := &cobra.Command{
		Use:   "list CONN [PATTERN]",
		Short: "List topics (or queues, or streams) with their message counts",
		Example: `  komando queue kafka topic list prod-kafka
  komando queue kafka topic list prod-kafka 'orders-*'
  komando queue kafka topic list prod-kafka --internal
  komando queue kafka topic list prod-kafka -n 50`,
		Args: cobra.RangeArgs(1, 2),
		RunE: inCall(func(cl *call, cmd *cobra.Command, args []string) error {
			if limit < 1 {
				return out.Usage("--limit takes 1 or more")
			}
			pattern := ""
			if len(args) == 2 {
				pattern = args[1]
			}
			return withQueue(cl, cmd.Context(), "queue.list", args[0], driver.Verdict{}, map[string]any{"pattern": pattern},
				func(_ *store.State, c *store.Conn, q queuex.Queue) (any, error) {
					ctx, cancel := queueCtx(cmd)
					defer cancel()
					// one more than asked tells whether the list was cut
					ts, err := q.Topics(ctx, pattern, internal, limit+1)
					if err != nil {
						return nil, err
					}
					cut := len(ts) > limit
					if cut {
						cl.out.CutNoted()
					}
					ts = queuex.First(ts, limit)
					return queueTopics{Conn: c.Name, Topics: ts, Count: len(ts), Truncated: cut, kind: c.Kind}, nil
				})
		}),
	}
	c.Flags().BoolVar(&internal, "internal", false, "Kafka: also list its own topics (__consumer_offsets, ...)")
	c.Flags().IntVarP(&limit, "limit", "n", 1000, "the most topics (or queues, or streams) to show, the first by name")
	return c
}

func queueDescribeCmd() *cobra.Command {
	return &cobra.Command{
		Use:     "describe CONN TOPIC",
		Short:   "One topic, queue or stream: messages, settings, and who reads it",
		Example: `  komando queue kafka topic show prod-kafka orders`,
		Args:    cobra.ExactArgs(2),
		RunE: inCall(func(cl *call, cmd *cobra.Command, args []string) error {
			return withQueue(cl, cmd.Context(), "queue.describe", args[0], driver.Verdict{}, map[string]any{"topic": args[1]},
				func(_ *store.State, c *store.Conn, q queuex.Queue) (any, error) {
					ctx, cancel := queueCtx(cmd)
					defer cancel()
					d, err := q.Describe(ctx, args[1])
					if err != nil {
						return nil, err
					}
					return queueTopic{Conn: c.Name, TopicDetail: d}, nil
				})
		}),
	}
}

func queuePeekCmd() *cobra.Command {
	var limit, partition int
	var oldest bool
	var wait time.Duration
	c := &cobra.Command{
		Use:   "peek CONN TOPIC",
		Short: "Read the newest (or oldest) messages without removing any",
		Long: `Kafka: read messages straight from the topic's partitions. No consumer
group is joined and no offset is committed, so no application notices and
nothing is removed. By default the newest -n messages over all partitions;
--oldest reads the first ones still kept.

RabbitMQ: take the first -n messages of the queue (the next ones a consumer
would get) and give them all back. Nothing is removed, but RabbitMQ marks
them redelivered, and a quorum queue counts each peek as a delivery: peek
stops (DELIVERY_LIMIT_NEAR) before a message runs out of them.

NATS: read messages straight from the stream by their sequence number. No
consumer is made and nothing is acknowledged, so nothing is removed, also
from a work-queue stream. The newest -n by default, --oldest for the first.

Amazon SQS: receive messages with a visibility timeout of 0 and never
delete them, so they stay and consumers can receive them at once. SQS gives
messages in no set order, so this is a sample of what waits. Every receive
counts toward a dead-letter queue's maxReceiveCount: peek stops
(DELIVERY_LIMIT_NEAR) before a message runs out of receives.

Google Cloud Pub/Sub: TOPIC is a subscription (messages wait there, not
in a topic). peek pulls messages without acknowledging them and gives them
straight back (ack deadline 0), so they stay and are delivered again at
once. With a dead-letter topic each pull counts as a delivery: peek stops
(DELIVERY_LIMIT_NEAR) before a message runs out of them.

Values that are not UTF-8 text are shown as base64.`,
		Example: `  komando queue kafka message list prod-kafka orders
  komando queue kafka message list prod-kafka orders -n 50 --partition 2
  komando queue kafka message list prod-kafka orders --oldest -n 5`,
		Args: cobra.ExactArgs(2),
		RunE: inCall(func(cl *call, cmd *cobra.Command, args []string) error {
			if limit < 1 || limit > 10000 {
				return out.Usage("--limit takes 1 to 10000")
			}
			o := queuex.PeekOptions{Topic: args[1], Limit: limit, Oldest: oldest, Partition: int32(partition), Wait: wait}
			return withQueue(cl, cmd.Context(), "queue.peek", args[0], driver.Verdict{}, map[string]any{"topic": args[1], "limit": limit},
				func(st *store.State, c *store.Conn, q queuex.Queue) (any, error) {
					if flagChanged(cmd, "idle") && c.Kind != "kafka" {
						return nil, queuex.NotSupported("--idle", c.Kind, "only a Kafka peek waits for messages to arrive; drop --idle")
					}
					ctx, cancel := queueCtx(cmd)
					defer cancel()
					o.MaxBytes = maxOutput(cl, st)
					p, err := q.Peek(ctx, o)
					if err != nil {
						return nil, err
					}
					hideBinaryMessages(cl, p.Messages)
					return queuePeek{Conn: c.Name, PeekResult: p}, nil
				})
		}),
	}
	c.Flags().IntVarP(&limit, "limit", "n", 10, "how many messages")
	c.Flags().BoolVar(&oldest, "oldest", false, "the first messages still kept, not the newest")
	optIntVar(c.Flags(), &partition, "partition", "Kafka: only this partition, numbered from 0 (default: every partition)")
	durVar(c.Flags(), &wait, "idle", 5*time.Second, "Kafka: stop when no message came for this long")
	return c
}

func queueGroupsCmd() *cobra.Command {
	var limit int
	c := &cobra.Command{
		Use:     "groups CONN",
		Short:   "List Kafka consumer groups, NATS consumers or Pub/Sub subscriptions",
		Example: `  komando queue kafka consumer list prod-kafka`,
		Args:    cobra.ExactArgs(1),
		RunE: inCall(func(cl *call, cmd *cobra.Command, args []string) error {
			return withQueue(cl, cmd.Context(), "queue.groups", args[0], driver.Verdict{}, nil,
				func(_ *store.State, c *store.Conn, q queuex.Queue) (any, error) {
					ctx, cancel := queueCtx(cmd)
					defer cancel()
					gs, err := q.Groups(ctx)
					if err != nil {
						return nil, err
					}
					gs = cutRows(cl, gs, limit)
					return queueGroups{Conn: c.Name, Groups: gs, Count: len(gs), kind: c.Kind}, nil
				})
		}),
	}
	limitFlag(c, &limit, 0, "groups")
	return c
}

func queueLagCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "lag CONN CONSUMER",
		Short: "How far one Kafka consumer group (or NATS consumer) is behind",
		Example: `  komando queue kafka consumer show prod-kafka billing
  komando queue nats consumer show stream ORDERS/billing`,
		Args: cobra.ExactArgs(2),
		RunE: inCall(func(cl *call, cmd *cobra.Command, args []string) error {
			return withQueue(cl, cmd.Context(), "queue.lag", args[0], driver.Verdict{}, map[string]any{"group": args[1]},
				func(_ *store.State, c *store.Conn, q queuex.Queue) (any, error) {
					ctx, cancel := queueCtx(cmd)
					defer cancel()
					l, err := q.Lag(ctx, args[1])
					if err != nil {
						return nil, err
					}
					return queueLag{Conn: c.Name, GroupLag: l}, nil
				})
		}),
	}
}

// The queue type of the table: komando queue PROVIDER VERB and queue
// PROVIDER topic|message|consumer VERB. The inventory verbs are the shared
// ones (inventoryHandlers); the others are today's info, ls, describe,
// create, rm, peek, send, purge, groups and lag. Each takes the conn of its
// provider only.
func init() {
	providers := []string{"kafka", "rabbitmq", "nats", "sqs", "pubsub"}
	inventoryHandlers("queue", providers...)
	for _, p := range providers {
		for k, body := range queueBodies {
			if k[0] == "consumer" && !queueHasConsumer(p, k[1]) {
				continue
			}
			words := strings.TrimSpace(k[0] + " " + k[1])
			handlers[capability.Key{Type: "queue", Provider: p, Area: k[0], Verb: k[1]}] = func(cl *call, ctx context.Context, in leafInput) error {
				if err := withEntry(cl, in.Args[0], "queue", p, words); err != nil {
					return err
				}
				return runBody(cl, ctx, body(), in, nil)
			}
		}
		handlers[capability.Key{Type: "queue", Provider: p, Area: "message", Verb: "delete"}] = func(cl *call, ctx context.Context, in leafInput) error {
			if !in.Bool("all") {
				return out.Errf(out.ExitUsage, "USAGE", "add --all to empty the topic: komando queue "+p+" message delete NAME TOPIC --all",
					"komando queue %s message delete deletes every message of a topic: give --all", p)
			}
			if err := withEntry(cl, in.Args[0], "queue", p, "message delete"); err != nil {
				return err
			}
			delete(in.vals, "all") // the purge body has no --all: giving it is what the body does
			return runBody(cl, ctx, queuePurgeCmd(), in, nil)
		}
		groupShorts["queue "+p] = queueGroupShort[p]
		queueGroupExamples(p)
		for area, short := range map[string]string{
			"topic":    "The topics (queues, streams) of a broker: list, show, create, delete",
			"message":  "The messages of a topic: list, create, delete",
			"consumer": "Consumer groups, consumers or subscriptions: list, show",
		} {
			if area == "consumer" && !queueHasConsumer(p, "list") {
				continue
			}
			groupShorts["queue "+p+" "+area] = short
		}
	}
	moveType("queue")
}

var queueGroupShort = map[string]string{
	"kafka":    "Kafka: save a cluster, and read, send and manage its topics",
	"rabbitmq": "RabbitMQ: save a broker, and read, send and manage its queues",
	"nats":     "NATS JetStream: save a server, and read, send and manage its streams",
	"sqs":      "Amazon SQS: save an account, and read, send and manage its queues",
	"pubsub":   "Pub/Sub: save a project, and read, send and manage its topics",
}

// queueGroupExamples are the examples of a provider's groups (3 to 5
// lines each, with a --dry-run line for a change).
func queueGroupExamples(p string) {
	entry, url, topic, _ := capability.QueueExample(p)
	c := "  komando queue " + p + " "
	examples["komando queue "+p] = c + "add " + entry + " " + url + " --via web1 --dry-run\n" +
		c + "add " + entry + " " + url + " --via web1\n" +
		c + "test " + entry + "\n" +
		c + "topic list " + entry + "\n" +
		c + "message list " + entry + " " + topic + " -n 5"
	examples["komando queue "+p+" topic"] = c + "topic list " + entry + "\n" +
		c + "topic show " + entry + " " + topic + "\n" +
		c + "topic create " + entry + " " + topic + " --dry-run\n" +
		c + "topic delete " + entry + " old-" + topic + " --dry-run"
	examples["komando queue "+p+" message"] = c + "message list " + entry + " " + topic + "\n" +
		c + "message list " + entry + " " + topic + " --oldest -n 5\n" +
		c + "message create " + entry + " " + topic + " --value test --dry-run\n" +
		c + "message delete " + entry + " " + topic + "-retry --all --dry-run"
	if !queueHasConsumer(p, "list") {
		return
	}
	examples["komando queue "+p+" consumer"] = c + "consumer list " + entry + "\n" +
		c + "consumer list " + entry + " -n 20"
	if queueHasConsumer(p, "show") {
		examples["komando queue "+p+" consumer"] += "\n" + c + "consumer show " + entry + " billing"
	}
}

// queueHasConsumer says whether a broker has the consumer verb: the table
// has the leaf (Kafka and NATS list and show, Pub/Sub lists, RabbitMQ and
// SQS have none).
func queueHasConsumer(provider, verb string) bool {
	l, ok := capability.Find(capability.Key{Type: "queue", Provider: provider, Area: "consumer", Verb: verb})
	return ok && l.State == capability.Built
}

// queueBodies are today's commands that the queue leaves run (runBody), by area and verb;
// message delete runs queuePurgeCmd.
var queueBodies = map[[2]string]func() *cobra.Command{
	{"", "info"}: queueInfoCmd, {"topic", "list"}: queueLsCmd, {"topic", "show"}: queueDescribeCmd,
	{"topic", "create"}: queueCreateCmd, {"topic", "delete"}: queueRmCmd,
	{"message", "list"}: queuePeekCmd, {"message", "create"}: queueSendCmd,
	{"consumer", "list"}: queueGroupsCmd, {"consumer", "show"}: queueLagCmd,
}
