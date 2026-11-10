package cli

import (
	"context"
	"time"

	"github.com/spf13/cobra"

	"github.com/sgnd/komando/internal/driver"
	"github.com/sgnd/komando/internal/out"
	"github.com/sgnd/komando/internal/queuex"
	_ "github.com/sgnd/komando/internal/queuex/nats"     // nats:// and tls:// conns
	_ "github.com/sgnd/komando/internal/queuex/pubsub"   // pubsub:// conns
	_ "github.com/sgnd/komando/internal/queuex/rabbitmq" // amqp:// and amqps:// conns
	_ "github.com/sgnd/komando/internal/queuex/sqs"      // sqs:// conns
	"github.com/sgnd/komando/internal/store"
)

// Queue commands (docs/design/queue.md), for Kafka, RabbitMQ, NATS
// JetStream, Amazon SQS and Google Cloud Pub/Sub: reading never moves a consumer group or
// removes a message; send and create change, behind the usual
// seatbelts (protected conns need --yes); rm and purge delete messages, so
// they also need --allow-dangerous. Every change has a real --dry-run.

func queueCmd() *cobra.Command {
	c := &cobra.Command{
		Use:     "queue",
		Aliases: []string{"kafka", "rabbitmq", "nats", "sqs", "pubsub"},
		Short:   "Read and change Kafka, RabbitMQ, NATS, SQS and Pub/Sub queues",
		Long: `Work with a kafka://, amqp://, nats://, sqs:// or pubsub:// conn (see ` + "`komando conn`" + `).
info, ls, describe, peek, groups and lag only read: peek reads Kafka
messages without joining a consumer group, gives RabbitMQ and Pub/Sub
messages straight back, reads NATS stream messages by their number, and
receives SQS messages without hiding or deleting them, so nothing is
removed. send and create change (protected conns need --yes); rm and purge
delete messages, so they also need --allow-dangerous. Try any change with
--dry-run first. In RabbitMQ words a topic is a queue; in NATS words it is
a stream. Pub/Sub keeps messages in subscriptions: peek and purge take a
subscription, and groups lists them.`,
	}
	c.AddCommand(queueInfoCmd(), queueLsCmd(), queueDescribeCmd(), queuePeekCmd(), queueGroupsCmd(), queueLagCmd(),
		queueSendCmd(), queueCreateCmd(), queueRmCmd(), queuePurgeCmd())
	return c
}

// queueRules are the rules of the destructive queue commands (rm, purge),
// listed by `komando policy list`.
var queueRules = []driver.Rule{
	{ID: "queue-delete", Reason: "deletes topics (or queues, or streams) and every message in them"},
	{ID: "queue-purge", Reason: "deletes every message in a topic, queue or stream (it stays)"},
}

func queueRisk(id string) driver.Verdict {
	for _, r := range queueRules {
		if r.ID == id {
			return driver.Verdict{Risk: driver.RiskDestructive, RuleIDs: []string{r.ID}, Reasons: []string{r.Reason}}
		}
	}
	return driver.Verdict{Risk: driver.RiskWrite}
}

type queueFn func(st *store.State, c *store.Conn, q queuex.Queue) (any, error)

// withQueue opens the conn's client, runs fn, and audits the action. A
// change is checked by guardConns first; fn itself honours --dry-run.
func withQueue(ctx context.Context, name, connExpr string, v driver.Verdict, rec map[string]any, fn queueFn) error {
	st, err := loadState()
	if err != nil {
		return err
	}
	c, err := singleConn(st, connExpr, "queue")
	if err != nil {
		return err
	}
	if rec == nil {
		rec = map[string]any{}
	}
	rec["conns"], rec["risk"] = []string{c.Name}, v.Risk.String()
	fail := func(err error) error {
		rec["error"] = toErr(err).Code
		audit(st, name, nil, "", false, rec)
		return err
	}
	if v.Risk > driver.RiskRead {
		if err := guardConns(st, []*store.Conn{c}, v); err != nil {
			return fail(err)
		}
	}
	a, err := openAccess(ctx, st, c)
	if err != nil {
		return fail(err)
	}
	defer a.Close()
	timeout := dbTimeout()
	cctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	q, err := openQueue(cctx, c, a, timeout)
	if err != nil {
		return fail(viaTimeout(c, err))
	}
	defer q.Close()
	data, err := fn(st, c, q)
	if err != nil {
		return fail(err)
	}
	audit(st, name, nil, "", true, rec)
	out.P.Print(name, data, nil)
	return nil
}

// queueCtx is the command's context with the --timeout limit.
func queueCtx(cmd *cobra.Command) (context.Context, context.CancelFunc) {
	return context.WithTimeout(cmd.Context(), dbTimeout())
}

func queueInfoCmd() *cobra.Command {
	return &cobra.Command{
		Use:     "info CONN",
		Short:   "Server summary: version, brokers or nodes, topic, queue or stream count",
		Example: `  komando queue info events`,
		Args:    cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return withQueue(cmd.Context(), "queue.info", args[0], driver.Verdict{}, nil,
				func(_ *store.State, c *store.Conn, q queuex.Queue) (any, error) {
					ctx, cancel := queueCtx(cmd)
					defer cancel()
					inf, err := q.Info(ctx)
					if err != nil {
						return nil, err
					}
					return queueInfo{Conn: c.Name, Info: inf}, nil
				})
		},
	}
}

func queueLsCmd() *cobra.Command {
	var internal bool
	c := &cobra.Command{
		Use:     "ls CONN [PATTERN]",
		Aliases: []string{"list"},
		Short:   "List topics (or queues, or streams) with their message counts",
		Example: `  komando queue ls events
  komando queue ls events 'orders-*'
  komando queue ls events --internal`,
		Args: cobra.RangeArgs(1, 2),
		RunE: func(cmd *cobra.Command, args []string) error {
			pattern := ""
			if len(args) == 2 {
				pattern = args[1]
			}
			return withQueue(cmd.Context(), "queue.ls", args[0], driver.Verdict{}, map[string]any{"pattern": pattern},
				func(_ *store.State, c *store.Conn, q queuex.Queue) (any, error) {
					ctx, cancel := queueCtx(cmd)
					defer cancel()
					ts, err := q.Topics(ctx, pattern, internal)
					if err != nil {
						return nil, err
					}
					return queueTopics{Conn: c.Name, Topics: ts, Count: len(ts), kind: c.Kind}, nil
				})
		},
	}
	c.Flags().BoolVar(&internal, "internal", false, "kafka: also list Kafka's own topics (__consumer_offsets, ...)")
	return c
}

func queueDescribeCmd() *cobra.Command {
	return &cobra.Command{
		Use:     "describe CONN TOPIC",
		Short:   "One topic, queue or stream: messages, settings, and who reads it",
		Example: `  komando queue describe events orders`,
		Args:    cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			return withQueue(cmd.Context(), "queue.describe", args[0], driver.Verdict{}, map[string]any{"topic": args[1]},
				func(_ *store.State, c *store.Conn, q queuex.Queue) (any, error) {
					ctx, cancel := queueCtx(cmd)
					defer cancel()
					d, err := q.Describe(ctx, args[1])
					if err != nil {
						return nil, err
					}
					return queueTopic{Conn: c.Name, TopicDetail: d}, nil
				})
		},
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
		Example: `  komando queue peek events orders
  komando queue peek events orders -n 50 --partition 2
  komando queue peek events orders --oldest -n 5`,
		Args: cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			if limit < 1 || limit > 10000 {
				return out.Usage("--limit must be between 1 and 10000")
			}
			o := queuex.PeekOptions{Topic: args[1], Limit: limit, Oldest: oldest, Partition: int32(partition), Wait: wait}
			return withQueue(cmd.Context(), "queue.peek", args[0], driver.Verdict{}, map[string]any{"topic": args[1], "limit": limit},
				func(st *store.State, c *store.Conn, q queuex.Queue) (any, error) {
					ctx, cancel := queueCtx(cmd)
					defer cancel()
					o.MaxBytes = maxOutput(st)
					p, err := q.Peek(ctx, o)
					if err != nil {
						return nil, err
					}
					return queuePeek{Conn: c.Name, PeekResult: p}, nil
				})
		},
	}
	c.Flags().IntVarP(&limit, "limit", "n", 10, "how many messages")
	c.Flags().BoolVar(&oldest, "oldest", false, "the first messages still kept, not the newest")
	c.Flags().IntVar(&partition, "partition", -1, "kafka: only this partition (numbered from 0)")
	c.Flags().DurationVar(&wait, "wait", 5*time.Second, "kafka: stop when no message came for this long")
	return c
}

func queueGroupsCmd() *cobra.Command {
	return &cobra.Command{
		Use:     "groups CONN",
		Short:   "List Kafka consumer groups, NATS consumers or Pub/Sub subscriptions",
		Example: `  komando queue groups events`,
		Args:    cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return withQueue(cmd.Context(), "queue.groups", args[0], driver.Verdict{}, nil,
				func(_ *store.State, c *store.Conn, q queuex.Queue) (any, error) {
					ctx, cancel := queueCtx(cmd)
					defer cancel()
					gs, err := q.Groups(ctx)
					if err != nil {
						return nil, err
					}
					return queueGroups{Conn: c.Name, Groups: gs, Count: len(gs), kind: c.Kind}, nil
				})
		},
	}
}

func queueLagCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "lag CONN GROUP",
		Short: "How far one Kafka consumer group (or NATS consumer) is behind",
		Example: `  komando queue lag events billing
  komando queue lag stream ORDERS/billing`,
		Args: cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			return withQueue(cmd.Context(), "queue.lag", args[0], driver.Verdict{}, map[string]any{"group": args[1]},
				func(_ *store.State, c *store.Conn, q queuex.Queue) (any, error) {
					ctx, cancel := queueCtx(cmd)
					defer cancel()
					l, err := q.Lag(ctx, args[1])
					if err != nil {
						return nil, err
					}
					return queueLag{Conn: c.Name, GroupLag: l}, nil
				})
		},
	}
}
