package cli

import (
	"strings"

	"github.com/spf13/cobra"

	"github.com/sgnd/komando/internal/driver"
	"github.com/sgnd/komando/internal/out"
	"github.com/sgnd/komando/internal/queuex"
	"github.com/sgnd/komando/internal/store"
)

// maxQueueMessage is the largest message `queue send` takes: Kafka's
// default limit (message.max.bytes) is about 1 MiB, and a message queue is
// no place for bigger ones.
const maxQueueMessage = 1 << 20

func queueSendCmd() *cobra.Command {
	var value, from, key string
	var headers []string
	var partition int
	c := &cobra.Command{
		Use:   "send CONN TOPIC",
		Short: "Publish one message",
		Long: `Publish one message to an existing topic (or queue) and wait until the
server keeps it. The value comes from --value, from a file (--from FILE;
'-' is stdin), or from data piped on stdin. --dry-run checks the topic and
the partition and sends nothing.

Kafka: --key picks the partition the usual way (the same key always goes
to the same partition); --partition picks one itself.
RabbitMQ: the message goes straight to the queue (the default exchange),
persistent, with --header values as its headers.
NATS: TOPIC is a subject that a stream keeps (orders.new); komando checks
which stream, publishes, and waits for the stream's acknowledgement.
Amazon SQS: text only; --header values become message attributes. A FIFO
queue (name.fifo) needs --key, the message group.
Google Cloud Pub/Sub: TOPIC is a topic; --header values become message
attributes and --key is the ordering key.`,
		Example: `  komando queue send prod-kafka orders --value '{"id": 42, "status": "paid"}' --key 42
  komando queue send prod-kafka orders --from ./order.json --header source=support
  komando queue send prod-kafka orders --value test --dry-run`,
		Args: cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			data, err := queueValue(cmd, value, from)
			if err != nil {
				return err
			}
			hs, err := queueHeaders(headers)
			if err != nil {
				return err
			}
			texts := []string{string(data), key}
			for _, h := range hs {
				texts = append(texts, h[0], h[1])
			}
			if err := refuseHiddenWrite(texts...); err != nil {
				return err
			}
			m := queuex.Message{Topic: args[1], Value: data, Headers: hs, Partition: int32(partition)}
			if cmd.Flags().Changed("key") {
				m.Key = []byte(key)
			}
			rec := map[string]any{"topic": args[1], "bytes": len(data)} // the message itself may be personal data
			return withQueue(cmd.Context(), "queue.send", args[0], queueRisk(""), rec,
				func(_ *store.State, c *store.Conn, q queuex.Queue) (any, error) {
					ctx, cancel := queueCtx(cmd)
					defer cancel()
					s, err := q.Send(ctx, m, g.dryRun)
					if err != nil {
						return nil, err
					}
					return queueSent{Conn: c.Name, Sent: s}, nil
				})
		},
	}
	c.Flags().StringVar(&value, "value", "", "the message")
	c.Flags().StringVar(&from, "from", "", "read the message from this file ('-' for stdin)")
	c.Flags().StringVar(&key, "key", "", "Kafka: the message key (picks the partition); SQS: the message group of a FIFO queue; Pub/Sub: the ordering key")
	c.Flags().StringArrayVar(&headers, "header", nil, "a message header KEY=VALUE (repeatable)")
	optIntVar(c.Flags(), &partition, "partition", "Kafka: send to this partition, numbered from 0 (default: the broker's choice)")
	return c
}

// queueValue reads the message: --value, --from FILE ('-' stdin), or stdin.
func queueValue(cmd *cobra.Command, value, from string) ([]byte, error) {
	var data []byte
	var err error
	switch {
	case cmd.Flags().Changed("value") && from != "":
		return nil, out.Usage("give --value or --from, not both")
	case cmd.Flags().Changed("value"):
		data = []byte(value)
	case from != "":
		if data, err = readFileOrStdin(from); err != nil {
			return nil, err
		}
	default:
		if data, err = readStdinIfPiped(maxQueueMessage, "the message"); err != nil {
			return nil, err
		}
		if data == nil {
			return nil, out.Usage("give the message with --value, --from FILE, or pipe it on stdin")
		}
	}
	if len(data) > maxQueueMessage {
		return nil, out.Usage("the message is %s; komando sends up to 1 MiB (Kafka's default limit, message.max.bytes): put bigger data in storage and send its name", humanBytes(int64(len(data))))
	}
	return data, nil
}

func queueHeaders(pairs []string) ([][2]string, error) {
	var hs [][2]string
	for _, p := range pairs {
		k, v, ok := strings.Cut(p, "=")
		if !ok || k == "" {
			return nil, out.Usage("--header takes KEY=VALUE, got %q", p)
		}
		hs = append(hs, [2]string{k, v})
	}
	return hs, nil
}

func queueCreateCmd() *cobra.Command {
	var partitions, replicas int
	var configs []string
	var typ string
	c := &cobra.Command{
		Use:   "create CONN TOPIC",
		Short: "Create a topic, queue or stream",
		Example: `  komando queue create prod-kafka orders --partitions 6 --replicas 3 --dry-run
  komando queue create prod-kafka orders --partitions 6 --replicas 3 --config retention.ms=604800000
  komando queue create jobs emails --type quorum --config x-max-length=10000
  komando queue create stream ORDERS --replicas 3 --config subjects='orders.>' --config max_age=7d
  komando queue create aws orders.fifo --config ContentBasedDeduplication=true
  komando queue create gcp orders --config messageRetentionDuration=7d
  komando queue create gcp subscriptions/billing --config topic=orders --config ackDeadlineSeconds=60`,
		Args: cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := parseKV(configs)
			if err != nil {
				return err
			}
			if partitions == 0 || partitions < -1 || replicas == 0 || replicas < -1 || replicas > 32767 {
				return out.Usage("--partitions and --replicas must be at least 1 (leave them out for the broker's default)")
			}
			s := queuex.TopicSpec{Topic: args[1], Partitions: int32(partitions), Replicas: int16(replicas), Type: typ, Config: cfg}
			return withQueue(cmd.Context(), "queue.create", args[0], queueRisk(""), map[string]any{"topic": args[1], "partitions": partitions, "replicas": replicas},
				func(_ *store.State, c *store.Conn, q queuex.Queue) (any, error) {
					ctx, cancel := queueCtx(cmd)
					defer cancel()
					r, err := q.Create(ctx, s, g.dryRun)
					if err != nil {
						return nil, err
					}
					return queueCreated{Conn: c.Name, Created: r}, nil
				})
		},
	}
	optIntVar(c.Flags(), &partitions, "partitions", "Kafka: how many partitions (default: the broker's)")
	optIntVar(c.Flags(), &replicas, "replicas", "copies of each message. Kafka: copies of each partition; NATS: copies of the stream (default: the broker's; NATS: 1)")
	c.Flags().StringVar(&typ, "type", "", "RabbitMQ: the queue type, classic, quorum or stream (default: the server's)")
	c.Flags().StringArrayVar(&configs, "config", nil, "a setting KEY=VALUE, e.g. retention.ms=86400000 (Kafka), x-max-length=1000 (RabbitMQ), max_age=7d (NATS), VisibilityTimeout=60 (SQS) or ackDeadlineSeconds=60 (Pub/Sub) (repeatable)")
	return c
}

func queueRmCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "rm CONN TOPIC...",
		Short: "Delete topics, queues or streams with their messages",
		Example: `  komando queue rm prod-kafka old-orders --dry-run
  komando queue rm prod-kafka old-orders --allow-dangerous`,
		Args: cobra.MinimumNArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			topics := args[1:]
			askTypes(topics, "topics or queues in "+args[0])
			return withQueue(cmd.Context(), "queue.rm", args[0], queueRisk("queue-delete", topics...), map[string]any{"topics": topics},
				func(_ *store.State, c *store.Conn, q queuex.Queue) (any, error) {
					ctx, cancel := queueCtx(cmd)
					defer cancel()
					d, err := q.Delete(ctx, topics, g.dryRun)
					if err != nil {
						return nil, err
					}
					return queueDeleted{Conn: c.Name, Topics: d, DryRun: g.dryRun, kind: c.Kind}, nil
				})
		},
	}
}

func queuePurgeCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "purge CONN TOPIC",
		Short: "Empty a topic, queue or stream and keep it",
		Example: `  komando queue purge prod-kafka orders-retry --dry-run
  komando queue purge prod-kafka orders-retry --allow-dangerous`,
		Args: cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			askTypes(args[1:], "topics or queues in "+args[0])
			return withQueue(cmd.Context(), "queue.purge", args[0], queueRisk("queue-purge", args[1]), map[string]any{"topic": args[1]},
				func(_ *store.State, c *store.Conn, q queuex.Queue) (any, error) {
					ctx, cancel := queueCtx(cmd)
					defer cancel()
					p, err := q.Purge(ctx, args[1], g.dryRun)
					if err != nil {
						return nil, err
					}
					return queuePurged{Conn: c.Name, Purged: p}, nil
				})
		},
	}
}

// queuePolicyRules lists the rules `komando policy list` shows for queues.
func queuePolicyRules() []driver.Rule { return append([]driver.Rule(nil), queueRules...) }
