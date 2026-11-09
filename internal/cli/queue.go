package cli

import (
	"context"
	"time"

	"github.com/spf13/cobra"

	"github.com/sgnd/komando/internal/driver"
	"github.com/sgnd/komando/internal/out"
	"github.com/sgnd/komando/internal/queuex"
	"github.com/sgnd/komando/internal/store"
)

// Queue commands (docs/design/queue.md): reading never moves a consumer
// group or removes a message; send and create change, behind the usual
// seatbelts (protected conns need --yes); rm and purge delete messages, so
// they also need --allow-dangerous. Every change has a real --dry-run.

func queueCmd() *cobra.Command {
	c := &cobra.Command{
		Use:     "queue",
		Aliases: []string{"kafka"},
		Short:   "Read and change message queues (Kafka topics) safely",
		Long: `Work with a kafka conn (see ` + "`komando conn`" + `). info, ls, describe, peek, groups
and lag only read: peek reads messages without joining a consumer group, so
no application's position moves and nothing is removed. send and create
change (protected conns need --yes); rm and purge delete messages, so they
also need --allow-dangerous. Try any change with --dry-run first.`,
	}
	c.AddCommand(queueInfoCmd(), queueLsCmd(), queueDescribeCmd(), queuePeekCmd(), queueGroupsCmd(), queueLagCmd(),
		queueSendCmd(), queueCreateCmd(), queueRmCmd(), queuePurgeCmd())
	return c
}

// queueRules are the rules of the destructive queue commands (rm, purge),
// listed by `komando policy list`.
var queueRules = []driver.Rule{
	{ID: "queue-delete", Reason: "deletes topics and every message in them"},
	{ID: "queue-purge", Reason: "deletes every message in a topic (the topic stays)"},
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
	q, err := queuex.Open(cctx, a.Target, a.Password, a.Dial, timeout, "komando/"+actor())
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
		Short:   "Cluster summary: brokers, controller, Kafka version, topic count",
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
		Short:   "List topics with partitions, replicas and message counts",
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
					return queueTopics{Conn: c.Name, Topics: ts, Count: len(ts)}, nil
				})
		},
	}
	c.Flags().BoolVar(&internal, "internal", false, "also list Kafka's own topics (__consumer_offsets, ...)")
	return c
}

func queueDescribeCmd() *cobra.Command {
	return &cobra.Command{
		Use:     "describe CONN TOPIC",
		Short:   "One topic: partitions, offsets, its own settings and the groups reading it",
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
		Short: "Read the newest (or oldest) messages without moving any consumer group",
		Long: `Read messages straight from the topic's partitions: no consumer group is
joined and no offset is committed, so no application notices and nothing is
removed. By default the newest -n messages over all partitions; --oldest
reads the first ones still kept. Values that are not UTF-8 text are shown
as base64.`,
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
	c.Flags().IntVar(&partition, "partition", -1, "only this partition (numbered from 0)")
	c.Flags().DurationVar(&wait, "wait", 5*time.Second, "stop when no message came for this long")
	return c
}

func queueGroupsCmd() *cobra.Command {
	return &cobra.Command{
		Use:     "groups CONN",
		Short:   "List consumer groups: state, members, topics and total lag",
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
					return queueGroups{Conn: c.Name, Groups: gs, Count: len(gs)}, nil
				})
		},
	}
}

func queueLagCmd() *cobra.Command {
	return &cobra.Command{
		Use:     "lag CONN GROUP",
		Short:   "How far one consumer group is behind, per topic and partition",
		Example: `  komando queue lag events billing`,
		Args:    cobra.ExactArgs(2),
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
