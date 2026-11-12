package rabbitmq

import (
	"context"
	"fmt"
	"sort"

	amqp "github.com/rabbitmq/amqp091-go"

	"github.com/sgnd/komando/internal/queuex"
)

// noManagement is the hint for what only the management API can tell.
const noManagement = "AMQP cannot list queues: add the management API's port to the conn's URL (`komando conn edit NAME --url 'amqp://...?management=15672'`), " +
	"or name a queue with `komando queue describe CONN QUEUE`"

// Info is the server's own words (product, version, cluster name) from
// the AMQP login, and with the management API its nodes and totals.
func (r *Rabbit) Info(ctx context.Context) (*queuex.Info, error) {
	p := r.conn.Properties
	inf := &queuex.Info{Engine: "rabbitmq", Version: str(p["version"]), RabbitInfo: &queuex.RabbitInfo{
		Product: str(p["product"]), Cluster: str(p["cluster_name"]), Vhost: r.t.Database, User: r.user,
		Platform: str(p["platform"]), Management: r.t.Management != "",
	}}
	if r.t.Management == "" {
		return inf, nil
	}
	var ov overview
	if err := r.mgmt(ctx, "/api/overview", "", &ov); err != nil {
		return nil, err
	}
	if ov.Version != "" {
		inf.Version = ov.Version
	}
	if ov.Cluster != "" {
		inf.Cluster = ov.Cluster
	}
	inf.Totals = &queuex.RabbitTotals{Queues: ov.Objects.Queues, Exchanges: ov.Objects.Exchanges, Connections: ov.Objects.Connections,
		Channels: ov.Objects.Channels, Consumers: ov.Objects.Consumers, Messages: ov.Queued.Messages, Ready: ov.Queued.Ready, Unacked: ov.Queued.Unacked}
	var nodes []struct {
		Name    string `json:"name"`
		Running bool   `json:"running"`
		Type    string `json:"type"`
	}
	if r.mgmt(ctx, "/api/nodes", "", &nodes) == nil { // needs the monitoring tag: leave them out without it
		for _, n := range nodes {
			inf.Nodes = append(inf.Nodes, queuex.RabbitNode{Name: n.Name, Running: n.Running, Type: n.Type})
		}
		sort.Slice(inf.Nodes, func(i, j int) bool { return inf.Nodes[i].Name < inf.Nodes[j].Name })
	}
	return inf, nil
}

type overview struct {
	Version string `json:"rabbitmq_version"`
	Cluster string `json:"cluster_name"`
	Objects struct {
		Queues, Exchanges, Connections, Channels, Consumers int
	} `json:"object_totals"`
	Queued struct {
		Messages int64 `json:"messages"`
		Ready    int64 `json:"messages_ready"`
		Unacked  int64 `json:"messages_unacknowledged"`
	} `json:"queue_totals"`
}

// mgmtQueue is a queue as the management API shows it.
type mgmtQueue struct {
	Name       string         `json:"name"`
	Type       string         `json:"type"`
	Durable    bool           `json:"durable"`
	AutoDelete bool           `json:"auto_delete"`
	Exclusive  bool           `json:"exclusive"`
	Messages   int64          `json:"messages"`
	Ready      int64          `json:"messages_ready"`
	Unacked    int64          `json:"messages_unacknowledged"`
	Consumers  int            `json:"consumers"`
	State      string         `json:"state"`
	Node       string         `json:"node"`
	Leader     string         `json:"leader"`
	Policy     string         `json:"policy"`
	Arguments  map[string]any `json:"arguments"`
	// EffectivePolicy is the policy's settings: an object, or [] without one
	EffectivePolicy any `json:"effective_policy_definition"`
	Details         []struct {
		Tag         string `json:"consumer_tag"`
		AckRequired bool   `json:"ack_required"`
		Prefetch    int    `json:"prefetch_count"`
		Active      bool   `json:"active"`
		Channel     struct {
			Connection string `json:"connection_name"`
			PeerHost   string `json:"peer_host"`
			User       string `json:"user"`
		} `json:"channel_details"`
	} `json:"consumer_details"`
}

// Topics lists the vhost's queues whose name matches pattern; it needs the
// management API. RabbitMQ has no internal queues to hide.
func (r *Rabbit) Topics(ctx context.Context, pattern string, internal bool, limit int) ([]queuex.Topic, error) {
	if internal {
		return nil, queuex.NotSupported("--internal", "rabbitmq", "RabbitMQ has no internal queues: `komando queue ls CONN` lists every queue of the vhost")
	}
	if r.t.Management == "" {
		return nil, queuex.NotSupported("queue ls without the management API", "rabbitmq", noManagement)
	}
	var qs []mgmtQueue
	if err := r.mgmt(ctx, r.vhostPath("queues", "")+"?columns=name,type,durable,messages,messages_ready,messages_unacknowledged,consumers,state", "", &qs); err != nil {
		return nil, err
	}
	res := []queuex.Topic{}
	for _, q := range qs {
		if !queuex.Match(pattern, q.Name) {
			continue
		}
		res = append(res, queuex.Topic{Name: q.Name, Messages: q.Messages, RabbitQueue: &queuex.RabbitQueue{
			Type: orClassic(q.Type), Durable: q.Durable, Ready: q.Ready, Unacked: q.Unacked, Consumers: q.Consumers, State: q.State}})
	}
	sort.Slice(res, func(i, j int) bool { return res[i].Name < res[j].Name })
	return queuex.First(res, limit), nil
}

// Describe reads one queue: with the management API all of it, otherwise
// what a passive queue.declare tells (ready messages and consumers).
func (r *Rabbit) Describe(ctx context.Context, name string) (*queuex.TopicDetail, error) {
	if r.t.Management == "" {
		q, err := r.declared(ctx, name)
		if err != nil {
			return nil, err
		}
		return &queuex.TopicDetail{Name: name, Messages: int64(q.Messages), RabbitQueueDetail: &queuex.RabbitQueueDetail{
			Vhost: r.t.Database, Ready: int64(q.Messages), Consumers: q.Consumers}}, nil
	}
	var q mgmtQueue
	if err := r.mgmt(ctx, r.vhostPath("queues", name), name, &q); err != nil {
		return nil, err
	}
	d := &queuex.RabbitQueueDetail{Vhost: r.t.Database, Management: true, Ready: q.Ready, Unacked: &q.Unacked, Consumers: q.Consumers,
		Type: orClassic(q.Type), Durable: &q.Durable, AutoDelete: q.AutoDelete, Exclusive: q.Exclusive, State: q.State,
		Node: q.Node, Policy: q.Policy, Arguments: q.Arguments}
	if q.Leader != "" {
		d.Node = q.Leader
	}
	if len(d.Arguments) == 0 {
		d.Arguments = nil
	}
	for _, c := range q.Details {
		conn := c.Channel.Connection
		if conn == "" {
			conn = c.Channel.PeerHost
		}
		d.ConsumerOf = append(d.ConsumerOf, queuex.RabbitConsumer{Tag: c.Tag, Connection: conn, User: c.Channel.User,
			AckRequired: c.AckRequired, Prefetch: c.Prefetch, Active: c.Active})
	}
	return &queuex.TopicDetail{Name: name, Messages: q.Messages, RabbitQueueDetail: d}, nil
}

func orClassic(t string) string {
	if t == "" {
		return "classic"
	}
	return t
}

// str is a server property as text.
func str(v any) string {
	switch v := v.(type) {
	case nil:
		return ""
	case string:
		return v
	case []byte:
		return string(v)
	}
	return fmt.Sprint(v)
}

// table is an AMQP table (headers, arguments) as text values.
func table(t amqp.Table, maxBytes int) map[string]string {
	if len(t) == 0 {
		return nil
	}
	m := make(map[string]string, len(t))
	for k, v := range t {
		switch v := v.(type) {
		case string:
			m[k], _, _ = queuex.Text([]byte(v), maxBytes)
		case []byte:
			m[k], _, _ = queuex.Text(v, maxBytes)
		default:
			m[k] = fmt.Sprint(v)
		}
	}
	return m
}
