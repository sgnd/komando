package cli

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/sgnd/komando/internal/queuex"
)

// The text of the queue commands for RabbitMQ conns.

func rabbitInfoText(d *queuex.Info) string {
	var b strings.Builder
	product := d.Product
	if product == "" {
		product = "AMQP server"
	}
	fmt.Fprintf(&b, "server:  %s %s", product, orDash(d.Version))
	if d.Platform != "" {
		fmt.Fprintf(&b, " (%s)", d.Platform)
	}
	fmt.Fprintf(&b, "\ncluster: %s\nvhost:   %s\nuser:    %s\n", orDash(d.Cluster), d.Vhost, d.User)
	if !d.Management {
		b.WriteString("\n(add ?management=15672 to the conn's URL to see the nodes and the counts)\n")
		return b.String()
	}
	if t := d.Totals; t != nil {
		fmt.Fprintf(&b, "\nover the whole cluster: %s, %s, %s, %s\nmessages: %d (%d ready, %d unacked)\n",
			countOf(t.Queues, "queue"), countOf(t.Exchanges, "exchange"), countOf(t.Connections, "connection"), countOf(t.Consumers, "consumer"),
			t.Messages, t.Ready, t.Unacked)
	}
	if len(d.Nodes) > 0 {
		rows := make([][]string, 0, len(d.Nodes))
		for _, n := range d.Nodes {
			rows = append(rows, []string{n.Name, map[bool]string{true: "running", false: "down"}[n.Running], orDash(n.Type)})
		}
		b.WriteString("\n" + layoutTable([]string{"NODE", "STATE", "TYPE"}, rows))
	}
	return b.String()
}

func rabbitQueuesText(qs []queuex.Topic) string {
	rows := make([][]string, 0, len(qs))
	for _, q := range qs {
		rows = append(rows, []string{q.Name, q.Type, strconv.FormatInt(q.Messages, 10), strconv.FormatInt(q.Ready, 10),
			strconv.FormatInt(q.Unacked, 10), strconv.Itoa(q.Consumers), orDash(q.State)})
	}
	return layoutTable([]string{"QUEUE", "TYPE", "MESSAGES", "READY", "UNACKED", "CONSUMERS", "STATE"}, rows)
}

func rabbitQueueText(d *queuex.TopicDetail) string {
	var b strings.Builder
	fmt.Fprintf(&b, "queue: %s (vhost %s)\n", d.Name, d.Vhost)
	if !d.Management {
		fmt.Fprintf(&b, "ready: %d\nconsumers: %d\n\n(add ?management=15672 to the conn's URL to see its type, settings and consumers)\n", d.Ready, d.Consumers)
		return b.String()
	}
	durable := d.Durable != nil && *d.Durable
	fmt.Fprintf(&b, "type: %s, %s", d.Type, map[bool]string{true: "durable", false: "not durable"}[durable])
	if d.AutoDelete {
		b.WriteString(", auto-delete")
	}
	if d.Exclusive {
		b.WriteString(", exclusive")
	}
	fmt.Fprintf(&b, "\nstate: %s on %s\nmessages: %d (%d ready, %d unacked)\npolicy: %s\n", orDash(d.State), orDash(d.Node), d.Messages, d.Ready, *d.Unacked, orDash(d.Policy))
	b.WriteString("\narguments:\n")
	if len(d.Arguments) == 0 {
		b.WriteString("  none\n")
	}
	for _, k := range sortedKeys(d.Arguments) {
		fmt.Fprintf(&b, "  %s=%v\n", k, d.Arguments[k])
	}
	fmt.Fprintf(&b, "\nconsumers: %d\n", d.Consumers)
	if len(d.ConsumerOf) > 0 {
		rows := make([][]string, 0, len(d.ConsumerOf))
		for _, c := range d.ConsumerOf {
			ack := map[bool]string{true: "manual", false: "auto"}[c.AckRequired]
			rows = append(rows, []string{c.Tag, orDash(c.Connection), orDash(c.User), ack, strconv.Itoa(c.Prefetch), yesCell(c.Active)})
		}
		b.WriteString(layoutTable([]string{"TAG", "CONNECTION", "USER", "ACK", "PREFETCH", "ACTIVE"}, rows))
	}
	return b.String()
}

func rabbitPeekText(p *queuex.PeekResult) string {
	var b strings.Builder
	for i, m := range p.Messages {
		fmt.Fprintf(&b, "# message %d", i+1)
		if m.Redelivered {
			b.WriteString(", redelivered")
		}
		if m.Deliveries > 0 {
			b.WriteString(", delivered " + count64(m.Deliveries, "time"))
		}
		if m.Exchange != "" {
			fmt.Fprintf(&b, ", exchange %s, routing key %s", m.Exchange, m.RoutingKey)
		}
		for _, kv := range []map[string]string{m.Properties, m.Headers} {
			for _, k := range sortedKeys(kv) {
				b.WriteString(", " + k + "=" + kv[k])
			}
		}
		if m.Encoding != "" {
			b.WriteString(", " + m.Encoding)
		}
		writeValue(&b, m)
	}
	switch {
	case len(p.Messages) == 0:
		b.WriteString("no messages waiting\n")
	case p.More:
		fmt.Fprintf(&b, "(the first %s; the queue holds more: raise -n)\n", countOf(p.Count, "message"))
	}
	if p.Requeued {
		b.WriteString("(every message went back to the queue, marked redelivered")
		if p.DeliveryLimit > 0 {
			fmt.Fprintf(&b, "; this quorum queue drops a message after %d deliveries, and each peek counts", p.DeliveryLimit)
		}
		b.WriteString(")\n")
	}
	return b.String()
}
