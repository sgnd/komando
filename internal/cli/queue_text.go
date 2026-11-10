package cli

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/sgnd/komando/internal/queuex"
)

// What the queue commands print: the JSON is the queuex types with the
// conn's name; the text is a table or a short summary.

type queueInfo struct {
	Conn string `json:"conn"`
	*queuex.Info
}

func (d queueInfo) Text() string {
	switch {
	case d.RabbitInfo != nil:
		return rabbitInfoText(d.Info)
	case d.NatsInfo != nil:
		return natsInfoText(d.Info)
	case d.SqsInfo != nil:
		return sqsInfoText(d.Info)
	case d.PubsubInfo != nil:
		return pubsubInfoText(d.Info)
	}
	var b strings.Builder
	version := d.Version
	if version == "" {
		version = "unknown"
	}
	fmt.Fprintf(&b, "cluster: %s\nversion: %s (a guess from the API versions the brokers take)\ntopics:  %d\n\n", orDash(d.ClusterID), version, d.Topics)
	var rows [][]string
	for _, br := range d.Brokers {
		role := ""
		if br.Controller {
			role = "controller"
		}
		rows = append(rows, []string{strconv.Itoa(int(br.ID)), br.Address, orDash(br.Rack), role})
	}
	b.WriteString(layoutTable([]string{"BROKER", "ADDRESS", "RACK", "ROLE"}, rows))
	return b.String()
}

// count64 is countOf for message counts.
func count64(n int64, noun string) string {
	if n == 1 {
		return "1 " + noun
	}
	return strconv.FormatInt(n, 10) + " " + noun + "s"
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

type queueTopics struct {
	Conn   string         `json:"conn"`
	Topics []queuex.Topic `json:"topics"` // rabbitmq: queues; nats: streams
	Count  int            `json:"count"`
	kind   string
}

func (l queueTopics) Text() string {
	switch {
	case len(l.Topics) == 0 && (l.kind == "rabbitmq" || l.kind == "sqs"):
		return "no queues\n"
	case len(l.Topics) == 0 && l.kind == "nats":
		return "no streams\n"
	case len(l.Topics) == 0:
		return "no topics\n"
	case l.kind == "rabbitmq":
		return rabbitQueuesText(l.Topics)
	case l.kind == "nats":
		return natsStreamsText(l.Topics)
	case l.kind == "sqs":
		return sqsQueuesText(l.Topics)
	case l.kind == "pubsub":
		return pubsubTopicsText(l.Topics)
	}
	var rows [][]string
	for _, t := range l.Topics {
		rows = append(rows, []string{t.Name, strconv.Itoa(t.Partitions), strconv.Itoa(t.Replicas), strconv.FormatInt(t.Messages, 10)})
	}
	return layoutTable([]string{"TOPIC", "PARTITIONS", "REPLICAS", "MESSAGES"}, rows)
}

type queueTopic struct {
	Conn string `json:"conn"`
	*queuex.TopicDetail
}

func (d queueTopic) Text() string {
	switch {
	case d.RabbitQueueDetail != nil:
		return rabbitQueueText(d.TopicDetail)
	case d.NatsStreamDetail != nil:
		return natsStreamText(d.TopicDetail)
	case d.SqsQueueDetail != nil:
		return sqsQueueText(d.TopicDetail)
	case d.PubsubDetail != nil:
		return pubsubDetailText(d.TopicDetail)
	}
	var b strings.Builder
	fmt.Fprintf(&b, "topic: %s (%s, %s, %s)\n\n", d.Name, countOf(len(d.Partitions), "partition"), countOf(d.Replicas, "replica"), count64(d.Messages, "message"))
	var rows [][]string
	for _, p := range d.Partitions {
		leader := strconv.Itoa(int(p.Leader))
		if p.Leader < 0 {
			leader = "none"
		}
		rows = append(rows, []string{strconv.Itoa(int(p.ID)), leader, ints(p.Replicas), ints(p.ISR),
			strconv.FormatInt(p.Start, 10), strconv.FormatInt(p.End, 10), strconv.FormatInt(p.Messages, 10)})
	}
	b.WriteString(layoutTable([]string{"PARTITION", "LEADER", "REPLICAS", "IN SYNC", "START", "END", "MESSAGES"}, rows))
	b.WriteString("\nsettings (only those that differ from the brokers' defaults):\n")
	if len(d.Config) == 0 {
		b.WriteString("  none\n")
	}
	for _, k := range sortedKeys(d.Config) {
		fmt.Fprintf(&b, "  %s=%s\n", k, d.Config[k])
	}
	b.WriteString("\nconsumer groups:\n")
	if len(d.Groups) == 0 {
		b.WriteString("  none\n")
	}
	for _, g := range d.Groups {
		fmt.Fprintf(&b, "  %s (%s): lag %d\n", g.Group, g.State, g.Lag)
	}
	return b.String()
}

func ints(is []int32) string {
	s := make([]string, len(is))
	for i, n := range is {
		s[i] = strconv.Itoa(int(n))
	}
	return strings.Join(s, ",")
}

type queuePeek struct {
	Conn string `json:"conn"`
	*queuex.PeekResult
}

func (p queuePeek) Text() string {
	switch {
	case p.From == "sample":
		return sqsPeekText(p.PeekResult)
	case p.From == "pulled":
		return pubsubPeekText(p.PeekResult)
	case p.Queue != "":
		return rabbitPeekText(p.PeekResult)
	case p.Stream != "":
		return natsPeekText(p.PeekResult)
	}
	var b strings.Builder
	for _, m := range p.Messages {
		key := "-"
		if m.Key != nil {
			key = *m.Key
		}
		fmt.Fprintf(&b, "# partition %d, offset %d, %s, key %s", m.Partition, m.Offset, m.Timestamp.Format(time.RFC3339), key)
		if len(m.Headers) > 0 {
			hs := make([]string, 0, len(m.Headers))
			for _, k := range sortedKeys(m.Headers) {
				hs = append(hs, k+"="+m.Headers[k])
			}
			b.WriteString(", headers " + strings.Join(hs, " "))
		}
		if m.Encoding != "" {
			b.WriteString(", " + m.Encoding)
		}
		writeValue(&b, m)
	}
	switch {
	case len(p.Messages) == 0:
		b.WriteString("no messages\n")
	case p.More:
		fmt.Fprintf(&b, "(the %s %s; the topic holds more: raise -n, or use --oldest or --partition)\n", p.From, countOf(p.Count, "message"))
	}
	if p.Partial {
		b.WriteString("(stopped waiting: some messages may be missing; raise --wait)\n")
	}
	return b.String()
}

// writeValue ends a message's header line and writes its value.
func writeValue(b *strings.Builder, m queuex.Received) {
	b.WriteString("\n" + m.Value + "\n")
	if m.ValueTruncated {
		fmt.Fprintf(b, "(cut: the value is %s)\n", humanBytes(int64(m.Size)))
	}
}

type queueGroups struct {
	Conn   string         `json:"conn"`
	Groups []queuex.Group `json:"groups"`
	Count  int            `json:"count"`
	kind   string
}

func (l queueGroups) Text() string {
	switch {
	case len(l.Groups) == 0 && l.kind == "pubsub":
		return "no subscriptions\n"
	case len(l.Groups) == 0:
		return "no consumer groups\n"
	case l.Groups[0].NatsConsumer != nil:
		return natsGroupsText(l.Groups)
	case l.Groups[0].PubsubSubscription != nil:
		return pubsubGroupsText(l.Groups)
	}
	var rows [][]string
	for _, g := range l.Groups {
		rows = append(rows, []string{g.Name, g.State, strconv.Itoa(g.Members), strings.Join(g.Topics, ","), strconv.FormatInt(g.Lag, 10)})
	}
	return layoutTable([]string{"GROUP", "STATE", "MEMBERS", "TOPICS", "LAG"}, rows)
}

type queueLag struct {
	Conn string `json:"conn"`
	*queuex.GroupLag
}

func (l queueLag) Text() string {
	if l.NatsConsumer != nil {
		return natsLagText(l.GroupLag)
	}
	var b strings.Builder
	fmt.Fprintf(&b, "group: %s (%s, %s), lag %d\n\n", l.Group, l.State, countOf(l.Members, "member"), l.Lag)
	rows := make([][]string, 0, len(l.Partitions))
	for _, p := range l.Partitions {
		committed, lag := strconv.FormatInt(p.Committed, 10), strconv.FormatInt(p.Lag, 10)
		if p.Committed < 0 {
			committed = "-"
		}
		if p.Lag < 0 {
			lag = "? " + p.Error
		}
		rows = append(rows, []string{p.Topic, strconv.Itoa(int(p.Partition)), committed, strconv.FormatInt(p.End, 10), lag, orDash(p.Client)})
	}
	sort.SliceStable(rows, func(i, j int) bool { return rows[i][0] < rows[j][0] })
	b.WriteString(layoutTable([]string{"TOPIC", "PARTITION", "COMMITTED", "END", "LAG", "CLIENT"}, rows))
	return b.String()
}

type queueSent struct {
	Conn string `json:"conn"`
	*queuex.Sent
}

func (s queueSent) Text() string {
	switch {
	case s.NatsSent != nil:
		return natsSentText(s.Sent)
	case s.SqsSent != nil:
		return sqsSentText(s.Sent)
	case s.PubsubSent != nil:
		return pubsubSentText(s.Sent)
	}
	if s.Queue != "" {
		if s.DryRun {
			return fmt.Sprintf("would send %s to queue %s (nothing sent)\n", humanBytes(int64(s.Size)), s.Queue)
		}
		return fmt.Sprintf("sent %s to queue %s; the server confirmed it\n", humanBytes(int64(s.Size)), s.Queue)
	}
	if s.DryRun {
		where := "the partition its key picks"
		if s.Partition != nil {
			where = "partition " + strconv.Itoa(int(*s.Partition))
		}
		return fmt.Sprintf("would send %s to %s, %s (nothing sent)\n", humanBytes(int64(s.Size)), s.Topic, where)
	}
	return fmt.Sprintf("sent %s to %s, partition %d, offset %d\n", humanBytes(int64(s.Size)), s.Topic, *s.Partition, *s.Offset)
}

type queueCreated struct {
	Conn string `json:"conn"`
	*queuex.Created
}

func (c queueCreated) Text() string {
	switch {
	case c.NatsCreated != nil:
		return natsCreatedText(c.Created)
	case c.SqsCreated != nil:
		return sqsCreatedText(c.Created)
	case c.PubsubCreated != nil:
		return pubsubCreatedText(c.Created)
	}
	if c.RabbitCreated != nil {
		typ := c.Type
		if typ == "" {
			typ = "the vhost's default type"
		}
		verb := "created"
		if c.DryRun {
			verb = "would create (the name is free; nothing created):"
		}
		return fmt.Sprintf("%s durable queue %s (%s) in vhost %s\n", verb, c.Queue, typ, c.Vhost)
	}
	verb := "created"
	if c.DryRun {
		verb = "the brokers accept (nothing created):"
	}
	return fmt.Sprintf("%s topic %s with %s, %s\n", verb, c.Topic, defaultNum(int(c.Partitions), "partition"), defaultNum(int(c.Replicas), "replica"))
}

func defaultNum(n int, noun string) string {
	if n < 0 {
		return "the default number of " + noun + "s"
	}
	return countOf(n, noun)
}

type queueDeleted struct {
	Conn   string           `json:"conn"`
	Topics []queuex.Deleted `json:"topics"`
	DryRun bool             `json:"dry_run,omitempty"`
	kind   string
}

func (d queueDeleted) Text() string {
	if d.kind == "pubsub" {
		return pubsubDeletedText(d.Topics, d.DryRun)
	}
	var b strings.Builder
	verb := "deleted"
	if d.DryRun {
		verb = "would delete"
	}
	for _, t := range d.Topics {
		if !t.Exists {
			fmt.Fprintf(&b, "%s does not exist\n", t.Name())
			continue
		}
		fmt.Fprintf(&b, "%s %s (%s", verb, t.Name(), count64(t.Messages, "message"))
		if t.Consumers != nil && *t.Consumers > 0 {
			what := map[bool]string{true: "deleted with it", false: "cancelled"}[t.Stream != ""]
			fmt.Fprintf(&b, "; its %s %s %s", countOf(*t.Consumers, "consumer"), map[bool]string{true: "would be", false: "were"}[d.DryRun], what)
		}
		b.WriteString(")\n")
	}
	return b.String()
}

type queuePurged struct {
	Conn string `json:"conn"`
	*queuex.Purged
}

func (p queuePurged) Text() string {
	switch {
	case p.InFlight != nil:
		return sqsPurgedText(p.Purged)
	case p.Subscription != "":
		return pubsubPurgedText(p.Purged)
	}
	if p.Stream != "" {
		verb := map[bool]string{true: "would delete", false: "deleted"}[p.DryRun]
		return fmt.Sprintf("%s %s from stream %s; the stream and its consumers stay\n", verb, count64(p.Messages, "message"), p.Stream)
	}
	if p.Queue != "" {
		verb := "deleted"
		if p.DryRun {
			verb = "would delete"
		}
		return fmt.Sprintf("%s %s waiting in queue %s; the queue stays, and messages a consumer holds stay\n", verb, count64(p.Messages, "message"), p.Queue)
	}
	if p.DryRun {
		return fmt.Sprintf("would delete %s from %s (%s); the topic stays\n", count64(p.Messages, "message"), p.Topic, countOf(p.Partitions, "partition"))
	}
	return fmt.Sprintf("deleted %s from %s; the topic stays\n", count64(p.Messages, "message"), p.Topic)
}
