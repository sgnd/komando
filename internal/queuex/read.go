package queuex

import (
	"context"
	"net"
	"path"
	"sort"
	"strconv"

	"github.com/twmb/franz-go/pkg/kadm"
	"github.com/twmb/franz-go/pkg/kmsg"
)

// Info is the cluster at a glance. Engine says which of the embedded
// parts is there: KafkaInfo or RabbitInfo (see rabbit.go).
type Info struct {
	Engine  string `json:"engine"` // kafka | rabbitmq | nats | sqs
	Version string `json:"version,omitempty"`
	*KafkaInfo
	*RabbitInfo
	*NatsInfo
	*SqsInfo
}

// KafkaInfo is what `queue info` shows of a Kafka cluster.
type KafkaInfo struct {
	ClusterID  string   `json:"cluster_id,omitempty"`
	Controller int32    `json:"controller"` // broker id, -1 when unknown
	Brokers    []Broker `json:"brokers"`
	Topics     int      `json:"topics"` // not counting internal ones
}

// Broker is one broker of the cluster.
type Broker struct {
	ID         int32  `json:"id"`
	Address    string `json:"address"` // as it advertises itself
	Rack       string `json:"rack,omitempty"`
	Controller bool   `json:"controller,omitempty"`
	Version    string `json:"version,omitempty"` // a guess from the API versions it takes
}

// Topic is one line of `queue ls`: a Kafka topic, a RabbitMQ queue or a
// NATS JetStream stream.
type Topic struct {
	Name     string `json:"name"`
	Messages int64  `json:"messages"` // kafka: end minus start offset, an upper bound on compacted topics
	*KafkaTopic
	*RabbitQueue
	*NatsStream
	*SqsQueue
}

// KafkaTopic is what `queue ls` shows of a Kafka topic.
type KafkaTopic struct {
	Partitions int  `json:"partitions"`
	Replicas   int  `json:"replicas"`
	Internal   bool `json:"internal,omitempty"`
}

// TopicDetail is `queue describe`: a Kafka topic, a RabbitMQ queue or a
// NATS stream.
type TopicDetail struct {
	Name     string `json:"name"`
	Messages int64  `json:"messages"`
	*KafkaTopicDetail
	*RabbitQueueDetail
	*NatsStreamDetail
	*SqsQueueDetail
}

// KafkaTopicDetail is what `queue describe` shows of a Kafka topic.
type KafkaTopicDetail struct {
	ID         string            `json:"id,omitempty"`
	Internal   bool              `json:"internal,omitempty"`
	Replicas   int               `json:"replicas"`
	Partitions []Partition       `json:"partitions"`
	Config     map[string]string `json:"config"` // settings that differ from the broker's defaults
	Groups     []GroupOnTopic    `json:"groups"`
}

// Partition is one partition of a topic.
type Partition struct {
	ID       int32   `json:"id"`
	Leader   int32   `json:"leader"` // -1: no leader (offline)
	Replicas []int32 `json:"replicas"`
	ISR      []int32 `json:"in_sync"`
	Start    int64   `json:"start_offset"`
	End      int64   `json:"end_offset"`
	Messages int64   `json:"messages"`
	Error    string  `json:"error,omitempty"`
}

// GroupOnTopic is a consumer group that reads a topic, and how far behind.
type GroupOnTopic struct {
	Group string `json:"group"`
	State string `json:"state"`
	Lag   int64  `json:"lag"`
}

// Group is one line of `queue groups`: a Kafka consumer group, or a NATS
// consumer (NatsConsumer says more).
type Group struct {
	Name     string   `json:"name"`
	State    string   `json:"state"`
	Protocol string   `json:"protocol,omitempty"` // range, roundrobin, cooperative-sticky ...
	Members  int      `json:"members"`
	Topics   []string `json:"topics"`
	Lag      int64    `json:"lag"`
	Error    string   `json:"error,omitempty"`
	*NatsConsumer
}

// GroupLag is `queue lag`: one group, per topic and partition.
type GroupLag struct {
	Group      string         `json:"group"`
	State      string         `json:"state"`
	Members    int            `json:"members"`
	Lag        int64          `json:"lag"`
	Partitions []PartitionLag `json:"partitions"` // nats: none, a stream has no partitions
	*NatsConsumer
}

// PartitionLag is where a group is in one partition.
type PartitionLag struct {
	Topic     string `json:"topic"`
	Partition int32  `json:"partition"`
	Committed int64  `json:"committed"` // -1: nothing committed yet
	End       int64  `json:"end_offset"`
	Lag       int64  `json:"lag"` // -1 when it cannot be worked out (see error)
	Member    string `json:"member,omitempty"`
	Client    string `json:"client_id,omitempty"`
	Host      string `json:"client_host,omitempty"`
	Error     string `json:"error,omitempty"`
}

// Info reads the brokers, the controller and a version guess.
func (k *Kafka) Info(ctx context.Context) (*Info, error) {
	md, err := k.adm.Metadata(ctx)
	if err != nil {
		return nil, opErr(err, "metadata")
	}
	inf := &Info{Engine: "kafka", KafkaInfo: &KafkaInfo{ClusterID: md.Cluster, Controller: md.Controller, Brokers: []Broker{}}}
	vers, _ := k.adm.ApiVersions(ctx) // a guess only: no error if it fails
	for _, b := range md.Brokers {
		br := Broker{ID: b.NodeID, Address: net.JoinHostPort(b.Host, strconv.Itoa(int(b.Port))), Controller: b.NodeID == md.Controller}
		if b.Rack != nil {
			br.Rack = *b.Rack
		}
		if v, ok := vers[b.NodeID]; ok && v.Err == nil {
			br.Version = v.VersionGuess()
		}
		if inf.Version == "" {
			inf.Version = br.Version
		}
		inf.Brokers = append(inf.Brokers, br)
	}
	sort.Slice(inf.Brokers, func(i, j int) bool { return inf.Brokers[i].ID < inf.Brokers[j].ID })
	for _, td := range md.Topics {
		if !td.IsInternal {
			inf.Topics++
		}
	}
	return inf, nil
}

// Topics lists topics whose name matches pattern (shell style: orders-*).
func (k *Kafka) Topics(ctx context.Context, pattern string, internal bool) ([]Topic, error) {
	tds, err := k.adm.ListTopicsWithInternal(ctx)
	if err != nil {
		return nil, opErr(err, "topics")
	}
	var names []string
	for name, td := range tds {
		if td.Err == nil && (internal || !td.IsInternal) && Match(pattern, name) {
			names = append(names, name)
		}
	}
	sort.Strings(names)
	res := []Topic{}
	if len(names) == 0 {
		return res, nil
	}
	starts, ends, err := k.offsets(ctx, names...)
	if err != nil {
		return nil, err
	}
	for _, name := range names {
		td := tds[name]
		t := Topic{Name: name, KafkaTopic: &KafkaTopic{Partitions: len(td.Partitions), Internal: td.IsInternal}}
		for _, p := range td.Partitions {
			t.Replicas = max(t.Replicas, len(p.Replicas))
			t.Messages += count(starts, ends, name, p.Partition)
		}
		res = append(res, t)
	}
	return res, nil
}

// Match says whether name matches a shell-style pattern ("" and "*" match
// everything).
func Match(pattern, name string) bool {
	if pattern == "" || pattern == "*" {
		return true
	}
	ok, err := path.Match(pattern, name)
	return err == nil && ok
}

// offsets are the start and end offsets of every partition of topics.
func (k *Kafka) offsets(ctx context.Context, topics ...string) (kadm.ListedOffsets, kadm.ListedOffsets, error) {
	starts, err := k.adm.ListStartOffsets(ctx, topics...)
	if err != nil {
		return nil, nil, opErr(err, "offsets")
	}
	ends, err := k.adm.ListEndOffsets(ctx, topics...)
	if err != nil {
		return nil, nil, opErr(err, "offsets")
	}
	return starts, ends, nil
}

// count is how many messages a partition holds: end minus start offset.
func count(starts, ends kadm.ListedOffsets, topic string, p int32) int64 {
	s, ok1 := starts.Lookup(topic, p)
	e, ok2 := ends.Lookup(topic, p)
	if !ok1 || !ok2 || s.Err != nil || e.Err != nil || e.Offset < s.Offset {
		return 0
	}
	return e.Offset - s.Offset
}

// topic reads one topic's metadata, or TOPIC_NOT_FOUND.
func (k *Kafka) topic(ctx context.Context, name string) (kadm.TopicDetail, error) {
	tds, err := k.adm.ListTopicsWithInternal(ctx, name)
	if err != nil {
		return kadm.TopicDetail{}, opErr(err, name)
	}
	td, ok := tds[name]
	if !ok {
		return kadm.TopicDetail{}, topicNotFound(name)
	}
	if td.Err != nil {
		return kadm.TopicDetail{}, opErr(td.Err, name)
	}
	return td, nil
}

// Describe reads a topic's partitions, its own settings and the groups
// that read it.
func (k *Kafka) Describe(ctx context.Context, name string) (*TopicDetail, error) {
	td, err := k.topic(ctx, name)
	if err != nil {
		return nil, err
	}
	starts, ends, err := k.offsets(ctx, name)
	if err != nil {
		return nil, err
	}
	d := &TopicDetail{Name: name, KafkaTopicDetail: &KafkaTopicDetail{Internal: td.IsInternal, Partitions: []Partition{}, Config: map[string]string{}, Groups: []GroupOnTopic{}}}
	if td.ID != (kadm.TopicID{}) {
		d.ID = td.ID.String()
	}
	for _, p := range td.Partitions.Sorted() {
		pp := Partition{ID: p.Partition, Leader: p.Leader, Replicas: p.Replicas, ISR: p.ISR, Messages: count(starts, ends, name, p.Partition)}
		if s, ok := starts.Lookup(name, p.Partition); ok {
			pp.Start = s.Offset
		}
		if e, ok := ends.Lookup(name, p.Partition); ok {
			pp.End = e.Offset
		}
		if p.Err != nil {
			pp.Error = p.Err.Error()
		}
		d.Replicas = max(d.Replicas, len(p.Replicas))
		d.Messages += pp.Messages
		d.Partitions = append(d.Partitions, pp)
	}
	if cfgs, err := k.adm.DescribeTopicConfigs(ctx, name); err == nil {
		for _, rc := range cfgs {
			for _, c := range rc.Configs {
				if c.Source == kmsg.ConfigSourceDynamicTopicConfig && !c.Sensitive {
					d.Config[c.Key] = c.MaybeValue()
				}
			}
		}
	}
	lags, err := k.adm.Lag(ctx)
	if err != nil {
		return d, nil // groups need more rights than the topic; leave them out
	}
	for _, l := range lags.Sorted() {
		if _, reads := l.Lag[name]; reads {
			d.Groups = append(d.Groups, GroupOnTopic{Group: l.Group, State: l.State, Lag: l.Lag.TotalByTopic()[name].Lag})
		}
	}
	return d, nil
}

// Groups lists the consumer groups with their total lag.
func (k *Kafka) Groups(ctx context.Context) ([]Group, error) {
	lags, err := k.adm.Lag(ctx)
	if err != nil {
		return nil, opErr(err, "groups")
	}
	res := []Group{}
	for _, l := range lags.Sorted() {
		g := Group{Name: l.Group, State: l.State, Protocol: l.Protocol, Members: len(l.Members), Topics: []string{}, Lag: l.Lag.Total()}
		for _, tl := range l.Lag.TotalByTopic().Sorted() {
			g.Topics = append(g.Topics, tl.Topic)
		}
		if e := l.Error(); e != nil {
			g.Error = e.Error()
		}
		res = append(res, g)
	}
	return res, nil
}

// Lag is one group's position in every partition it reads.
func (k *Kafka) Lag(ctx context.Context, group string) (*GroupLag, error) {
	lags, err := k.adm.Lag(ctx, group)
	if err != nil {
		return nil, opErr(err, group)
	}
	l, ok := lags[group]
	if !ok || l.State == "Dead" {
		return nil, groupNotFound(group)
	}
	if e := l.Error(); e != nil {
		return nil, opErr(e, group)
	}
	res := &GroupLag{Group: group, State: l.State, Members: len(l.Members), Lag: l.Lag.Total(), Partitions: []PartitionLag{}}
	for _, m := range l.Lag.Sorted() {
		pl := PartitionLag{Topic: m.Topic, Partition: m.Partition, Committed: m.Commit.At, End: m.End.Offset, Lag: m.Lag}
		if m.Member != nil {
			pl.Member, pl.Client, pl.Host = m.Member.MemberID, m.Member.ClientID, m.Member.ClientHost
		}
		if m.Err != nil {
			pl.Error = m.Err.Error()
		}
		res.Partitions = append(res.Partitions, pl)
	}
	return res, nil
}
