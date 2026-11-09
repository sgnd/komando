package queuex

import (
	"context"
	"fmt"
	"sort"
	"time"

	"github.com/twmb/franz-go/pkg/kadm"
	"github.com/twmb/franz-go/pkg/kgo"

	"github.com/sgnd/komando/internal/out"
)

// Message is what `queue send` publishes.
type Message struct {
	Topic     string
	Key       []byte // nil: no key
	Value     []byte
	Headers   [][2]string
	Partition int32 // -1: the broker's usual choice (by key, or spread out)
}

// Sent is where a message went (or, with dry run, would go).
type Sent struct {
	Topic string `json:"topic,omitempty"` // kafka
	Queue string `json:"queue,omitempty"` // rabbitmq
	*KafkaSent
	Size   int  `json:"size"`
	DryRun bool `json:"dry_run,omitempty"`
}

// KafkaSent is where a message went in a Kafka topic.
type KafkaSent struct {
	Partition *int32     `json:"partition"` // null on a dry run without --partition: chosen when sent
	Offset    *int64     `json:"offset"`    // null on a dry run
	Timestamp *time.Time `json:"timestamp,omitempty"`
}

// TopicSpec is a topic (or queue) `queue create` makes.
type TopicSpec struct {
	Topic      string
	Partitions int32  // kafka; -1: the broker's default
	Replicas   int16  // kafka; -1: the broker's default
	Type       string // rabbitmq: classic, quorum or stream ("": the server's default)
	Config     map[string]string
}

// Created is the topic or queue made (or checked, with dry run).
type Created struct {
	Topic string `json:"topic,omitempty"` // kafka
	Queue string `json:"queue,omitempty"` // rabbitmq
	*KafkaCreated
	*RabbitCreated
	DryRun bool `json:"dry_run,omitempty"`
}

// KafkaCreated is the Kafka topic made.
type KafkaCreated struct {
	Partitions int32             `json:"partitions"`
	Replicas   int16             `json:"replicas"`
	Config     map[string]string `json:"config"`
}

// Deleted is one topic or queue `queue rm` deleted (or would).
type Deleted struct {
	Topic     string `json:"topic,omitempty"` // kafka
	Queue     string `json:"queue,omitempty"` // rabbitmq
	Messages  int64  `json:"messages"`        // how many it held
	Consumers *int   `json:"consumers,omitempty"`
	Exists    bool   `json:"exists"`
}

// Name is the topic's or the queue's name.
func (d Deleted) Name() string { return d.Topic + d.Queue }

// Purged is what `queue purge` removed (or would).
type Purged struct {
	Topic      string `json:"topic,omitempty"` // kafka
	Queue      string `json:"queue,omitempty"` // rabbitmq
	Messages   int64  `json:"messages"`
	Partitions int    `json:"partitions,omitempty"` // kafka
	DryRun     bool   `json:"dry_run,omitempty"`
}

// Send publishes one message and waits for the brokers to keep it. The
// topic must exist: komando never lets the brokers create one on the fly.
func (k *Kafka) Send(ctx context.Context, m Message, dryRun bool) (*Sent, error) {
	td, err := k.topic(ctx, m.Topic)
	if err != nil {
		return nil, err
	}
	if m.Partition >= 0 {
		if _, ok := td.Partitions[m.Partition]; !ok {
			return nil, partitionNotFound(m.Topic, m.Partition, len(td.Partitions))
		}
	}
	res := &Sent{Topic: m.Topic, KafkaSent: &KafkaSent{}, Size: len(m.Value), DryRun: dryRun}
	if dryRun {
		if m.Partition >= 0 {
			res.Partition = &m.Partition
		}
		return res, nil
	}
	opts := []kgo.Opt{kgo.RequiredAcks(kgo.AllISRAcks()), kgo.DisableIdempotentWrite(), kgo.RecordRetries(3), kgo.UnknownTopicRetries(0),
		kgo.ProduceRequestTimeout(k.timeout)}
	if m.Partition >= 0 {
		opts = append(opts, kgo.RecordPartitioner(kgo.ManualPartitioner()))
	}
	cl, err := k.client(opts...)
	if err != nil {
		return nil, err
	}
	defer cl.Close()
	r := &kgo.Record{Topic: m.Topic, Key: m.Key, Value: m.Value, Partition: m.Partition}
	for _, h := range m.Headers {
		r.Headers = append(r.Headers, kgo.RecordHeader{Key: h[0], Value: []byte(h[1])})
	}
	got, err := cl.ProduceSync(ctx, r).First()
	if err != nil {
		return nil, opErr(err, m.Topic)
	}
	ts := got.Timestamp.UTC()
	res.Partition, res.Offset, res.Timestamp = &got.Partition, &got.Offset, &ts
	return res, nil
}

// Create makes a topic; with dry run the brokers only check it
// (validate_only), so a bad setting or too many replicas shows now.
func (k *Kafka) Create(ctx context.Context, s TopicSpec, dryRun bool) (*Created, error) {
	if s.Type != "" {
		return nil, NotSupported("--type", "kafka", "--type picks a RabbitMQ queue type; a Kafka topic takes --partitions, --replicas and --config")
	}
	cfg := map[string]*string{}
	for key, v := range s.Config {
		cfg[key] = &v
	}
	create := k.adm.CreateTopics
	if dryRun {
		create = k.adm.ValidateCreateTopics
	}
	rs, err := create(ctx, s.Partitions, s.Replicas, cfg, s.Topic)
	if err != nil {
		return nil, opErr(err, s.Topic)
	}
	r, err := rs.On(s.Topic, nil)
	if err == nil {
		err = r.Err
	}
	if err != nil {
		if r.ErrMessage != "" {
			err = fmt.Errorf("%w: %s", err, r.ErrMessage)
		}
		return nil, opErr(err, s.Topic)
	}
	res := &Created{Topic: s.Topic, KafkaCreated: &KafkaCreated{Partitions: r.NumPartitions, Replicas: r.ReplicationFactor, Config: map[string]string{}}, DryRun: dryRun}
	if res.Partitions <= 0 {
		res.Partitions = s.Partitions
	}
	if res.Replicas <= 0 {
		res.Replicas = s.Replicas
	}
	for key, v := range s.Config {
		res.Config[key] = v
	}
	return res, nil
}

// Delete deletes topics. Every name must exist; with dry run it only says
// what each holds.
func (k *Kafka) Delete(ctx context.Context, topics []string, dryRun bool) ([]Deleted, error) {
	tds, err := k.adm.ListTopicsWithInternal(ctx, topics...)
	if err != nil {
		return nil, opErr(err, topics[0])
	}
	var have []string
	for _, t := range topics {
		if td, ok := tds[t]; ok && td.Err == nil {
			have = append(have, t)
		}
	}
	res := []Deleted{}
	counts := map[string]int64{}
	if len(have) > 0 {
		starts, ends, err := k.offsets(ctx, have...)
		if err != nil {
			return nil, err
		}
		for _, t := range have {
			for p := range tds[t].Partitions {
				counts[t] += count(starts, ends, t, p)
			}
		}
	}
	for _, t := range topics {
		_, ok := counts[t]
		res = append(res, Deleted{Topic: t, Messages: counts[t], Exists: ok})
	}
	sort.Slice(res, func(i, j int) bool { return res[i].Topic < res[j].Topic })
	if dryRun {
		return res, nil
	}
	for _, d := range res {
		if !d.Exists {
			return nil, topicNotFound(d.Topic)
		}
	}
	rs, err := k.adm.DeleteTopics(ctx, have...)
	if err != nil {
		return nil, opErr(err, have[0])
	}
	for _, r := range rs.Sorted() {
		if r.Err != nil {
			return nil, opErr(r.Err, r.Topic)
		}
	}
	return res, nil
}

// Purge deletes every message of a topic and keeps the topic (Kafka's
// DeleteRecords up to each partition's end).
func (k *Kafka) Purge(ctx context.Context, topic string, dryRun bool) (*Purged, error) {
	td, err := k.topic(ctx, topic)
	if err != nil {
		return nil, err
	}
	starts, ends, err := k.offsets(ctx, topic)
	if err != nil {
		return nil, err
	}
	res := &Purged{Topic: topic, Partitions: len(td.Partitions), DryRun: dryRun}
	to := kadm.Offsets{}
	for p := range td.Partitions {
		if n := count(starts, ends, topic, p); n > 0 {
			res.Messages += n
			e, _ := ends.Lookup(topic, p)
			to.Add(kadm.Offset{Topic: topic, Partition: p, At: e.Offset, LeaderEpoch: -1})
		}
	}
	if dryRun || len(to) == 0 {
		return res, nil
	}
	rs, err := k.adm.DeleteRecords(ctx, to)
	if err != nil {
		return nil, opErr(err, topic)
	}
	if err := rs.Error(); err != nil {
		return nil, opErr(err, topic)
	}
	return res, nil
}

func partitionNotFound(topic string, p int32, n int) error {
	return out.Errf(out.ExitNotFound, "PARTITION_NOT_FOUND", "partitions are numbered from 0; see them with `komando queue describe CONN "+topic+"`",
		"topic %s has no partition %d (it has %d)", topic, p, n)
}
