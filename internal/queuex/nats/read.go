package nats

import (
	"context"
	"encoding/json"
	"errors"
	"sort"
	"strings"

	"github.com/nats-io/nats.go/jetstream"

	"github.com/sgnd/komando/internal/out"
	"github.com/sgnd/komando/internal/queuex"
)

// Info is the server komando talks to and its account's JetStream use.
// A server or account without JetStream still answers, with jetstream
// false.
func (n *Nats) Info(ctx context.Context) (*queuex.Info, error) {
	inf := &queuex.Info{Engine: "nats", Version: n.nc.ConnectedServerVersion(), NatsInfo: &queuex.NatsInfo{
		ServerName: n.nc.ConnectedServerName(), ServerID: n.nc.ConnectedServerId(), ClusterName: n.nc.ConnectedClusterName(),
		Connected: strings.TrimPrefix(n.nc.ConnectedUrlRedacted(), "nats://"), MaxPayload: n.nc.MaxPayload(), Domain: n.t.Domain,
	}}
	ai, err := n.js.AccountInfo(ctx)
	switch {
	case err != nil && noJetStream(err):
		return inf, nil
	case err != nil:
		return nil, n.opErr(err, "account")
	}
	inf.JetStream = true
	if ai.Domain != "" {
		inf.Domain = ai.Domain
	}
	inf.Account = &queuex.NatsAccount{Streams: ai.Streams, Consumers: ai.Consumers, Memory: ai.Memory, Storage: ai.Store,
		MaxMemory: ai.Limits.MaxMemory, MaxStorage: ai.Limits.MaxStore, MaxStreams: ai.Limits.MaxStreams, MaxConsumers: ai.Limits.MaxConsumers}
	return inf, nil
}

// streams are the account's streams, sorted by name.
func (n *Nats) streams(ctx context.Context) ([]*jetstream.StreamInfo, error) {
	l := n.js.ListStreams(ctx)
	var res []*jetstream.StreamInfo
	for si := range l.Info() {
		res = append(res, si)
	}
	if err := l.Err(); err != nil {
		return nil, n.opErr(err, "streams")
	}
	sort.Slice(res, func(i, j int) bool { return res[i].Config.Name < res[j].Config.Name })
	return res, nil
}

// Topics lists the streams whose name matches pattern. Key-value buckets
// (KV_NAME) and object stores (OBJ_NAME) are streams too, and are listed.
func (n *Nats) Topics(ctx context.Context, pattern string, internal bool) ([]queuex.Topic, error) {
	if internal {
		return nil, queuex.NotSupported("--internal", "nats", "`komando queue ls CONN` lists every stream of the account, key-value buckets (KV_*) and object stores (OBJ_*) too")
	}
	sis, err := n.streams(ctx)
	if err != nil {
		return nil, err
	}
	res := []queuex.Topic{}
	for _, si := range sis {
		if queuex.Match(pattern, si.Config.Name) {
			res = append(res, queuex.Topic{Name: si.Config.Name, Messages: int64(si.State.Msgs), NatsStream: summary(si)})
		}
	}
	return res, nil
}

func summary(si *jetstream.StreamInfo) *queuex.NatsStream {
	c, st := si.Config, si.State
	subjects := c.Subjects
	if subjects == nil {
		subjects = []string{}
	}
	return &queuex.NatsStream{Subjects: subjects, Bytes: st.Bytes, ConsumerCount: st.Consumers, Storage: word(c.Storage), Retention: word(c.Retention),
		NumReplicas: max(c.Replicas, 1), FirstSeq: st.FirstSeq, LastSeq: st.LastSeq, Sealed: c.Sealed}
}

// word is a JetStream setting as the server writes it (file, workqueue).
func word(v json.Marshaler) string {
	b, err := v.MarshalJSON()
	if err != nil {
		return "unknown"
	}
	return strings.Trim(string(b), `"`)
}

// Describe reads a stream's settings, state, copies and consumers.
func (n *Nats) Describe(ctx context.Context, name string) (*queuex.TopicDetail, error) {
	s, err := n.stream(ctx, name)
	if err != nil {
		return nil, err
	}
	si := s.CachedInfo()
	c, st := si.Config, si.State
	d := &queuex.NatsStreamDetail{NatsStream: *summary(si), Description: c.Description, Discard: word(c.Discard), Limits: limits(c),
		NumDeleted: st.NumDeleted, NumSubjects: st.NumSubjects, DenyDelete: c.DenyDelete, DenyPurge: c.DenyPurge, Created: si.Created.UTC(),
		ConsumerInfo: []queuex.NatsConsumer{}}
	if st.Msgs > 0 {
		first, last := st.FirstTime.UTC(), st.LastTime.UTC()
		d.FirstTime, d.LastTime = &first, &last
	}
	if cl := si.Cluster; cl != nil && (cl.Name != "" || len(cl.Replicas) > 0) {
		d.Cluster = &queuex.NatsCluster{Name: cl.Name, Leader: cl.Leader}
		for _, p := range cl.Replicas {
			d.Cluster.Replicas = append(d.Cluster.Replicas, queuex.NatsReplica{Name: p.Name, Current: p.Current, Offline: p.Offline, Lag: p.Lag})
		}
	}
	if si.Mirror != nil {
		d.Mirror = si.Mirror.Name
	}
	for _, src := range si.Sources {
		d.Sources = append(d.Sources, src.Name)
	}
	cis, err := n.consumers(ctx, s, name)
	if err != nil {
		return nil, err
	}
	for _, ci := range cis {
		nc := consumer(ci)
		nc.Consumer = ci.Name
		d.ConsumerInfo = append(d.ConsumerInfo, *nc)
	}
	return &queuex.TopicDetail{Name: name, Messages: int64(st.Msgs), NatsStreamDetail: d}, nil
}

func limits(c jetstream.StreamConfig) queuex.NatsLimits {
	l := queuex.NatsLimits{MaxMsgs: c.MaxMsgs, MaxBytes: c.MaxBytes, MaxAge: c.MaxAge.String(), MaxMsgSize: c.MaxMsgSize,
		MaxMsgsPerSubject: c.MaxMsgsPerSubject, MaxConsumers: c.MaxConsumers}
	if c.Duplicates > 0 {
		l.DuplicateWindow = c.Duplicates.String()
	}
	return l
}

// consumers are a stream's consumers, sorted by name.
func (n *Nats) consumers(ctx context.Context, s jetstream.Stream, stream string) ([]*jetstream.ConsumerInfo, error) {
	l := s.ListConsumers(ctx)
	var res []*jetstream.ConsumerInfo
	for ci := range l.Info() {
		res = append(res, ci)
	}
	if err := l.Err(); err != nil {
		return nil, n.opErr(err, stream)
	}
	sort.Slice(res, func(i, j int) bool { return res[i].Name < res[j].Name })
	return res, nil
}

// consumer is what komando shows of a consumer.
func consumer(ci *jetstream.ConsumerInfo) *queuex.NatsConsumer {
	c := ci.Config
	kind := "pull"
	if c.DeliverSubject != "" {
		kind = "push"
	}
	filters := c.FilterSubjects
	if c.FilterSubject != "" {
		filters = append([]string{c.FilterSubject}, filters...)
	}
	res := &queuex.NatsConsumer{Stream: ci.Stream, Durable: c.Durable != "", Kind: kind, AckPolicy: word(c.AckPolicy), FilterSubjects: filters,
		Pending: ci.NumPending, AckPending: ci.NumAckPending, Redelivered: ci.NumRedelivered, Waiting: ci.NumWaiting,
		DeliveredSeq: ci.Delivered.Stream, AckFloorSeq: ci.AckFloor.Stream, Paused: ci.Paused}
	if last := ci.Delivered.Last; last != nil && !last.IsZero() {
		t := last.UTC()
		res.LastActive = &t
	}
	return res
}

// state is a consumer's state in a word: paused, active (a push consumer
// with a subscriber, or a pull consumer with requests waiting) or idle.
// members is how many readers it has: its waiting pull requests, or 1 for
// a push consumer with a subscriber.
func state(ci *jetstream.ConsumerInfo) (string, int) {
	members := ci.NumWaiting
	if ci.Config.DeliverSubject != "" {
		members = map[bool]int{true: 1}[ci.PushBound]
	}
	switch {
	case ci.Paused:
		return "paused", members
	case members > 0:
		return "active", members
	}
	return "idle", members
}

// Groups lists the consumers of every stream. Lag is what each has not
// been given yet (pending).
func (n *Nats) Groups(ctx context.Context) ([]queuex.Group, error) {
	sis, err := n.streams(ctx)
	if err != nil {
		return nil, err
	}
	res := []queuex.Group{}
	for _, si := range sis {
		if si.State.Consumers == 0 {
			continue
		}
		s, err := n.stream(ctx, si.Config.Name)
		if err != nil {
			return nil, err
		}
		cis, err := n.consumers(ctx, s, si.Config.Name)
		if err != nil {
			return nil, err
		}
		for _, ci := range cis {
			st, members := state(ci)
			res = append(res, queuex.Group{Name: ci.Name, State: st, Members: members, Topics: []string{ci.Stream}, Lag: int64(ci.NumPending), NatsConsumer: consumer(ci)})
		}
	}
	return res, nil
}

// Lag is one consumer, named STREAM/CONSUMER or by its name alone when
// only one stream has a consumer of that name.
func (n *Nats) Lag(ctx context.Context, group string) (*queuex.GroupLag, error) {
	stream, name, ok := strings.Cut(group, "/")
	if !ok {
		var err error
		name = group
		if stream, err = n.streamOf(ctx, name); err != nil {
			return nil, err
		}
	}
	if err := checkName("consumer", name); err != nil {
		return nil, err
	}
	s, err := n.stream(ctx, stream)
	if err != nil {
		return nil, err
	}
	ci, err := consumerInfo(ctx, s, name)
	if err != nil {
		return nil, n.opErr(err, group)
	}
	st, members := state(ci)
	return &queuex.GroupLag{Group: name, State: st, Members: members, Lag: int64(ci.NumPending), Partitions: []queuex.PartitionLag{}, NatsConsumer: consumer(ci)}, nil
}

// consumerInfo reads one consumer, pull or push.
func consumerInfo(ctx context.Context, s jetstream.Stream, name string) (*jetstream.ConsumerInfo, error) {
	c, err := s.Consumer(ctx, name)
	if errors.Is(err, jetstream.ErrNotPullConsumer) {
		pc, err := s.PushConsumer(ctx, name)
		if err != nil {
			return nil, err
		}
		return pc.CachedInfo(), nil
	}
	if err != nil {
		return nil, err
	}
	return c.CachedInfo(), nil
}

// streamOf is the one stream that has a consumer of this name.
func (n *Nats) streamOf(ctx context.Context, name string) (string, error) {
	gs, err := n.Groups(ctx)
	if err != nil {
		return "", err
	}
	var in []string
	for _, g := range gs {
		if g.Name == name {
			in = append(in, g.Stream)
		}
	}
	switch len(in) {
	case 0:
		return "", consumerNotFound(name)
	case 1:
		return in[0], nil
	}
	return "", out.Errf(out.ExitUsage, "USAGE", "name it with its stream, as in `komando queue lag CONN "+in[0]+"/"+name+"`",
		"streams %s each have a consumer %s", strings.Join(in, ", "), name)
}
