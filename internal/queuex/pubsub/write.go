package pubsub

import (
	"context"
	"encoding/base64"
	"net/http"
	"sort"
	"time"

	"github.com/sgnd/komando/internal/out"
	"github.com/sgnd/komando/internal/queuex"
)

// topicRef reads a name a command takes as a topic (NAME or topics/NAME).
func (p *Pubsub) topicRef(verb, s string) (string, error) {
	r, err := p.parseRef(s)
	if err == nil && r.kind == "subscription" {
		err = out.Usage("queue %s takes a topic, not a subscription: give the topic's name", verb)
	}
	return r.name, err
}

// subRef reads a name a command takes as a subscription (NAME or
// subscriptions/NAME).
func (p *Pubsub) subRef(verb, s string) (string, error) {
	r, err := p.parseRef(s)
	if err == nil && r.kind == "topic" {
		err = out.Usage("queue %s takes a subscription: a Pub/Sub topic keeps no messages of its own (`komando queue describe CONN %s` lists its subscriptions)", verb, s)
	}
	return r.name, err
}

// Send publishes one message to a topic. Headers become the message's
// attributes; --key is its ordering key (a subscription with ordering
// gives messages of one key in order).
func (p *Pubsub) Send(ctx context.Context, m queuex.Message, dryRun bool) (*queuex.Sent, error) {
	if m.Partition >= 0 {
		return nil, queuex.NotSupported("--partition", "pubsub", "a Pub/Sub topic has no partitions: drop --partition (--key sets the ordering key)")
	}
	name, err := p.topicRef("send", m.Topic)
	if err != nil {
		return nil, err
	}
	if len(m.Value) == 0 && len(m.Headers) == 0 {
		return nil, out.Usage("Pub/Sub takes no empty message: give a value, or at least one --header")
	}
	if _, err := p.getTopic(ctx, name); err != nil {
		return nil, err
	}
	res := &queuex.Sent{Topic: name, Size: len(m.Value), DryRun: dryRun, PubsubSent: &queuex.PubsubSent{OrderingKey: string(m.Key)}}
	if dryRun {
		return res, nil
	}
	msg := map[string]any{"data": base64.StdEncoding.EncodeToString(m.Value)}
	if len(m.Headers) > 0 {
		attrs := map[string]string{}
		for _, h := range m.Headers {
			attrs[h[0]] = h[1]
		}
		msg["attributes"] = attrs
	}
	if len(m.Key) > 0 {
		msg["orderingKey"] = string(m.Key)
	}
	var sent struct {
		MessageIDs []string `json:"messageIds"`
	}
	if err := p.call(ctx, http.MethodPost, p.path(ref{name: name}, "topic")+":publish", map[string]any{"messages": []any{msg}}, &sent); err != nil {
		return nil, opErr(err, name, topicNotFound)
	}
	if len(sent.MessageIDs) == 0 {
		return nil, out.Errf(out.ExitRemote, "QUEUE_ERROR", "send it again; if this repeats, the endpoint may not be Pub/Sub", "topic %s: Pub/Sub gave no message ID", name)
	}
	res.ID = &sent.MessageIDs[0]
	return res, nil
}

// Create makes a topic, or a subscription when the name is
// subscriptions/NAME or --config names its topic (topic=NAME). Pub/Sub
// cannot check a resource without making it, so a dry run checks the
// names and settings and makes nothing.
func (p *Pubsub) Create(ctx context.Context, sp queuex.TopicSpec, dryRun bool) (*queuex.Created, error) {
	switch {
	case sp.Partitions != -1 || sp.Replicas != -1:
		return nil, queuex.NotSupported("--partitions and --replicas", "pubsub", "a Pub/Sub topic has no partitions, and Google keeps its copies itself: drop them")
	case sp.Type != "":
		return nil, queuex.NotSupported("--type", "pubsub", "a name makes a topic; subscriptions/NAME --config topic=TOPIC makes a subscription")
	}
	r, err := p.parseRef(sp.Topic)
	if err != nil {
		return nil, err
	}
	topic, body, err := p.settings(r, sp.Config)
	if err != nil {
		return nil, err
	}
	kind := "topic"
	if topic != "" {
		kind = "subscription"
	}
	res := &queuex.Created{PubsubCreated: &queuex.PubsubCreated{FullName: p.full(kind, r.name), OfTopic: shortName(topic), Settings: sp.Config}, DryRun: dryRun}
	if kind == "topic" {
		res.Topic = r.name
		if _, err := p.getTopic(ctx, r.name); err == nil {
			return nil, topicExists(r.name)
		} else if !isCode(err, "TOPIC_NOT_FOUND") {
			return nil, err
		}
	} else {
		res.Subscription = r.name
		if err := p.canSubscribe(ctx, r.name, topic); err != nil {
			return nil, err
		}
	}
	if dryRun {
		return res, nil
	}
	if err := p.call(ctx, http.MethodPut, p.path(r, kind), body, nil); err != nil {
		switch {
		case isStatus(err, 409) && kind == "topic":
			return nil, topicExists(r.name)
		case isStatus(err, 409):
			return nil, subExists(r.name)
		}
		return nil, opErr(err, r.name, topicNotFound)
	}
	return res, nil
}

// canSubscribe checks that the subscription is free and its topic there.
func (p *Pubsub) canSubscribe(ctx context.Context, name, topic string) error {
	if _, err := p.getSub(ctx, name); err == nil {
		return subExists(name)
	} else if !isCode(err, "SUBSCRIPTION_NOT_FOUND") {
		return err
	}
	if err := p.call(ctx, http.MethodGet, escapePath(topic), nil, nil); err != nil {
		return opErr(err, shortName(topic), topicNotFound)
	}
	return nil
}

// Delete deletes topics, or subscriptions written subscriptions/NAME.
// Every name must exist; with dry run it only says what each is. Deleting
// a topic leaves its subscriptions and their messages: they are cut off
// (their topic becomes _deleted-topic_). Deleting a subscription deletes
// the messages it held. Pub/Sub does not count them, so messages is -1.
func (p *Pubsub) Delete(ctx context.Context, names []string, dryRun bool) ([]queuex.Deleted, error) {
	res := []queuex.Deleted{}
	var subs []apiSub // read once, for the topics' subscription counts
	for _, n := range names {
		r, err := p.parseRef(n)
		if err != nil {
			return nil, err
		}
		d := queuex.Deleted{Messages: -1}
		if r.kind == "subscription" {
			d.Subscription = r.name
			_, err = p.getSub(ctx, r.name)
		} else {
			d.Topic = r.name
			_, err = p.getTopic(ctx, r.name)
		}
		switch {
		case err == nil:
			d.Exists = true
		case !isCode(err, "TOPIC_NOT_FOUND") && !isCode(err, "SUBSCRIPTION_NOT_FOUND"):
			return nil, err
		case !dryRun:
			return nil, err
		}
		if d.Exists && d.Topic != "" {
			if subs == nil {
				if subs, err = p.subscriptions(ctx); err != nil {
					return nil, err
				}
			}
			count := 0
			for _, s := range subs {
				if s.Topic == p.full("topic", r.name) {
					count++
				}
			}
			d.Consumers = &count
		}
		res = append(res, d)
	}
	sort.SliceStable(res, func(i, j int) bool { return res[i].Name() < res[j].Name() })
	if dryRun {
		return res, nil
	}
	for _, d := range res {
		kind := "topic"
		if d.Subscription != "" {
			kind = "subscription"
		}
		if err := p.call(ctx, http.MethodDelete, p.path(ref{name: d.Name()}, kind), nil, nil); err != nil {
			return nil, opErr(err, d.Name(), nil)
		}
	}
	return res, nil
}

// Purge empties a subscription and keeps it: a seek to now, which marks
// every message published before now as acknowledged, also those a
// subscriber pulled and has not acknowledged yet. Other subscriptions of
// the topic keep theirs. Pub/Sub does not count them, so messages is -1.
func (p *Pubsub) Purge(ctx context.Context, name string, dryRun bool) (*queuex.Purged, error) {
	sub, err := p.subRef("purge", name)
	if err != nil {
		return nil, err
	}
	if _, err := p.getSub(ctx, sub); err != nil {
		return nil, err
	}
	res := &queuex.Purged{Subscription: sub, Messages: -1, DryRun: dryRun}
	if dryRun {
		return res, nil
	}
	in := map[string]any{"time": time.Now().UTC().Format(time.RFC3339Nano)}
	if err := p.call(ctx, http.MethodPost, p.path(ref{name: sub}, "subscription")+":seek", in, nil); err != nil {
		return nil, opErr(err, sub, subNotFound)
	}
	return res, nil
}
