package pubsub

import (
	"context"
	"encoding/base64"
	"net/http"
	"time"

	"github.com/sgnd/komando/internal/out"
	"github.com/sgnd/komando/internal/queuex"
)

// keepDeliveries is how many deliveries peek leaves a message of a
// subscription with a dead-letter topic for its real subscribers: below
// that it stops.
const keepDeliveries = 3

// maxPerPull is the most messages peek asks for in one pull, so one
// answer stays well under maxResponse even with big messages.
const maxPerPull = 8

// emptyPulls is how many pulls in a row may bring nothing new before peek
// stops: a pull that returns at once can come back empty while messages
// wait.
const emptyPulls = 3

type received struct {
	AckID   string `json:"ackId"`
	Message struct {
		Data        string            `json:"data"` // base64
		Attributes  map[string]string `json:"attributes"`
		MessageID   string            `json:"messageId"`
		PublishTime *time.Time        `json:"publishTime"`
		OrderingKey string            `json:"orderingKey"`
	} `json:"message"`
	DeliveryAttempt int `json:"deliveryAttempt"`
}

// Peek pulls up to o.Limit messages from a subscription and gives every
// one back unacknowledged (its ack deadline set to 0), so Pub/Sub keeps
// them all and delivers them again at once. While peek runs (a few
// seconds) the messages it holds are not given to other subscribers; if
// komando stops before giving them back, Pub/Sub gives them out again
// after the subscription's ack deadline. Pulls return at once and never
// wait for new messages, so nothing is taken after peek is done.
//
// With a dead-letter topic every delivery counts, and after
// maxDeliveryAttempts Pub/Sub moves the message there, so peek stops with
// DELIVERY_LIMIT_NEAR once a message it showed has fewer than
// keepDeliveries left.
func (p *Pubsub) Peek(ctx context.Context, o queuex.PeekOptions) (*queuex.PeekResult, error) {
	switch {
	case o.Partition >= 0:
		return nil, queuex.NotSupported("--partition", "pubsub", "a Pub/Sub subscription has no partitions: drop --partition")
	case o.Oldest:
		return nil, queuex.NotSupported("--oldest", "pubsub", "Pub/Sub gives messages in no set order (in order per ordering key on a subscription with ordering), so peek shows what a pull gets: drop --oldest")
	}
	r, err := p.parseRef(o.Topic)
	if err != nil {
		return nil, err
	}
	if r.kind == "topic" {
		return nil, out.Usage("a Pub/Sub topic keeps no messages to read: peek a subscription of it (`komando queue describe CONN %s` lists them)", o.Topic)
	}
	s, err := p.getSub(ctx, r.name)
	if err != nil {
		if _, terr := p.getTopic(ctx, r.name); terr == nil {
			return nil, out.Errf(out.ExitNotFound, "SUBSCRIPTION_NOT_FOUND", "peek reads a subscription, and "+r.name+" is a topic: `komando queue describe CONN "+r.name+"` lists its subscriptions",
				"there is no subscription %s, only a topic of that name", r.name)
		}
		return nil, err
	}
	sub := subscriptionOf(s)
	if sub.Delivery != "pull" {
		return nil, queuex.NotSupported("queue peek", "a pubsub "+sub.Delivery+" subscription", "Pub/Sub delivers this subscription's messages itself, so they cannot be pulled; peek a pull subscription of the same topic")
	}
	if limit := sub.MaxDeliveryAttempts; limit > 0 && limit <= keepDeliveries {
		return nil, limitNear(r.name, 0, limit)
	}
	res := &queuex.PeekResult{Subscription: r.name, From: "pulled", Messages: []queuex.Received{}, DeliveryLimit: sub.MaxDeliveryAttempts}
	var held []string
	err = p.pullAll(ctx, r.name, o, res, &held)
	if nerr := p.giveBack(ctx, r.name, held); err == nil {
		err = nerr
	}
	if err != nil {
		return nil, err
	}
	res.Requeued = len(held) > 0
	res.Count = len(res.Messages)
	res.More = res.Count >= o.Limit // Pub/Sub does not say how many wait
	return res, nil
}

// pullAll pulls until it has o.Limit messages or pulls bring nothing new,
// keeping every ack ID it got in held (to give them back).
func (p *Pubsub) pullAll(ctx context.Context, name string, o queuex.PeekOptions, res *queuex.PeekResult, held *[]string) error {
	seen := map[string]int{}
	empty := 0
	for round := 0; len(res.Messages) < o.Limit && empty < emptyPulls && round < o.Limit/maxPerPull+10; round++ {
		in := map[string]any{"maxMessages": min(maxPerPull, o.Limit-len(res.Messages)), "returnImmediately": true}
		var got struct {
			ReceivedMessages []received `json:"receivedMessages"`
		}
		if err := p.call(ctx, http.MethodPost, p.path(ref{name: name}, "subscription")+":pull", in, &got); err != nil {
			return opErr(err, name, subNotFound)
		}
		fresh := 0
		for _, m := range got.ReceivedMessages {
			*held = append(*held, m.AckID)
			if i, ok := seen[m.Message.MessageID]; ok { // given again: its count went up
				res.Messages[i].DeliveryAttempt = m.DeliveryAttempt
				continue
			}
			seen[m.Message.MessageID] = len(res.Messages)
			res.Messages = append(res.Messages, toReceived(m, o.MaxBytes))
			fresh++
		}
		if err := nearLimit(res); err != nil {
			return err
		}
		if fresh > 0 {
			empty = 0
			continue
		}
		empty++
		select {
		case <-ctx.Done():
			return opErr(ctx.Err(), name, nil)
		case <-time.After(200 * time.Millisecond):
		}
	}
	return nil
}

// giveBack sets the ack deadline of the held messages to 0: Pub/Sub then
// delivers them again at once, as if never pulled. It runs also when the
// command's time is up, with a little time of its own.
func (p *Pubsub) giveBack(ctx context.Context, name string, held []string) error {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), p.timeout)
	defer cancel()
	for len(held) > 0 {
		n := min(len(held), 500)
		in := map[string]any{"ackIds": held[:n], "ackDeadlineSeconds": 0}
		if err := p.call(ctx, http.MethodPost, p.path(ref{name: name}, "subscription")+":modifyAckDeadline", in, nil); err != nil {
			return out.Errf(out.ExitRemote, "QUEUE_ERROR", "Pub/Sub gives the messages out again once the subscription's ack deadline has passed",
				"%s: could not give back the messages peek pulled: %v; nothing is lost", name, err)
		}
		held = held[n:]
	}
	return nil
}

func toReceived(m received, maxBytes int) queuex.Received {
	data, err := base64.StdEncoding.DecodeString(m.Message.Data)
	if err != nil {
		data = []byte(m.Message.Data)
	}
	r := queuex.Received{
		PubsubMessage: &queuex.PubsubMessage{ID: m.Message.MessageID, PublishTime: m.Message.PublishTime, OrderingKey: m.Message.OrderingKey,
			DeliveryAttempt: m.DeliveryAttempt},
		Size: len(data),
	}
	if t := r.PublishTime; t != nil {
		utc := t.UTC()
		r.PublishTime = &utc
	}
	r.Value, r.Encoding, r.ValueTruncated = queuex.Text(data, maxBytes)
	for k, v := range m.Message.Attributes {
		if r.Headers == nil {
			r.Headers = map[string]string{}
		}
		r.Headers[k], _, _ = queuex.Text([]byte(v), maxBytes)
	}
	return r
}

// nearLimit is DELIVERY_LIMIT_NEAR when a message peek showed is close to
// the deliveries after which Pub/Sub moves it to the dead-letter topic.
func nearLimit(res *queuex.PeekResult) error {
	worst := 0
	for _, m := range res.Messages {
		worst = max(worst, m.DeliveryAttempt)
	}
	if res.DeliveryLimit <= 0 || res.DeliveryLimit-worst >= keepDeliveries {
		return nil
	}
	return limitNear(res.Subscription, worst, res.DeliveryLimit)
}

func limitNear(sub string, worst, limit int) error {
	if worst == 0 {
		return out.Errf(out.ExitConflict, "DELIVERY_LIMIT_NEAR",
			"do not peek this subscription: every delivery counts, and a message delivered too often goes to the dead-letter topic. Peek a subscription of the dead-letter topic instead, or raise maxDeliveryAttempts",
			"subscription %s moves a message to its dead-letter topic after %d deliveries, and peek would count as one", sub, limit)
	}
	return out.Errf(out.ExitConflict, "DELIVERY_LIMIT_NEAR",
		"do not peek this subscription again: every delivery counts. Let its subscribers take the message, or raise maxDeliveryAttempts in its dead-letter policy if it is meant to be retried more",
		"a message in subscription %s has been delivered %d times; after %d Pub/Sub moves it to the dead-letter topic", sub, worst, limit)
}
