package rabbitmq

import (
	"context"
	"errors"
	"strconv"
	"strings"
	"time"

	amqp "github.com/rabbitmq/amqp091-go"

	"github.com/sgnd/komando/internal/out"
	"github.com/sgnd/komando/internal/queuex"
)

// Peek takes up to o.Limit messages from the front of the queue with
// basic.get, without acknowledging them, and gives them all back (nack
// with requeue): nothing is removed. RabbitMQ then marks them redelivered,
// and while peek holds them (a moment) no consumer gets them. If the
// connection drops in between, RabbitMQ puts them back by itself.
//
// A quorum queue counts every return as a delivery (x-delivery-count) and
// drops or dead-letters a message after its delivery limit (20 by default
// since RabbitMQ 4.0). So peek stops with DELIVERY_LIMIT_NEAR once a
// message it showed has fewer than keepDeliveries deliveries left.
func (r *Rabbit) Peek(ctx context.Context, o queuex.PeekOptions) (*queuex.PeekResult, error) {
	if o.Partition >= 0 {
		return nil, queuex.NotSupported("--partition", "rabbitmq", "a RabbitMQ queue has no partitions: drop --partition")
	}
	q, err := r.declared(ctx, o.Topic)
	if err != nil {
		return nil, err
	}
	quorum, limit, err := r.deliveryLimit(ctx, o.Topic)
	if err != nil {
		return nil, err
	}
	res := &queuex.PeekResult{Queue: o.Topic, From: "front", Messages: []queuex.Received{}}
	err = r.do(ctx, o.Topic, func(ch *amqp.Channel) error {
		var last uint64
		defer func() {
			if last > 0 { // every message taken goes back, even after an error
				_ = ch.Nack(last, true, true)
				res.Requeued = true
			}
		}()
		for len(res.Messages) < o.Limit {
			d, ok, err := ch.Get(o.Topic, false)
			if err != nil {
				return streamErr(err)
			}
			if !ok {
				return nil
			}
			last = d.DeliveryTag
			m := delivery(d, o.MaxBytes, quorum)
			res.Messages = append(res.Messages, m)
			if limit > 0 && limit-m.Deliveries < keepDeliveries {
				// giving this one back counts as a delivery: take no more,
				// so no other message near its limit is put at risk too
				return nil
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	res.Count = len(res.Messages)
	res.More = int64(q.Messages) > int64(res.Count)
	return res, nearLimit(res, limit)
}

// keepDeliveries is how many deliveries peek leaves a message of a quorum
// queue for its real consumers: below that it refuses to go on.
const keepDeliveries = 3

// nearLimit is DELIVERY_LIMIT_NEAR when a message peek showed (and gave
// back) is close to its queue's delivery limit, or went over it.
func nearLimit(res *queuex.PeekResult, limit int64) error {
	var worst *queuex.Received
	for i, m := range res.Messages {
		if limit > 0 && m.Deliveries > 0 && (worst == nil || m.Deliveries > worst.Deliveries) {
			worst = &res.Messages[i]
			res.DeliveryLimit = int(limit)
		}
	}
	if worst == nil || limit-worst.Deliveries >= keepDeliveries {
		return nil
	}
	left := limit - worst.Deliveries
	what := "has " + strconv.FormatInt(left, 10) + " deliveries left"
	if left < 0 {
		what = "went over it, so RabbitMQ dropped it (or dead-lettered it) when peek gave it back"
	}
	return out.Errf(out.ExitConflict, "DELIVERY_LIMIT_NEAR",
		"do not peek this queue again: every peek counts as a delivery. Let its consumers take the message, move it with a dead-letter policy, or raise the queue's delivery-limit (a policy) if it is meant to be retried more",
		"a message in quorum queue %s has been delivered %d times; the queue's delivery limit is %d and the message %s", res.Queue, worst.Deliveries, limit, what)
}

// deliveryLimit says whether the queue is a quorum queue and after how
// many deliveries it drops a message (0: never). Only the management API
// knows a queue's type and its own limit (x-delivery-limit or a policy):
// AMQP shows neither, and a quorum queue may drop a message after its
// first return. So without the management API, or when it fails, peek
// refuses before it takes a message.
func (r *Rabbit) deliveryLimit(ctx context.Context, name string) (bool, int64, error) {
	if r.t.Management == "" {
		return false, 0, queuex.NotSupported("queue peek without the management API", "rabbitmq",
			"every peek counts as a delivery on a quorum queue, and only the management API tells the queue's type and delivery limit: add its port to the conn's URL (`komando conn edit NAME --url 'amqp://...?management=15672'`), or read the messages with the queue's own consumer")
	}
	var q mgmtQueue
	if err := r.mgmt(ctx, r.vhostPath("queues", name), name, &q); err != nil {
		var oe *out.Error
		if errors.As(err, &oe) {
			return false, 0, out.Errf(oe.Exit, oe.Code,
				"peek reads the queue's type and delivery limit from the management API before it takes a message, so it stops here: fix what the message says (the ?management= port, the user's management tag or its vhost permission) and peek again",
				"%s", oe.Message)
		}
		return false, 0, err
	}
	switch q.Type {
	case "stream": // basic.get there would end the whole connection
		return false, 0, streamErr(&amqp.Error{Code: amqp.NotImplemented})
	case "quorum":
	default:
		return false, 0, nil
	}
	policy, _ := q.EffectivePolicy.(map[string]any) // [] when there is none
	for _, v := range []any{q.Arguments["x-delivery-limit"], policy["delivery-limit"]} {
		if n, ok := number(v); ok {
			return true, max(n, 0), nil // -1: no limit
		}
	}
	if major, _, _ := strings.Cut(str(r.conn.Properties["version"]), "."); atoi(major) >= 4 {
		return true, 20, nil // RabbitMQ 4.0 and later
	}
	return true, 0, nil
}

// streamErr: a stream queue refuses basic.get.
func streamErr(err error) error {
	var ae *amqp.Error
	if errors.As(err, &ae) && (ae.Code == amqp.NotImplemented || strings.Contains(strings.ToLower(ae.Reason), "stream")) {
		return queuex.NotSupported("queue peek on a stream queue", "rabbitmq",
			"a stream queue is read by consumers that give an offset, not by basic.get; peek works on classic and quorum queues")
	}
	return err
}

func delivery(d amqp.Delivery, maxBytes int, quorum bool) queuex.Received {
	m := queuex.Received{RabbitDelivery: &queuex.RabbitDelivery{Redelivered: d.Redelivered, Exchange: d.Exchange, RoutingKey: d.RoutingKey}, Size: len(d.Body)}
	if n, ok := number(d.Headers["x-delivery-count"]); ok || quorum {
		m.Deliveries = n + 1 // this peek's return counts too
	}
	m.Value, m.Encoding, m.ValueTruncated = queuex.Text(d.Body, maxBytes)
	m.Headers = table(d.Headers, maxBytes)
	props := map[string]string{}
	for k, v := range map[string]string{"content_type": d.ContentType, "content_encoding": d.ContentEncoding, "correlation_id": d.CorrelationId,
		"reply_to": d.ReplyTo, "expiration": d.Expiration, "message_id": d.MessageId, "type": d.Type, "user_id": d.UserId, "app_id": d.AppId} {
		if v != "" {
			props[k] = v
		}
	}
	if !d.Timestamp.IsZero() {
		props["timestamp"] = d.Timestamp.UTC().Format(time.RFC3339)
	}
	if d.DeliveryMode == amqp.Persistent {
		props["delivery_mode"] = "persistent"
	}
	if d.Priority > 0 {
		props["priority"] = strconv.Itoa(int(d.Priority))
	}
	if len(props) > 0 {
		m.Properties = props
	}
	return m
}

func atoi(s string) int {
	n, _ := strconv.Atoi(s)
	return n
}

// number is an AMQP or JSON number as an int64.
func number(v any) (int64, bool) {
	switch n := v.(type) {
	case int8:
		return int64(n), true
	case int16:
		return int64(n), true
	case int32:
		return int64(n), true
	case int64:
		return n, true
	case int:
		return int64(n), true
	case uint8:
		return int64(n), true
	case uint16:
		return int64(n), true
	case uint32:
		return int64(n), true
	case float64:
		return int64(n), true
	}
	return 0, false
}
