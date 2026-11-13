package rabbitmq

import (
	"context"
	"sort"
	"strconv"
	"time"

	amqp "github.com/rabbitmq/amqp091-go"

	"github.com/sgnd/komando/internal/out"
	"github.com/sgnd/komando/internal/queuex"
)

// Send publishes one message to a queue through the default exchange (the
// routing key is the queue's name) and waits for the server's confirm.
// The message is persistent, so a durable queue keeps it over a restart.
func (r *Rabbit) Send(ctx context.Context, m queuex.Message, dryRun bool) (*queuex.Sent, error) {
	switch {
	case m.Key != nil:
		return nil, queuex.NotSupported("--key", "rabbitmq", "a message to a RabbitMQ queue has no key: drop --key (put what it should say in a --header)")
	case m.Partition >= 0:
		return nil, queuex.NotSupported("--partition", "rabbitmq", "a RabbitMQ queue has no partitions: drop --partition")
	}
	if _, err := r.declared(ctx, m.Topic); err != nil {
		return nil, err
	}
	res := &queuex.Sent{Queue: m.Topic, Size: len(m.Value), DryRun: dryRun}
	if dryRun {
		return res, nil
	}
	msg := amqp.Publishing{Body: m.Value, DeliveryMode: amqp.Persistent, Timestamp: time.Now().UTC().Truncate(time.Second)}
	for _, h := range m.Headers {
		if msg.Headers == nil {
			msg.Headers = amqp.Table{}
		}
		msg.Headers[h[0]] = h[1]
	}
	err := r.do(ctx, m.Topic, func(ch *amqp.Channel) error {
		if err := ch.Confirm(false); err != nil {
			return err
		}
		returned := ch.NotifyReturn(make(chan amqp.Return, 1))
		dc, err := ch.PublishWithDeferredConfirmWithContext(ctx, "", m.Topic, true, false, msg)
		if err != nil {
			return err
		}
		acked, err := dc.WaitContext(ctx)
		switch {
		case err != nil:
			return err
		case !acked:
			return out.Errf(out.ExitRemote, "QUEUE_ERROR", "the server could not keep the message (a full queue with overflow=reject-publish, or a disk or memory alarm): `komando queue describe CONN "+m.Topic+"`",
				"the server refused the message for %s", m.Topic)
		}
		select {
		case <-returned: // the queue went away after the check
			return queueNotFound(m.Topic)
		case <-time.After(50 * time.Millisecond):
			return nil
		}
	})
	if err != nil {
		return nil, err
	}
	return res, nil
}

// queueTypes are the queue types `queue create --type` takes.
var queueTypes = map[string]bool{"classic": true, "quorum": true, "stream": true}

// Create declares a durable queue. RabbitMQ would answer a second declare
// of the same queue with "ok", so komando checks first and says
// QUEUE_EXISTS. A dry run checks the name and the settings komando knows,
// and makes nothing: RabbitMQ cannot check a queue without making it.
func (r *Rabbit) Create(ctx context.Context, s queuex.TopicSpec, dryRun bool) (*queuex.Created, error) {
	if s.Partitions != -1 || s.Replicas != -1 {
		return nil, queuex.NotSupported("--partitions and --replicas", "rabbitmq", "a RabbitMQ queue has no partitions; for copies on several nodes use --type quorum")
	}
	if s.Type != "" && !queueTypes[s.Type] {
		return nil, out.Usage("--type takes classic, quorum or stream, not %q", s.Type)
	}
	args := amqp.Table{}
	for k, v := range s.Config {
		args[k] = argument(v)
	}
	if s.Type != "" {
		args["x-queue-type"] = s.Type
	}
	if t, ok := args["x-queue-type"].(string); ok { // also when --config gave it
		s.Type = t
	}
	if _, err := r.declared(ctx, s.Topic); err == nil {
		return nil, out.Errf(out.ExitConflict, "QUEUE_EXISTS", "pick another name, or see it with `komando queue describe CONN "+s.Topic+"`", "queue %s already exists", s.Topic)
	} else if e, ok := err.(*out.Error); !ok || e.Code != "QUEUE_NOT_FOUND" {
		return nil, err
	}
	res := &queuex.Created{Queue: s.Topic, RabbitCreated: &queuex.RabbitCreated{Type: s.Type, Durable: true, Vhost: r.t.Database}, DryRun: dryRun}
	if len(args) > 0 {
		res.Arguments = map[string]any(args)
	}
	if dryRun {
		return res, nil
	}
	err := r.do(ctx, s.Topic, func(ch *amqp.Channel) error {
		_, err := ch.QueueDeclare(s.Topic, true, false, false, false, args)
		return err
	})
	if err != nil {
		return nil, err
	}
	return res, nil
}

// argument is a --config value as RabbitMQ wants it: x-max-length=1000 is
// a number, x-single-active-consumer=true a boolean, the rest text.
func argument(v string) any {
	if n, err := strconv.ParseInt(v, 10, 64); err == nil {
		return n
	}
	if b, err := strconv.ParseBool(v); err == nil && (v == "true" || v == "false") {
		return b
	}
	return v
}

// Delete deletes queues and the messages in them; their consumers are
// cancelled. Every name must exist; with dry run it only says what each
// holds.
func (r *Rabbit) Delete(ctx context.Context, queues []string, dryRun bool) ([]queuex.Deleted, error) {
	res := []queuex.Deleted{}
	for _, name := range queues {
		d := queuex.Deleted{Queue: name}
		q, err := r.declared(ctx, name)
		switch e, _ := err.(*out.Error); {
		case err == nil:
			consumers := q.Consumers
			d.Exists, d.Messages, d.Consumers = true, int64(q.Messages), &consumers
		case e == nil || e.Code != "QUEUE_NOT_FOUND":
			return nil, err
		}
		res = append(res, d)
	}
	sort.Slice(res, func(i, j int) bool { return res[i].Queue < res[j].Queue })
	if dryRun {
		return res, nil
	}
	for _, d := range res {
		if !d.Exists {
			return nil, queueNotFound(d.Queue)
		}
	}
	for i, d := range res {
		err := r.do(ctx, d.Queue, func(ch *amqp.Channel) error {
			n, err := ch.QueueDelete(d.Queue, false, false, false)
			res[i].Messages = int64(n)
			return err
		})
		if err != nil {
			return nil, err
		}
	}
	return res, nil
}

// Purge deletes the messages waiting in a queue (ready) and keeps the
// queue. Messages a consumer holds and has not acknowledged stay.
func (r *Rabbit) Purge(ctx context.Context, queue string, dryRun bool) (*queuex.Purged, error) {
	q, err := r.declared(ctx, queue)
	if err != nil {
		return nil, err
	}
	res := &queuex.Purged{Queue: queue, Messages: int64(q.Messages), DryRun: dryRun}
	if dryRun {
		return res, nil
	}
	err = r.do(ctx, queue, func(ch *amqp.Channel) error {
		n, err := ch.QueuePurge(queue, false)
		res.Messages = int64(n)
		return err
	})
	if err != nil {
		return nil, err
	}
	return res, nil
}
