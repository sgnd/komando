package sqs

import (
	"context"
	"time"

	"github.com/sgnd/komando/internal/out"
	"github.com/sgnd/komando/internal/queuex"
)

// keepReceives is how many receives peek leaves a message of a queue with
// a dead-letter queue for its real consumers: below that it stops.
const keepReceives = 3

// maxPerReceive is the most messages SQS gives in one ReceiveMessage.
const maxPerReceive = 10

type sqsMessage struct {
	MessageID         string            `json:"MessageId"`
	Body              string            `json:"Body"`
	Attributes        map[string]string `json:"Attributes"`
	MessageAttributes map[string]struct {
		DataType    string `json:"DataType"`
		StringValue string `json:"StringValue"`
		BinaryValue string `json:"BinaryValue"` // base64
	} `json:"MessageAttributes"`
}

// Peek receives up to o.Limit messages with a visibility timeout of 0 and
// never deletes them: SQS keeps every message, and consumers can receive
// them again at once (nothing is hidden from them). SQS gives messages in
// no set order (a FIFO queue: in order within a message group), so peek
// shows a sample of what is waiting, not the newest or the oldest.
//
// Every receive counts: SQS raises the message's receive count, and a
// queue with a dead-letter queue moves a message there after
// maxReceiveCount receives. So peek refuses a queue whose limit is too low
// to spare one, and stops with DELIVERY_LIMIT_NEAR once a message it showed
// has fewer than keepReceives receives left.
func (s *SQS) Peek(ctx context.Context, o queuex.PeekOptions) (*queuex.PeekResult, error) {
	switch {
	case o.Partition >= 0:
		return nil, queuex.NotSupported("--partition", "sqs", "an SQS queue has no partitions: drop --partition")
	case o.Oldest:
		return nil, queuex.NotSupported("--oldest", "sqs", "SQS gives messages in no set order (a FIFO queue: in order within each message group), so peek shows a sample of the waiting messages: drop --oldest")
	}
	u, err := s.queueURL(ctx, o.Topic)
	if err != nil {
		return nil, err
	}
	a, err := s.attributes(ctx, u)
	if err != nil {
		return nil, err
	}
	_, limit := redrive(a["RedrivePolicy"])
	if limit > 0 && limit <= keepReceives {
		return nil, out.Errf(out.ExitConflict, "DELIVERY_LIMIT_NEAR",
			"do not peek this queue: every receive counts, and a message received too often goes to the dead-letter queue. Peek the dead-letter queue instead, or raise maxReceiveCount in the queue's RedrivePolicy",
			"queue %s moves a message to its dead-letter queue after %d receives, and peek would count as one", o.Topic, limit)
	}
	waiting := num64(a["ApproximateNumberOfMessages"])
	res := &queuex.PeekResult{Queue: o.Topic, From: "sample", Messages: []queuex.Received{}, DeliveryLimit: limit}
	seen := map[string]int{}
	for round := 0; len(res.Messages) < o.Limit && round < o.Limit/maxPerReceive+5; round++ {
		msgs, err := s.receive(ctx, u, min(maxPerReceive, o.Limit-len(res.Messages)))
		if err != nil {
			return nil, err
		}
		fresh := 0
		for _, m := range msgs {
			r := received(m, o.MaxBytes)
			if i, ok := seen[m.MessageID]; ok {
				res.Messages[i].ReceiveCount = r.ReceiveCount // received again: its count went up
				continue
			}
			seen[m.MessageID] = len(res.Messages)
			res.Messages = append(res.Messages, r)
			fresh++
		}
		if err := nearLimit(res, limit); err != nil {
			return nil, err
		}
		// no new one, or every message SQS counted: more rounds would only
		// receive the same ones again and raise their counts
		if fresh == 0 || int64(len(res.Messages)) >= waiting {
			break
		}
	}
	res.Count = len(res.Messages)
	res.More = waiting > int64(res.Count)
	res.Partial = res.Count < o.Limit && res.More
	return res, nil
}

// receive is one ReceiveMessage that hides nothing (visibility timeout 0)
// and waits up to a second for messages (long polling asks every SQS
// server, so a queue with few messages still answers with them).
func (s *SQS) receive(ctx context.Context, queueURL string, n int) ([]sqsMessage, error) {
	in := map[string]any{
		"QueueUrl": queueURL, "MaxNumberOfMessages": n, "VisibilityTimeout": 0, "WaitTimeSeconds": 1,
		"MessageSystemAttributeNames": []string{"All"}, "AttributeNames": []string{"All"}, "MessageAttributeNames": []string{"All"},
	}
	var res struct {
		Messages []sqsMessage `json:"Messages"`
	}
	if err := s.call(ctx, "ReceiveMessage", in, &res); err != nil {
		return nil, opErr(err, queueNameOf(queueURL))
	}
	return res.Messages, nil
}

func received(m sqsMessage, maxBytes int) queuex.Received {
	a := m.Attributes
	r := queuex.Received{
		SqsMessage: &queuex.SqsMessage{
			MessageID: m.MessageID, SentAt: unixTime(a["SentTimestamp"], time.Millisecond), ReceiveCount: int(num64(a["ApproximateReceiveCount"])),
			FirstReceivedAt: unixTime(a["ApproximateFirstReceiveTimestamp"], time.Millisecond), MessageGroupID: a["MessageGroupId"],
			SequenceNumber: a["SequenceNumber"], DeduplicationID: a["MessageDeduplicationId"],
		},
		Size: len(m.Body),
	}
	r.Value, r.Encoding, r.ValueTruncated = queuex.Text([]byte(m.Body), maxBytes)
	for k, v := range m.MessageAttributes {
		if v.DataType == "" {
			// not a message attribute: SQS always gives the type, but moto
			// lists the system attributes here, empty, on a message with none
			continue
		}
		if r.Headers == nil {
			r.Headers = map[string]string{}
		}
		val := v.StringValue
		if v.BinaryValue != "" {
			val = "base64:" + v.BinaryValue
		}
		if maxBytes > 0 && len(val) > maxBytes {
			val = val[:maxBytes]
		}
		r.Headers[k] = val
	}
	return r
}

// nearLimit is DELIVERY_LIMIT_NEAR when a message peek showed is close to
// the receives after which SQS moves it to the dead-letter queue.
func nearLimit(res *queuex.PeekResult, limit int) error {
	worst := 0
	for _, m := range res.Messages {
		worst = max(worst, m.ReceiveCount)
	}
	if limit <= 0 || limit-worst >= keepReceives {
		return nil
	}
	return out.Errf(out.ExitConflict, "DELIVERY_LIMIT_NEAR",
		"do not peek this queue again: every receive counts. Let its consumers take the message, or raise maxReceiveCount in the queue's RedrivePolicy if it is meant to be retried more",
		"a message in queue %s has been received %d times; after %d SQS moves it to the dead-letter queue", res.Queue, worst, limit)
}
