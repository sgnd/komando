package sqs

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"sort"
	"strings"
	"unicode/utf8"

	"github.com/sgnd/komando/internal/out"
	"github.com/sgnd/komando/internal/queuex"
)

// Send sends one message to a queue. Headers become string message
// attributes. A FIFO queue needs --key, the message group: messages of one
// group are received in order. Its deduplication ID is the body's hash
// when the queue says so (ContentBasedDeduplication), otherwise a new
// random one, so sending the same text twice gives two messages.
func (s *SQS) Send(ctx context.Context, m queuex.Message, dryRun bool) (*queuex.Sent, error) {
	if m.Partition >= 0 {
		return nil, queuex.NotSupported("--partition", "sqs", "an SQS queue has no partitions: drop --partition (a FIFO queue keeps order per --key, the message group)")
	}
	if !validBody(m.Value) {
		return nil, out.Usage("SQS takes text only (UTF-8, no control characters other than tab and newlines): encode binary data, for example as base64, before sending it")
	}
	u, err := s.queueURL(ctx, m.Topic)
	if err != nil {
		return nil, err
	}
	a, err := s.attributes(ctx, u)
	if err != nil {
		return nil, err
	}
	fifo := a["FifoQueue"] == "true"
	switch {
	case fifo && m.Key == nil:
		return nil, out.Usage("queue %s is a FIFO queue: give the message group with --key (messages of one group are received in order)", m.Topic)
	case !fifo && m.Key != nil:
		return nil, queuex.NotSupported("--key", "a standard sqs queue", "only a FIFO queue (a name ending in .fifo) has message groups: drop --key, or put what it should say in a --header")
	}
	if limit := num64(a["MaximumMessageSize"]); limit > 0 && int64(len(m.Value)) > limit {
		return nil, out.Usage("the message is %d bytes; queue %s takes up to %d (MaximumMessageSize): put bigger data in storage and send its name", len(m.Value), m.Topic, limit)
	}
	res := &queuex.Sent{Queue: m.Topic, Size: len(m.Value), DryRun: dryRun, SqsSent: &queuex.SqsSent{}}
	if fifo {
		res.MessageGroupID = string(m.Key)
	}
	if dryRun {
		return res, nil
	}
	in := map[string]any{"QueueUrl": u, "MessageBody": string(m.Value)}
	if len(m.Headers) > 0 {
		attrs := map[string]any{}
		for _, h := range m.Headers {
			attrs[h[0]] = map[string]string{"DataType": "String", "StringValue": h[1]}
		}
		in["MessageAttributes"] = attrs
	}
	if fifo {
		in["MessageGroupId"] = string(m.Key)
		if a["ContentBasedDeduplication"] != "true" {
			in["MessageDeduplicationId"] = randomID()
		}
	}
	var sent struct {
		MessageID      string `json:"MessageId"`
		SequenceNumber string `json:"SequenceNumber"`
	}
	if err := s.call(ctx, "SendMessage", in, &sent); err != nil {
		return nil, opErr(err, m.Topic)
	}
	res.MessageID, res.SequenceNumber = &sent.MessageID, sent.SequenceNumber
	return res, nil
}

// validBody says whether SQS takes b as a message body: Unicode text
// without control characters other than tab, newline and carriage return.
func validBody(b []byte) bool {
	if !utf8.Valid(b) {
		return false
	}
	for _, r := range string(b) {
		if r < 0x20 && r != '\t' && r != '\n' && r != '\r' || r == 0xFFFE || r == 0xFFFF {
			return false
		}
	}
	return true
}

func randomID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// createAttributes are the queue settings `queue create --config` takes,
// as SQS names them (the case does not matter).
var createAttributes = []string{
	"DelaySeconds", "MaximumMessageSize", "MessageRetentionPeriod", "Policy", "ReceiveMessageWaitTimeSeconds", "VisibilityTimeout",
	"RedrivePolicy", "RedriveAllowPolicy", "KmsMasterKeyId", "KmsDataKeyReusePeriodSeconds", "SqsManagedSseEnabled",
	"FifoQueue", "ContentBasedDeduplication", "DeduplicationScope", "FifoThroughputLimit",
}

// fifoOnly are the settings only a FIFO queue has.
var fifoOnly = map[string]bool{"ContentBasedDeduplication": true, "DeduplicationScope": true, "FifoThroughputLimit": true}

// Create makes a queue: a FIFO queue when its name ends in .fifo. SQS
// would answer a second create with the same settings by giving the
// queue that is there, so komando checks first and says QUEUE_EXISTS. A
// dry run checks the name and the settings komando knows, and makes
// nothing: SQS cannot check a queue without making it.
func (s *SQS) Create(ctx context.Context, sp queuex.TopicSpec, dryRun bool) (*queuex.Created, error) {
	switch {
	case sp.Partitions != -1 || sp.Replicas != -1:
		return nil, queuex.NotSupported("--partitions and --replicas", "sqs", "an SQS queue has no partitions, and AWS keeps its copies itself: drop them")
	case sp.Type != "":
		return nil, queuex.NotSupported("--type", "sqs", "a name ending in .fifo makes a FIFO queue; any other name a standard one")
	}
	if err := checkName(sp.Topic); err != nil {
		return nil, err
	}
	fifo := strings.HasSuffix(sp.Topic, ".fifo")
	attrs, err := queueAttributes(sp.Config, fifo)
	if err != nil {
		return nil, err
	}
	if _, err := s.queueURL(ctx, sp.Topic); err == nil {
		return nil, queueExists(sp.Topic)
	} else if e, ok := err.(*out.Error); !ok || e.Code != "QUEUE_NOT_FOUND" {
		return nil, err
	}
	res := &queuex.Created{Queue: sp.Topic, SqsCreated: &queuex.SqsCreated{Fifo: fifo}, DryRun: dryRun}
	if len(attrs) > 0 {
		res.Attributes = attrs
	}
	if dryRun {
		return res, nil
	}
	in := map[string]any{"QueueName": sp.Topic}
	if len(attrs) > 0 {
		in["Attributes"] = attrs
	}
	var created struct {
		QueueURL string `json:"QueueUrl"`
	}
	if err := s.call(ctx, "CreateQueue", in, &created); err != nil {
		return nil, opErr(err, sp.Topic)
	}
	res.URL = created.QueueURL
	return res, nil
}

// queueAttributes are the --config settings with SQS's names, and
// FifoQueue=true for a FIFO queue.
func queueAttributes(cfg map[string]string, fifo bool) (map[string]string, error) {
	attrs := map[string]string{}
	for k, v := range cfg {
		name := ""
		for _, a := range createAttributes {
			if strings.EqualFold(k, a) {
				name = a
			}
		}
		switch {
		case name == "":
			return nil, out.Usage("unknown SQS queue setting %q (known: %s)", k, strings.Join(createAttributes, ", "))
		case fifoOnly[name] && !fifo:
			return nil, out.Usage("%s is for FIFO queues only: give the queue a name ending in .fifo", name)
		}
		attrs[name] = v
	}
	if v, ok := attrs["FifoQueue"]; ok && (v == "true") != fifo {
		return nil, out.Usage("FifoQueue follows the name: a FIFO queue's name ends in .fifo; drop --config FifoQueue")
	}
	if fifo {
		attrs["FifoQueue"] = "true"
	} else {
		delete(attrs, "FifoQueue")
	}
	return attrs, nil
}

// Delete deletes queues and every message in them. Every name must exist;
// with dry run it only says what each holds. SQS takes up to 60 seconds
// to finish a delete, and only then can a queue of the same name be made.
func (s *SQS) Delete(ctx context.Context, queues []string, dryRun bool) ([]queuex.Deleted, error) {
	res := []queuex.Deleted{}
	urls := map[string]string{}
	for _, name := range queues {
		d := queuex.Deleted{Queue: name}
		u, err := s.queueURL(ctx, name)
		switch e, _ := err.(*out.Error); {
		case err == nil:
			a, err := s.attributes(ctx, u)
			if err != nil {
				return nil, err
			}
			d.Exists, urls[name] = true, u
			d.Messages = num64(a["ApproximateNumberOfMessages"]) + num64(a["ApproximateNumberOfMessagesNotVisible"]) + num64(a["ApproximateNumberOfMessagesDelayed"])
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
	for _, d := range res {
		if err := s.call(ctx, "DeleteQueue", map[string]any{"QueueUrl": urls[d.Queue]}, nil); err != nil {
			return nil, opErr(err, d.Queue)
		}
	}
	return res, nil
}

// Purge deletes every message in a queue, also those a consumer received
// and has not deleted yet (in flight), and keeps the queue. SQS allows one
// purge per queue every 60 seconds and may take that long to finish.
func (s *SQS) Purge(ctx context.Context, queue string, dryRun bool) (*queuex.Purged, error) {
	u, err := s.queueURL(ctx, queue)
	if err != nil {
		return nil, err
	}
	a, err := s.attributes(ctx, u)
	if err != nil {
		return nil, err
	}
	inFlight := num64(a["ApproximateNumberOfMessagesNotVisible"])
	res := &queuex.Purged{Queue: queue, Messages: num64(a["ApproximateNumberOfMessages"]) + num64(a["ApproximateNumberOfMessagesDelayed"]),
		InFlight: &inFlight, DryRun: dryRun}
	if dryRun {
		return res, nil
	}
	if err := s.call(ctx, "PurgeQueue", map[string]any{"QueueUrl": u}, nil); err != nil {
		return nil, opErr(err, queue)
	}
	return res, nil
}
