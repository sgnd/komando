package sqs

import (
	"context"
	"encoding/json"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/sgnd/komando/internal/out"
	"github.com/sgnd/komando/internal/queuex"
)

// Info is the region at a glance: where komando talks to, whose queues
// they are, and how many.
func (s *SQS) Info(ctx context.Context) (*queuex.Info, error) {
	urls, err := s.listQueues(ctx, "")
	if err != nil {
		return nil, err
	}
	inf := &queuex.SqsInfo{Region: s.t.Region, Endpoint: s.t.Address, AccountID: s.t.Account, Queues: len(urls)}
	if inf.AccountID == "" && len(urls) > 0 {
		inf.AccountID = accountOf(urls[0])
	}
	return &queuex.Info{Engine: "sqs", SqsInfo: inf}, nil
}

// listQueues is the URL of every queue whose name starts with prefix,
// page by page.
func (s *SQS) listQueues(ctx context.Context, prefix string) ([]string, error) {
	var urls []string
	in := map[string]any{"MaxResults": 1000}
	if prefix != "" {
		in["QueueNamePrefix"] = prefix
	}
	for {
		var res listQueuesOut
		if err := s.call(ctx, "ListQueues", in, &res); err != nil {
			return nil, opErr(err, "queues")
		}
		urls = append(urls, res.QueueUrls...)
		if res.NextToken == "" {
			return urls, nil
		}
		in["NextToken"] = res.NextToken
	}
}

// Topics lists the queues whose name matches pattern (shell style:
// orders-*), with their message counts.
func (s *SQS) Topics(ctx context.Context, pattern string, internal bool, limit int) ([]queuex.Topic, error) {
	if internal {
		return nil, queuex.NotSupported("--internal", "sqs", "SQS has no queues of its own: drop --internal")
	}
	prefix := pattern
	if i := strings.IndexAny(pattern, `*?[\`); i >= 0 {
		prefix = pattern[:i]
	}
	urls, err := s.listQueues(ctx, prefix)
	if err != nil {
		return nil, err
	}
	var matched []string
	for _, u := range urls {
		if queuex.Match(pattern, queueNameOf(u)) {
			matched = append(matched, u)
		}
	}
	// one GetQueueAttributes per queue: only for those shown
	sort.Slice(matched, func(i, j int) bool { return queueNameOf(matched[i]) < queueNameOf(matched[j]) })
	matched = queuex.First(matched, limit)
	res := make([]queuex.Topic, len(matched))
	errs := make([]error, len(matched))
	var wg sync.WaitGroup
	sem := make(chan struct{}, 8)
	for i, u := range matched {
		wg.Add(1)
		go func() {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			a, err := s.attributes(ctx, u)
			if err != nil {
				errs[i] = err
				return
			}
			q, n := queueOf(a)
			res[i] = queuex.Topic{Name: queueNameOf(u), Messages: n, SqsQueue: &q}
		}()
	}
	wg.Wait()
	kept := []queuex.Topic{}
	for i, t := range res {
		switch e, _ := errs[i].(*out.Error); {
		case errs[i] == nil:
			kept = append(kept, t)
		case e != nil && e.Code == "QUEUE_NOT_FOUND": // deleted since the list
		default:
			return nil, errs[i]
		}
	}
	sort.Slice(kept, func(i, j int) bool { return kept[i].Name < kept[j].Name })
	return kept, nil
}

// attributes are every attribute of a queue, as SQS names them.
func (s *SQS) attributes(ctx context.Context, queueURL string) (map[string]string, error) {
	var res struct {
		Attributes map[string]string `json:"Attributes"`
	}
	if err := s.call(ctx, "GetQueueAttributes", map[string]any{"QueueUrl": queueURL, "AttributeNames": []string{"All"}}, &res); err != nil {
		return nil, opErr(err, queueNameOf(queueURL))
	}
	if res.Attributes == nil {
		res.Attributes = map[string]string{}
	}
	return res.Attributes, nil
}

// queueOf is what ls shows of a queue, and the messages waiting in it.
func queueOf(a map[string]string) (queuex.SqsQueue, int64) {
	q := queuex.SqsQueue{
		Fifo:     a["FifoQueue"] == "true",
		InFlight: num64(a["ApproximateNumberOfMessagesNotVisible"]),
		Delayed:  num64(a["ApproximateNumberOfMessagesDelayed"]),
	}
	q.DeadLetterQueue, q.MaxReceiveCount = redrive(a["RedrivePolicy"])
	return q, num64(a["ApproximateNumberOfMessages"])
}

// redrive reads a RedrivePolicy: the dead-letter queue's name and the
// receives after which a message goes there.
func redrive(policy string) (string, int) {
	if policy == "" {
		return "", 0
	}
	var p struct {
		Target string          `json:"deadLetterTargetArn"`
		Max    json.RawMessage `json:"maxReceiveCount"` // a number, or a number in a string
	}
	if json.Unmarshal([]byte(policy), &p) != nil {
		return "", 0
	}
	target := p.Target[strings.LastIndex(p.Target, ":")+1:]
	return target, int(num64(strings.Trim(string(p.Max), `"`)))
}

func num64(s string) int64 {
	n, _ := strconv.ParseInt(s, 10, 64)
	return n
}

// shown are the attributes describe shows as fields of their own; the
// others are listed under attributes as SQS names them.
var shown = map[string]bool{
	"ApproximateNumberOfMessages": true, "ApproximateNumberOfMessagesNotVisible": true, "ApproximateNumberOfMessagesDelayed": true,
	"FifoQueue": true, "RedrivePolicy": true, "QueueArn": true, "VisibilityTimeout": true, "MessageRetentionPeriod": true,
	"DelaySeconds": true, "MaximumMessageSize": true, "ReceiveMessageWaitTimeSeconds": true, "ContentBasedDeduplication": true,
	"KmsMasterKeyId": true, "SqsManagedSseEnabled": true, "CreatedTimestamp": true, "LastModifiedTimestamp": true,
}

// Describe shows one queue: its counts, its settings, its dead-letter
// queue and the queues that use it as theirs, and its tags.
func (s *SQS) Describe(ctx context.Context, name string) (*queuex.TopicDetail, error) {
	u, err := s.queueURL(ctx, name)
	if err != nil {
		return nil, err
	}
	a, err := s.attributes(ctx, u)
	if err != nil {
		return nil, err
	}
	q, n := queueOf(a)
	d := &queuex.SqsQueueDetail{
		SqsQueue: q, URL: u, ARN: a["QueueArn"],
		VisibilityTimeout: int(num64(a["VisibilityTimeout"])), RetentionSeconds: int(num64(a["MessageRetentionPeriod"])),
		DelaySeconds: int(num64(a["DelaySeconds"])), MaxMessageSize: int(num64(a["MaximumMessageSize"])),
		ReceiveWait: int(num64(a["ReceiveMessageWaitTimeSeconds"])), ContentDedup: a["ContentBasedDeduplication"] == "true",
		Encryption: "none", CreatedAt: unixTime(a["CreatedTimestamp"], time.Second), ModifiedAt: unixTime(a["LastModifiedTimestamp"], time.Second),
		DeadLetterSources: []string{},
	}
	switch {
	case a["KmsMasterKeyId"] != "":
		d.Encryption = "kms:" + a["KmsMasterKeyId"]
	case a["SqsManagedSseEnabled"] == "true":
		d.Encryption = "sqs-managed"
	}
	for k, v := range a {
		if !shown[k] {
			if d.Attributes == nil {
				d.Attributes = map[string]string{}
			}
			d.Attributes[k] = v
		}
	}
	// both need a permission of their own; without it describe still works
	var src struct {
		QueueUrls  []string `json:"queueUrls"`
		QueueUrls2 []string `json:"QueueUrls"`
	}
	if s.call(ctx, "ListDeadLetterSourceQueues", map[string]any{"QueueUrl": u, "MaxResults": 1000}, &src) == nil {
		for _, su := range append(src.QueueUrls, src.QueueUrls2...) {
			d.DeadLetterSources = append(d.DeadLetterSources, queueNameOf(su))
		}
		sort.Strings(d.DeadLetterSources)
	}
	var tags struct {
		Tags map[string]string `json:"Tags"`
	}
	if s.call(ctx, "ListQueueTags", map[string]any{"QueueUrl": u}, &tags) == nil && len(tags.Tags) > 0 {
		d.Tags = tags.Tags
	}
	return &queuex.TopicDetail{Name: name, Messages: n, SqsQueueDetail: d}, nil
}

// unixTime reads a time SQS gives as a number of units since 1970.
func unixTime(s string, unit time.Duration) *time.Time {
	n := num64(s)
	if n <= 0 {
		return nil
	}
	t := time.Unix(0, n*int64(unit)).UTC()
	return &t
}
