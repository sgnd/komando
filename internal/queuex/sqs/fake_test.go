package sqs

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeSQS is an in-process SQS that speaks the JSON API (AmazonSQS.*), for
// the unit tests. It keeps queues and messages in memory and records what
// komando asked.
type fakeSQS struct {
	mu       sync.Mutex
	queues   map[string]*fakeQueue
	calls    []string       // every action, in order
	last     map[string]any // the body of the last call of each action, by action
	fail     map[string]string
	pageSize int // ListQueues: queues per page (0: all)
	auth     []string
	seq      int
}

type fakeQueue struct {
	attrs map[string]string
	tags  map[string]string
	msgs  []*fakeMsg
}

type fakeMsg struct {
	id, body, group, dedup string
	attrs                  map[string]any
	received               int
	sent                   time.Time
}

const fakeAccount = "123456789012"

func newFake(t *testing.T) (*fakeSQS, *httptest.Server) {
	t.Helper()
	f := &fakeSQS{queues: map[string]*fakeQueue{}, last: map[string]any{}, fail: map[string]string{}}
	srv := httptest.NewServer(http.HandlerFunc(f.serve))
	t.Cleanup(srv.Close)
	return f, srv
}

func (f *fakeSQS) add(name string, attrs map[string]string, bodies ...string) *fakeQueue {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.addLocked(name, attrs, bodies...)
}

func (f *fakeSQS) addLocked(name string, attrs map[string]string, bodies ...string) *fakeQueue {
	q := &fakeQueue{attrs: map[string]string{"QueueArn": "arn:aws:sqs:us-east-1:" + fakeAccount + ":" + name, "VisibilityTimeout": "30",
		"MessageRetentionPeriod": "345600", "DelaySeconds": "0", "MaximumMessageSize": "262144", "ReceiveMessageWaitTimeSeconds": "0",
		"CreatedTimestamp": "1700000000", "LastModifiedTimestamp": "1700000100"}}
	if strings.HasSuffix(name, ".fifo") {
		q.attrs["FifoQueue"] = "true"
	}
	for k, v := range attrs {
		q.attrs[k] = v
	}
	for _, b := range bodies {
		f.seq++
		q.msgs = append(q.msgs, &fakeMsg{id: "m" + strconv.Itoa(f.seq), body: b, sent: time.UnixMilli(1700000000000)})
	}
	f.queues[name] = q
	return q
}

func (f *fakeSQS) count(action string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	n := 0
	for _, c := range f.calls {
		if c == action {
			n++
		}
	}
	return n
}

func queueURLOf(name string) string { return "http://fake.local/" + fakeAccount + "/" + name }

func (f *fakeSQS) serve(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	action := strings.TrimPrefix(r.Header.Get("X-Amz-Target"), "AmazonSQS.")
	f.calls = append(f.calls, action)
	f.auth = append(f.auth, r.Header.Get("Authorization"))
	var in map[string]any
	body, _ := io.ReadAll(r.Body)
	_ = json.Unmarshal(body, &in)
	f.last[action] = in
	if r.Header.Get("Content-Type") != "application/x-amz-json-1.0" || !strings.HasPrefix(r.Header.Get("Authorization"), "AWS4-HMAC-SHA256 ") {
		fakeErr(w, 400, "MissingAuthenticationToken", "no signature")
		return
	}
	if code := f.fail[action]; code != "" {
		fakeErr(w, map[bool]int{true: 403, false: 400}[strings.Contains(code, "Token") || strings.Contains(code, "Denied")], code, "the fake says no")
		return
	}
	res, code := f.do(action, in)
	if code != "" {
		fakeErr(w, 400, code, "fake: "+code)
		return
	}
	w.Header().Set("Content-Type", "application/x-amz-json-1.0")
	_ = json.NewEncoder(w).Encode(res)
}

func fakeErr(w http.ResponseWriter, status int, code, msg string) {
	w.Header().Set("Content-Type", "application/x-amz-json-1.0")
	w.WriteHeader(status)
	fmt.Fprintf(w, `{"__type":"com.amazonaws.sqs#%s","message":%q}`, code, msg)
}

func str(in map[string]any, k string) string { s, _ := in[k].(string); return s }

func (f *fakeSQS) byURL(in map[string]any) (string, *fakeQueue) {
	name := queueNameOf(str(in, "QueueUrl"))
	return name, f.queues[name]
}

func (f *fakeSQS) do(action string, in map[string]any) (any, string) {
	switch action {
	case "ListQueues":
		return f.list(in), ""
	case "GetQueueUrl":
		if f.queues[str(in, "QueueName")] == nil {
			return nil, "QueueDoesNotExist"
		}
		return map[string]string{"QueueUrl": queueURLOf(str(in, "QueueName"))}, ""
	case "CreateQueue":
		attrs := map[string]string{}
		given, _ := in["Attributes"].(map[string]any)
		for k, v := range given {
			attrs[k] = v.(string)
		}
		f.addLocked(str(in, "QueueName"), attrs)
		return map[string]string{"QueueUrl": queueURLOf(str(in, "QueueName"))}, ""
	}
	name, q := f.byURL(in)
	if q == nil {
		return nil, "QueueDoesNotExist"
	}
	switch action {
	case "GetQueueAttributes":
		return map[string]any{"Attributes": q.attributes()}, ""
	case "ListDeadLetterSourceQueues":
		var urls []string
		for n, o := range f.queues {
			if strings.Contains(o.attrs["RedrivePolicy"], ":"+name+`"`) {
				urls = append(urls, queueURLOf(n))
			}
		}
		return map[string]any{"queueUrls": urls}, ""
	case "ListQueueTags":
		return map[string]any{"Tags": q.tags}, ""
	case "ReceiveMessage":
		return map[string]any{"Messages": q.receive(int(in["MaxNumberOfMessages"].(float64)))}, ""
	case "SendMessage":
		f.seq++
		m := &fakeMsg{id: "m" + strconv.Itoa(f.seq), body: str(in, "MessageBody"), group: str(in, "MessageGroupId"), dedup: str(in, "MessageDeduplicationId"), sent: time.Now()}
		m.attrs, _ = in["MessageAttributes"].(map[string]any)
		q.msgs = append(q.msgs, m)
		res := map[string]string{"MessageId": m.id}
		if m.group != "" {
			res["SequenceNumber"] = "1000" + strconv.Itoa(f.seq)
		}
		return res, ""
	case "DeleteQueue":
		delete(f.queues, name)
		return map[string]any{}, ""
	case "PurgeQueue":
		q.msgs = nil
		return map[string]any{}, ""
	}
	return nil, "InvalidAction"
}

func (f *fakeSQS) list(in map[string]any) map[string]any {
	var names []string
	for n := range f.queues {
		if strings.HasPrefix(n, str(in, "QueueNamePrefix")) {
			names = append(names, n)
		}
	}
	sort.Strings(names)
	start, _ := strconv.Atoi(str(in, "NextToken"))
	end := len(names)
	if f.pageSize > 0 && start+f.pageSize < end {
		end = start + f.pageSize
	}
	if mr, ok := in["MaxResults"].(float64); ok && start+int(mr) < end {
		end = start + int(mr)
	}
	res := map[string]any{}
	var urls []string
	for _, n := range names[start:end] {
		urls = append(urls, queueURLOf(n))
	}
	if len(urls) > 0 {
		res["QueueUrls"] = urls
	}
	if end < len(names) {
		res["NextToken"] = strconv.Itoa(end)
	}
	return res
}

func (q *fakeQueue) attributes() map[string]string {
	a := map[string]string{}
	for k, v := range q.attrs {
		a[k] = v
	}
	a["ApproximateNumberOfMessages"] = strconv.Itoa(len(q.msgs))
	a["ApproximateNumberOfMessagesNotVisible"] = "0"
	a["ApproximateNumberOfMessagesDelayed"] = "0"
	return a
}

// receive gives the first n messages and keeps them all (the visibility
// timeout komando asks for is 0); each one's receive count goes up.
func (q *fakeQueue) receive(n int) []map[string]any {
	var res []map[string]any
	for _, m := range q.msgs {
		if len(res) == n {
			break
		}
		m.received++
		attrs := map[string]string{"SentTimestamp": strconv.FormatInt(m.sent.UnixMilli(), 10), "ApproximateReceiveCount": strconv.Itoa(m.received),
			"ApproximateFirstReceiveTimestamp": "1700000001000"}
		if m.group != "" {
			attrs["MessageGroupId"], attrs["MessageDeduplicationId"], attrs["SequenceNumber"] = m.group, m.dedup, "1"
		}
		msg := map[string]any{"MessageId": m.id, "ReceiptHandle": "rh-" + m.id, "Body": m.body, "Attributes": attrs}
		if m.attrs != nil {
			msg["MessageAttributes"] = m.attrs
		}
		res = append(res, msg)
	}
	return res
}
