package queuex

import (
	"context"
	"encoding/base64"
	"sort"
	"time"
	"unicode/utf8"

	"github.com/twmb/franz-go/pkg/kgo"
)

// PeekOptions say which messages `queue peek` reads.
type PeekOptions struct {
	Topic     string
	Limit     int   // how many messages, over all partitions
	Oldest    bool  // the first ones still kept, not the newest
	Partition int32 // -1: every partition
	MaxBytes  int   // a longer key or value is cut (0: no limit)
	Wait      time.Duration
}

// PeekResult is what `queue peek` read.
type PeekResult struct {
	Topic    string     `json:"topic"`
	From     string     `json:"from"` // newest | oldest
	Messages []Received `json:"messages"`
	Count    int        `json:"count"`
	More     bool       `json:"more"` // the topic holds more than these
	Partial  bool       `json:"partial,omitempty"`
}

// Received is one message read from a partition.
type Received struct {
	Partition      int32             `json:"partition"`
	Offset         int64             `json:"offset"`
	Timestamp      time.Time         `json:"timestamp"`
	Key            *string           `json:"key"` // null: no key
	Value          string            `json:"value"`
	Encoding       string            `json:"encoding,omitempty"` // base64 when the value is not UTF-8 text
	Size           int               `json:"size"`               // the value's size in bytes
	ValueTruncated bool              `json:"value_truncated,omitempty"`
	Headers        map[string]string `json:"headers,omitempty"`
}

// window is the part of one partition that peek reads: [from, to).
type window struct{ from, to int64 }

// Peek reads messages directly from the partitions: no consumer group, no
// committed offset, nothing removed, so no application notices.
func (k *Kafka) Peek(ctx context.Context, o PeekOptions) (*PeekResult, error) {
	td, err := k.topic(ctx, o.Topic)
	if err != nil {
		return nil, err
	}
	if o.Partition >= 0 {
		if _, ok := td.Partitions[o.Partition]; !ok {
			return nil, partitionNotFound(o.Topic, o.Partition, len(td.Partitions))
		}
	}
	starts, ends, err := k.offsets(ctx, o.Topic)
	if err != nil {
		return nil, err
	}
	res := &PeekResult{Topic: o.Topic, From: "newest", Messages: []Received{}}
	if o.Oldest {
		res.From = "oldest"
	}
	wins := map[int32]window{}
	var total int64
	for p := range td.Partitions {
		if o.Partition >= 0 && p != o.Partition {
			continue
		}
		s, _ := starts.Lookup(o.Topic, p)
		e, _ := ends.Lookup(o.Topic, p)
		if s.Err != nil || e.Err != nil || e.Offset <= s.Offset {
			continue
		}
		total += e.Offset - s.Offset
		w := window{from: s.Offset, to: e.Offset}
		if o.Oldest {
			w.to = min(e.Offset, s.Offset+int64(o.Limit))
		} else {
			w.from = max(s.Offset, e.Offset-int64(o.Limit))
		}
		wins[p] = w
	}
	if len(wins) > 0 {
		recs, partial, err := k.read(ctx, o.Topic, wins, o.Wait)
		if err != nil {
			return nil, err
		}
		res.Partial = partial
		res.Messages = pick(recs, o, res.Messages)
	}
	res.Count = len(res.Messages)
	res.More = total > int64(res.Count)
	return res, nil
}

// read consumes each partition's window. It stops when every window is
// read, or when nothing came for wait (a window can have holes: compacted
// or transaction markers), and then says the result may be partial.
func (k *Kafka) read(ctx context.Context, topic string, wins map[int32]window, wait time.Duration) ([]*kgo.Record, bool, error) {
	at := map[int32]kgo.Offset{}
	for p, w := range wins {
		at[p] = kgo.NewOffset().At(w.from)
	}
	cl, err := k.client(kgo.ConsumePartitions(map[string]map[int32]kgo.Offset{topic: at}), kgo.FetchMaxWait(500*time.Millisecond))
	if err != nil {
		return nil, false, err
	}
	defer cl.Close()
	if wait <= 0 {
		wait = 5 * time.Second
	}
	left := len(wins)
	done := map[int32]bool{}
	var recs []*kgo.Record
	for left > 0 {
		pctx, cancel := context.WithTimeout(ctx, wait)
		fs := cl.PollFetches(pctx)
		timedOut := pctx.Err() != nil
		cancel()
		if timedOut {
			return recs, true, nil
		}
		var ferr error
		fs.EachError(func(_ string, _ int32, err error) {
			if err != context.DeadlineExceeded && ferr == nil {
				ferr = err
			}
		})
		if ferr != nil {
			return nil, false, opErr(ferr, topic)
		}
		fs.EachRecord(func(r *kgo.Record) {
			w := wins[r.Partition]
			if done[r.Partition] || r.Offset < w.from || r.Offset >= w.to {
				return
			}
			recs = append(recs, r)
			if r.Offset == w.to-1 {
				done[r.Partition] = true
				left--
			}
		})
	}
	return recs, false, nil
}

// pick keeps o.Limit of the records, the newest or the oldest over all
// partitions by time, in the order they were written.
func pick(recs []*kgo.Record, o PeekOptions, res []Received) []Received {
	sort.SliceStable(recs, func(i, j int) bool {
		a, b := recs[i], recs[j]
		if !a.Timestamp.Equal(b.Timestamp) {
			return a.Timestamp.Before(b.Timestamp)
		}
		if a.Partition != b.Partition {
			return a.Partition < b.Partition
		}
		return a.Offset < b.Offset
	})
	if len(recs) > o.Limit {
		if o.Oldest {
			recs = recs[:o.Limit]
		} else {
			recs = recs[len(recs)-o.Limit:]
		}
	}
	for _, r := range recs {
		res = append(res, received(r, o.MaxBytes))
	}
	return res
}

func received(r *kgo.Record, maxBytes int) Received {
	m := Received{Partition: r.Partition, Offset: r.Offset, Timestamp: r.Timestamp.UTC(), Size: len(r.Value)}
	if r.Key != nil {
		k, _, _ := text(r.Key, maxBytes)
		m.Key = &k
	}
	m.Value, m.Encoding, m.ValueTruncated = text(r.Value, maxBytes)
	for _, h := range r.Headers {
		if m.Headers == nil {
			m.Headers = map[string]string{}
		}
		m.Headers[h.Key], _, _ = text(h.Value, maxBytes)
	}
	return m
}

// text shows bytes as text when they are UTF-8, otherwise as base64; cut
// to maxBytes first (a rune cut in half at the end is dropped).
func text(b []byte, maxBytes int) (string, string, bool) {
	cut := maxBytes > 0 && len(b) > maxBytes
	if cut {
		b = b[:maxBytes]
	}
	if utf8.Valid(b) {
		return string(b), "", cut
	}
	for i := 1; cut && i < utf8.UTFMax && i < len(b); i++ {
		if head, tail := b[:len(b)-i], b[len(b)-i:]; utf8.Valid(head) && !utf8.FullRune(tail) {
			return string(head), "", cut
		}
	}
	return base64.StdEncoding.EncodeToString(b), "base64", cut
}
