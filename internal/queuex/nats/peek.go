package nats

import (
	"context"
	"errors"
	"sort"
	"strings"

	"github.com/nats-io/nats.go/jetstream"

	"github.com/sgnd/komando/internal/queuex"
)

// maxHoles is how many deleted messages in the middle of a stream peek
// steps around exactly; past that the newest messages may come partial.
const maxHoles = 100000

// Peek reads messages straight from the stream by their sequence number,
// the way `nats stream get` does: no consumer is made, nothing is
// acknowledged and nothing is removed, also on a work-queue stream. By
// default the newest o.Limit, with o.Oldest the first ones still kept.
func (n *Nats) Peek(ctx context.Context, o queuex.PeekOptions) (*queuex.PeekResult, error) {
	if o.Partition >= 0 {
		return nil, queuex.NotSupported("--partition", "nats", "a stream has no partitions: drop --partition")
	}
	s, err := n.stream(ctx, o.Topic)
	if err != nil {
		return nil, err
	}
	si := s.CachedInfo()
	st := si.State
	res := &queuex.PeekResult{Stream: o.Topic, From: "newest", Messages: []queuex.Received{}}
	if o.Oldest {
		res.From = "oldest"
	}
	var msgs []*jetstream.RawStreamMsg
	switch {
	case st.Msgs == 0:
	case o.Oldest:
		msgs, err = n.forward(ctx, s, st.FirstSeq, st.LastSeq, o.Limit)
	default:
		msgs, res.Partial, err = n.newest(ctx, s, st, o.Limit)
	}
	if err != nil {
		return nil, err
	}
	for _, m := range msgs {
		res.Messages = append(res.Messages, received(m, o.MaxBytes, si.Config.AllowDirect))
	}
	res.Count = len(res.Messages)
	res.More = st.Msgs > uint64(res.Count)
	return res, nil
}

// forward reads up to limit messages with a sequence in [from, to],
// oldest first. Each read asks for the first message at or after a
// sequence, so deleted ones cost nothing.
func (n *Nats) forward(ctx context.Context, s jetstream.Stream, from, to uint64, limit int) ([]*jetstream.RawStreamMsg, error) {
	var res []*jetstream.RawStreamMsg
	for seq := from; seq <= to && len(res) < limit; {
		m, err := s.GetMsg(ctx, seq, jetstream.WithGetMsgSubject(">"))
		if errors.Is(err, jetstream.ErrMsgNotFound) {
			break
		}
		if err != nil {
			return nil, n.opErr(err, s.CachedInfo().Config.Name)
		}
		if m.Sequence > to {
			break
		}
		res = append(res, m)
		seq = m.Sequence + 1
	}
	return res, nil
}

// newest reads the last limit messages. Without deleted messages in the
// middle they are the last limit sequences; with some, the stream says
// which (up to maxHoles), so peek still reads only what it shows. The
// bool says the result may miss some.
func (n *Nats) newest(ctx context.Context, s jetstream.Stream, st jetstream.StreamState, limit int) ([]*jetstream.RawStreamMsg, bool, error) {
	start := func(span uint64) uint64 {
		if st.LastSeq-st.FirstSeq+1 <= span {
			return st.FirstSeq
		}
		return st.LastSeq - span + 1
	}
	if st.NumDeleted == 0 {
		msgs, err := n.forward(ctx, s, start(uint64(limit)), st.LastSeq, limit)
		return msgs, false, err
	}
	if st.NumDeleted > maxHoles {
		msgs, err := n.forward(ctx, s, start(uint64(limit)), st.LastSeq, limit)
		return msgs, len(msgs) < limit, err
	}
	si, err := s.Info(ctx, jetstream.WithDeletedDetails(true))
	if err != nil {
		return nil, false, n.opErr(err, s.CachedInfo().Config.Name)
	}
	gone := make(map[uint64]bool, len(si.State.Deleted))
	for _, seq := range si.State.Deleted {
		gone[seq] = true
	}
	var seqs []uint64
	for seq := si.State.LastSeq; seq >= si.State.FirstSeq && seq > 0 && len(seqs) < limit; seq-- {
		if !gone[seq] {
			seqs = append(seqs, seq)
		}
	}
	sort.Slice(seqs, func(i, j int) bool { return seqs[i] < seqs[j] })
	var res []*jetstream.RawStreamMsg
	for _, seq := range seqs {
		m, err := s.GetMsg(ctx, seq)
		if errors.Is(err, jetstream.ErrMsgNotFound) { // removed since (a work queue being read)
			continue
		}
		if err != nil {
			return nil, false, n.opErr(err, si.Config.Name)
		}
		res = append(res, m)
	}
	return res, false, nil
}

// directHeaders are the headers a direct get adds to say where the
// message is; komando shows that in its own fields.
var directHeaders = map[string]bool{"Nats-Stream": true, "Nats-Sequence": true, "Nats-Time-Stamp": true, "Nats-Subject": true,
	"Nats-Num-Pending": true, "Nats-Last-Sequence": true, "Nats-Upto-Sequence": true}

func received(m *jetstream.RawStreamMsg, maxBytes int, direct bool) queuex.Received {
	r := queuex.Received{NatsMsg: &queuex.NatsMsg{Subject: m.Subject, Sequence: m.Sequence, Time: m.Time.UTC()}, Size: len(m.Data)}
	r.Value, r.Encoding, r.ValueTruncated = queuex.Text(m.Data, maxBytes)
	for k, vs := range m.Header {
		if direct && directHeaders[k] {
			continue
		}
		if r.Headers == nil {
			r.Headers = map[string]string{}
		}
		r.Headers[k], _, _ = queuex.Text([]byte(strings.Join(vs, ", ")), maxBytes)
	}
	return r
}
