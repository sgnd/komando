package nats

import (
	"encoding/json"
	"path"
	"sort"
	"strings"
	"time"

	"github.com/nats-io/nats.go/jetstream"
)

// handle answers one JetStream API request (or a publish), with f.mu held.
func (f *fakeServer) handle(subject string, hdr, data []byte) any {
	api, isAPI := strings.CutPrefix(subject, "$JS.API.")
	if !isAPI {
		return f.publish(subject, hdr, data)
	}
	verb, name, _ := strings.Cut(api, ".")
	if verb == "STREAM" || verb == "CONSUMER" {
		var rest string
		verb, rest, _ = strings.Cut(api, ".")
		sub, arg, _ := strings.Cut(rest, ".")
		verb, name = verb+"."+sub, arg
		if sub == "MSG" {
			name = strings.TrimPrefix(arg, "GET.")
		}
	}
	switch verb {
	case "INFO":
		return map[string]any{"type": "io.nats.jetstream.api.v1.account_info_response", "memory": 0, "storage": 2048, "streams": len(f.streams), "consumers": 1,
			"limits": map[string]any{"max_memory": -1, "max_storage": -1, "max_streams": -1, "max_consumers": -1}}
	case "STREAM.LIST":
		var res []*jetstream.StreamInfo
		for _, s := range f.streams {
			res = append(res, s.info(false))
		}
		sort.Slice(res, func(i, j int) bool { return res[i].Config.Name > res[j].Config.Name })
		return map[string]any{"total": len(res), "offset": 0, "limit": 256, "streams": res}
	case "STREAM.NAMES":
		var req struct{ Subject string }
		json.Unmarshal(data, &req)
		names := []string{}
		for n, s := range f.streams {
			for _, pat := range s.cfg.Subjects {
				if matches(pat, req.Subject) {
					names = append(names, n)
				}
			}
		}
		return map[string]any{"total": len(names), "offset": 0, "limit": 1024, "streams": names}
	case "STREAM.CREATE":
		var cfg jetstream.StreamConfig
		json.Unmarshal(data, &cfg)
		f.streams[cfg.Name] = &fakeStream{cfg: cfg}
		return map[string]any{"config": cfg, "created": time.Now(), "state": map[string]any{}}
	}
	parts := strings.SplitN(name, ".", 2)
	s := f.streams[parts[0]]
	if s == nil {
		return apiErr(404, 10059, "stream not found")
	}
	switch verb {
	case "STREAM.INFO":
		var req struct {
			Deleted bool `json:"deleted_details"`
		}
		json.Unmarshal(data, &req)
		return s.info(req.Deleted)
	case "STREAM.DELETE":
		delete(f.streams, parts[0])
		return map[string]any{"success": true}
	case "STREAM.PURGE":
		n := len(s.msgs)
		s.msgs = nil
		return map[string]any{"success": true, "purged": n}
	case "STREAM.MSG":
		return s.get(data)
	case "CONSUMER.LIST":
		return map[string]any{"total": len(s.consumers), "offset": 0, "limit": 256, "consumers": s.consumers}
	case "CONSUMER.INFO":
		for _, c := range s.consumers {
			if len(parts) == 2 && c.Name == parts[1] {
				return c
			}
		}
		return apiErr(404, 10014, "consumer not found")
	}
	return apiErr(400, 10003, "unknown request "+subject)
}

// matches says whether a NATS subject pattern (orders.*, orders.>) takes
// subject.
func matches(pat, subject string) bool {
	if p, ok := strings.CutSuffix(pat, ">"); ok {
		return strings.HasPrefix(subject, p) && len(subject) > len(p)
	}
	ok, _ := path.Match(strings.ReplaceAll(pat, ".", "/"), strings.ReplaceAll(subject, ".", "/"))
	return ok
}

func (f *fakeServer) publish(subject string, hdr, data []byte) any {
	for name, s := range f.streams {
		for _, pat := range s.cfg.Subjects {
			if matches(pat, subject) {
				s.lastSeq++
				s.msgs = append(s.msgs, fakeMsg{seq: s.lastSeq, subject: subject, hdr: hdr, data: data, at: time.Now()})
				return map[string]any{"stream": name, "seq": s.lastSeq}
			}
		}
	}
	return nil // no responders: nats.go times out or says so
}

func (s *fakeStream) info(deleted bool) *jetstream.StreamInfo {
	si := &jetstream.StreamInfo{Config: s.cfg, Created: time.Unix(1700000000, 0)}
	si.State.Consumers = len(s.consumers)
	si.State.LastSeq = s.lastSeq
	si.State.NumDeleted = len(s.deleted)
	if deleted {
		si.State.Deleted = s.deleted
	}
	for i, m := range s.msgs {
		if i == 0 {
			si.State.FirstSeq, si.State.FirstTime = m.seq, m.at
		}
		si.State.Msgs++
		si.State.Bytes += uint64(len(m.data))
		si.State.LastTime = m.at
	}
	if len(s.msgs) == 0 {
		si.State.FirstSeq = s.lastSeq + 1
	}
	return si
}

func (s *fakeStream) get(data []byte) any {
	var req struct {
		Seq  uint64 `json:"seq"`
		Next string `json:"next_by_subj"`
	}
	json.Unmarshal(data, &req)
	for _, m := range s.msgs {
		if m.seq == req.Seq || (req.Next != "" && m.seq > req.Seq) {
			return map[string]any{"message": map[string]any{"subject": m.subject, "seq": m.seq, "data": m.data, "hdrs": m.hdr, "time": m.at}}
		}
	}
	return apiErr(404, 10037, "no message found")
}
