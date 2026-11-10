package pubsub

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
)

// fakePubsub is an in-process Pub/Sub that speaks the REST API (v1), for
// the unit tests. It keeps topics, subscriptions and messages in memory
// and records what komando asked.
type fakePubsub struct {
	mu       sync.Mutex
	topics   map[string]map[string]any // by short name
	subs     map[string]*fakeSub
	calls    []string // "METHOD path", in order
	fail     map[string]int
	pageSize int // list calls: items per page (0: all)
	auth     []string
	seq      int
	token    string // what /token gives (a service account login)
}

type fakeSub struct {
	body  map[string]any
	msgs  []*fakeMsg
	acks  map[string]*fakeMsg // ack ID -> message held by a pull
	nacks int
}

type fakeMsg struct {
	id, data, key string
	attrs         map[string]string
	deliveries    int
	held          bool
}

const fakeProject = "test-project"

func newFake(t *testing.T, tls bool) (*fakePubsub, *httptest.Server) {
	t.Helper()
	f := &fakePubsub{topics: map[string]map[string]any{}, subs: map[string]*fakeSub{}, fail: map[string]int{}, token: "tok-1"}
	if !tls {
		srv := httptest.NewServer(http.HandlerFunc(f.serve))
		t.Cleanup(srv.Close)
		return f, srv
	}
	srv := httptest.NewTLSServer(http.HandlerFunc(f.serve))
	t.Cleanup(srv.Close)
	testTLS = srv.Client().Transport.(*http.Transport).TLSClientConfig
	t.Cleanup(func() { testTLS = nil })
	return f, srv
}

func (f *fakePubsub) addTopic(name string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.topics[name] = map[string]any{"name": "projects/" + fakeProject + "/topics/" + name}
}

func (f *fakePubsub) addSub(name, topic string, extra map[string]any, bodies ...string) *fakeSub {
	f.mu.Lock()
	defer f.mu.Unlock()
	b := map[string]any{"name": "projects/" + fakeProject + "/subscriptions/" + name, "topic": "projects/" + fakeProject + "/topics/" + topic,
		"ackDeadlineSeconds": 10, "messageRetentionDuration": "604800s", "pushConfig": map[string]any{}}
	for k, v := range extra {
		b[k] = v
	}
	s := &fakeSub{body: b, acks: map[string]*fakeMsg{}}
	for _, d := range bodies {
		f.seq++
		s.msgs = append(s.msgs, &fakeMsg{id: strconv.Itoa(f.seq), data: base64.StdEncoding.EncodeToString([]byte(d))})
	}
	f.subs[name] = s
	return s
}

func (f *fakePubsub) count(prefix string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	n := 0
	for _, c := range f.calls {
		if strings.HasPrefix(c, prefix) {
			n++
		}
	}
	return n
}

func reply(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func apiErr(w http.ResponseWriter, status int, word, msg string) {
	reply(w, status, map[string]any{"error": map[string]any{"code": status, "status": word, "message": msg}})
}

func (f *fakePubsub) serve(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if r.URL.Path == "/token" {
		reply(w, 200, map[string]any{"access_token": f.token, "token_type": "Bearer", "expires_in": 3600})
		return
	}
	f.calls = append(f.calls, r.Method+" "+r.URL.Path)
	f.auth = append(f.auth, r.Header.Get("Authorization"))
	for k, status := range f.fail {
		if strings.Contains(r.Method+" "+r.URL.Path, k) {
			apiErr(w, status, map[int]string{401: "UNAUTHENTICATED", 403: "PERMISSION_DENIED", 429: "RESOURCE_EXHAUSTED", 400: "INVALID_ARGUMENT", 500: "INTERNAL"}[status], "injected")
			return
		}
	}
	rest, ok := strings.CutPrefix(r.URL.Path, "/v1/projects/"+fakeProject+"/")
	if !ok {
		apiErr(w, 404, "NOT_FOUND", "Requested project not found")
		return
	}
	var in map[string]any
	_ = json.NewDecoder(r.Body).Decode(&in)
	kind, name, _ := strings.Cut(rest, "/")
	name, verb, _ := strings.Cut(name, ":")
	switch {
	case name == "":
		f.list(w, r, kind)
	case kind == "topics":
		f.topic(w, r.Method, name, verb, in)
	case kind == "subscriptions":
		f.sub(w, r.Method, name, verb, in)
	default:
		apiErr(w, 404, "NOT_FOUND", "no such path")
	}
}

func (f *fakePubsub) list(w http.ResponseWriter, r *http.Request, kind string) {
	var names []string
	src := map[string]bool{}
	for n := range f.topics {
		src[n] = kind == "topics"
	}
	for n := range f.subs {
		src[n+"\x00"] = kind == "subscriptions"
	}
	for n, ok := range src {
		if ok {
			names = append(names, strings.TrimSuffix(n, "\x00"))
		}
	}
	sort.Strings(names)
	start, _ := strconv.Atoi(r.URL.Query().Get("pageToken"))
	end := len(names)
	if f.pageSize > 0 && start+f.pageSize < end {
		end = start + f.pageSize
	}
	items := []any{}
	for _, n := range names[start:end] {
		if kind == "topics" {
			items = append(items, f.topics[n])
		} else {
			items = append(items, f.subs[n].body)
		}
	}
	res := map[string]any{kind: items}
	if end < len(names) {
		res["nextPageToken"] = strconv.Itoa(end)
	}
	reply(w, 200, res)
}

func (f *fakePubsub) topic(w http.ResponseWriter, method, name, verb string, in map[string]any) {
	t, there := f.topics[name]
	switch {
	case method == "PUT" && there:
		apiErr(w, 409, "ALREADY_EXISTS", "Topic already exists")
	case method == "PUT":
		in["name"] = "projects/" + fakeProject + "/topics/" + name
		f.topics[name] = in
		reply(w, 200, in)
	case !there:
		apiErr(w, 404, "NOT_FOUND", "Topic not found")
	case method == "GET":
		reply(w, 200, t)
	case method == "DELETE":
		delete(f.topics, name)
		for _, s := range f.subs {
			if s.body["topic"] == t["name"] {
				s.body["topic"] = "_deleted-topic_"
			}
		}
		reply(w, 200, map[string]any{})
	case verb == "publish":
		var ids []string
		for _, m := range in["messages"].([]any) {
			mm := m.(map[string]any)
			f.seq++
			id := strconv.Itoa(f.seq)
			ids = append(ids, id)
			attrs := map[string]string{}
			if a, ok := mm["attributes"].(map[string]any); ok {
				for k, v := range a {
					attrs[k] = fmt.Sprint(v)
				}
			}
			key, _ := mm["orderingKey"].(string)
			for _, s := range f.subs {
				if s.body["topic"] == t["name"] {
					s.msgs = append(s.msgs, &fakeMsg{id: id, data: mm["data"].(string), key: key, attrs: attrs})
				}
			}
		}
		reply(w, 200, map[string]any{"messageIds": ids})
	}
}

func (f *fakePubsub) sub(w http.ResponseWriter, method, name, verb string, in map[string]any) {
	s, there := f.subs[name]
	switch {
	case method == "PUT" && there:
		apiErr(w, 409, "ALREADY_EXISTS", "Subscription already exists")
	case method == "PUT":
		in["name"] = "projects/" + fakeProject + "/subscriptions/" + name
		f.subs[name] = &fakeSub{body: in, acks: map[string]*fakeMsg{}}
		reply(w, 200, in)
	case !there:
		apiErr(w, 404, "NOT_FOUND", "Subscription does not exist")
	case method == "GET":
		reply(w, 200, s.body)
	case method == "DELETE":
		delete(f.subs, name)
		reply(w, 200, map[string]any{})
	case verb == "pull":
		f.pull(w, s, int(in["maxMessages"].(float64)))
	case verb == "modifyAckDeadline":
		for _, id := range in["ackIds"].([]any) {
			if m := s.acks[id.(string)]; m != nil {
				m.held = false
				delete(s.acks, id.(string))
				s.nacks++
			}
		}
		reply(w, 200, map[string]any{})
	case verb == "seek":
		s.msgs, s.acks = nil, map[string]*fakeMsg{}
		reply(w, 200, map[string]any{})
	}
}

func (f *fakePubsub) pull(w http.ResponseWriter, s *fakeSub, n int) {
	got := []any{}
	for _, m := range s.msgs {
		if len(got) == n || m.held {
			continue
		}
		m.held = true
		m.deliveries++
		f.seq++
		ack := "ack-" + strconv.Itoa(f.seq)
		s.acks[ack] = m
		rm := map[string]any{"ackId": ack, "message": map[string]any{"data": m.data, "messageId": m.id, "attributes": m.attrs,
			"publishTime": "2026-11-10T08:00:00.5Z", "orderingKey": m.key}}
		if s.body["deadLetterPolicy"] != nil {
			rm["deliveryAttempt"] = m.deliveries
		}
		got = append(got, rm)
	}
	reply(w, 200, map[string]any{"receivedMessages": got})
}
