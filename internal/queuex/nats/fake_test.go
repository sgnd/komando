package nats

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/nats-io/nats.go/jetstream"
)

// fakeServer speaks just enough of the NATS client protocol and the
// JetStream API for the unit tests: streams with messages and consumers,
// kept in memory. Live tests (TestNatsLive) use a real server.
type fakeServer struct {
	ln      net.Listener
	mu      sync.Mutex
	streams map[string]*fakeStream
	user    string // "" takes any login
	pass    string
	noJS    bool   // answer the JetStream API with "not enabled"
	deny    string // an API subject prefix the user may not use
}

type fakeStream struct {
	cfg       jetstream.StreamConfig
	msgs      []fakeMsg
	deleted   []uint64
	consumers []*jetstream.ConsumerInfo
	lastSeq   uint64
}

type fakeMsg struct {
	seq     uint64
	subject string
	hdr     []byte
	data    []byte
	at      time.Time
}

// newFake starts a fake server; set changes its settings before it runs.
func newFake(t *testing.T, set ...func(*fakeServer)) *fakeServer {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	f := &fakeServer{ln: ln, streams: map[string]*fakeStream{}}
	for _, s := range set {
		s(f)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go f.serve(c)
		}
	}()
	return f
}

func (f *fakeServer) addr() string { return f.ln.Addr().String() }

// add makes a stream with messages on subject SUBJ.N for every body.
func (f *fakeServer) add(cfg jetstream.StreamConfig, bodies ...string) *fakeStream {
	f.mu.Lock()
	defer f.mu.Unlock()
	s := &fakeStream{cfg: cfg}
	for _, b := range bodies {
		s.lastSeq++
		s.msgs = append(s.msgs, fakeMsg{seq: s.lastSeq, subject: strings.TrimSuffix(cfg.Subjects[0], ">") + "x", data: []byte(b), at: time.Unix(1700000000+int64(s.lastSeq), 0)})
	}
	f.streams[cfg.Name] = s
	return s
}

type fakeConn struct {
	f    *fakeServer
	w    *bufio.Writer
	mu   sync.Mutex
	subs map[string]string // sid -> subject
}

func (f *fakeServer) serve(c net.Conn) {
	defer c.Close()
	fc := &fakeConn{f: f, w: bufio.NewWriter(c), subs: map[string]string{}}
	info := map[string]any{"server_id": "NFAKE", "server_name": "fake-1", "version": "2.12.1", "proto": 1, "headers": true, "max_payload": 1048576,
		"jetstream": !f.noJS, "auth_required": f.user != "", "cluster": "lab"}
	b, _ := json.Marshal(info)
	fc.send("INFO " + string(b) + "\r\n")
	r := bufio.NewReader(c)
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			return
		}
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		switch strings.ToUpper(fields[0]) {
		case "CONNECT":
			var cn struct{ User, Pass string }
			json.Unmarshal([]byte(strings.TrimPrefix(strings.TrimSpace(line), fields[0])), &cn)
			if f.user != "" && (cn.User != f.user || cn.Pass != f.pass) {
				fc.send("-ERR 'Authorization Violation'\r\n")
				return
			}
		case "PING":
			fc.send("PONG\r\n")
		case "SUB":
			fc.mu.Lock()
			fc.subs[fields[len(fields)-1]] = fields[1]
			fc.mu.Unlock()
		case "PUB", "HPUB":
			n, _ := strconv.Atoi(fields[len(fields)-1])
			body := make([]byte, n+2)
			if _, err := io.ReadFull(r, body); err != nil {
				return
			}
			var hdr []byte
			reply := ""
			if fields[0] == "HPUB" {
				h, _ := strconv.Atoi(fields[len(fields)-2])
				hdr, body = body[:h], body[h:]
				if len(fields) == 5 {
					reply = fields[2]
				}
			} else if len(fields) == 4 {
				reply = fields[2]
			}
			go fc.answer(fields[1], reply, hdr, body[:len(body)-2])
		}
	}
}

func (fc *fakeConn) send(s string) {
	fc.mu.Lock()
	defer fc.mu.Unlock()
	fc.w.WriteString(s)
	fc.w.Flush()
}

// reply sends v as JSON to the subscription that covers subject.
func (fc *fakeConn) reply(subject string, v any) {
	b, _ := json.Marshal(v)
	fc.mu.Lock()
	sid := ""
	for id, pat := range fc.subs {
		if pat == subject || (strings.HasSuffix(pat, ".*") && strings.HasPrefix(subject, strings.TrimSuffix(pat, "*"))) {
			sid = id
		}
	}
	fc.mu.Unlock()
	if sid != "" {
		fc.send(fmt.Sprintf("MSG %s %s %d\r\n%s\r\n", subject, sid, len(b), b))
	}
}

func apiErr(code, errCode int, desc string) map[string]any {
	return map[string]any{"error": map[string]any{"code": code, "err_code": errCode, "description": desc}}
}

// answer is the server's answer to a message published to subject.
func (fc *fakeConn) answer(subject, reply string, hdr, data []byte) {
	f := fc.f
	if reply == "" {
		return
	}
	switch {
	case f.deny != "" && strings.HasPrefix(subject, f.deny):
		fc.send(fmt.Sprintf("-ERR 'Permissions Violation for Publish to \"%s\"'\r\n", subject))
		return
	case f.noJS && strings.HasPrefix(subject, "$JS.API."):
		fc.reply(reply, apiErr(503, 10039, "jetstream not enabled for account"))
		return
	}
	f.mu.Lock()
	v := f.handle(subject, hdr, data)
	f.mu.Unlock()
	if v != nil {
		fc.reply(reply, v)
	}
}
