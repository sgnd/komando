package cloud

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

// floodAgent does the handshake, then calls send with a function that
// writes one output message. It records the sequence numbers the client
// acknowledges and returns them once the client has acked seq last.
func floodAgent(t *testing.T, last int64, send func(out func(seq int64, payType uint32, p []byte))) func() map[int64]bool {
	t.Helper()
	var mu sync.Mutex
	acked := map[int64]bool{}
	done := make(chan struct{})
	up := websocket.Upgrader{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ws, err := up.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer ws.Close()
		if _, _, err := ws.ReadMessage(); err != nil { // the open message
			return
		}
		gone := make(chan struct{})
		go func() {
			defer close(gone)
			for {
				_, b, err := ws.ReadMessage()
				if err != nil {
					return
				}
				m, err := decodeSSM(b)
				if err != nil || m.typ != ssmAck {
					continue
				}
				var a struct{ AcknowledgedMessageSequenceNumber int64 }
				json.Unmarshal(m.payload, &a)
				mu.Lock()
				acked[a.AcknowledgedMessageSequenceNumber] = true
				if a.AcknowledgedMessageSequenceNumber == last {
					close(done)
				}
				mu.Unlock()
			}
		}()
		out := func(seq int64, payType uint32, p []byte) {
			ws.WriteMessage(websocket.BinaryMessage, encodeSSM(ssmMsg{typ: ssmOutput, seq: seq, payType: payType, payload: p}))
		}
		out(0, payHandDone, []byte(`{}`))
		send(out)
		select {
		case <-done:
			time.Sleep(100 * time.Millisecond)
		case <-gone:
		case <-time.After(20 * time.Second):
		}
	}))
	t.Cleanup(srv.Close)
	saved := ssmStart
	t.Cleanup(func() { ssmStart = saved })
	ssmStart = func(context.Context, string, string, string, string) (ssmSession, error) {
		return ssmSession{id: "s", url: "ws" + strings.TrimPrefix(srv.URL, "http"), token: "tok"}, nil
	}
	return func() map[int64]bool {
		select {
		case <-done:
		case <-time.After(20 * time.Second):
			t.Fatalf("the client never acked seq %d", last)
		}
		mu.Lock()
		defer mu.Unlock()
		return acked
	}
}

// Messages that come early are kept only within a window of sequence
// numbers and bytes; the rest are not acked (the agent sends them again),
// so a broken or hostile agent cannot fill memory. What is kept comes out
// in order.
func TestSSMOutOfOrderIsBounded(t *testing.T) {
	big := bytes.Repeat([]byte("x"), 64<<10)
	acks := floodAgent(t, 1, func(out func(int64, uint32, []byte)) {
		out(2, payOutput, []byte("B"))
		for s := int64(10_000); s < 10_100; s++ { // far ahead
			out(s, payOutput, big)
		}
		for s := int64(3); s < 103; s++ { // 6.4 MiB just ahead
			out(s, payOutput, big)
		}
		out(1, payOutput, []byte("A"))
	})
	c, err := SSMDial(context.Background(), "", "", "i-0abc", "22")
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	got := make([]byte, 2)
	if _, err := io.ReadFull(c, got); err != nil || string(got) != "AB" {
		t.Fatalf("read %q %v", got, err)
	}
	acked := acks()
	kept := 0
	for s := range acked {
		switch {
		case s >= 10_000:
			t.Errorf("acked seq %d, far ahead of the stream", s)
		case s >= 3:
			kept++
		}
	}
	if kept == 0 || kept*len(big) > ssmMaxBuffered {
		t.Errorf("kept %d messages of 64 KiB early (cap %d bytes)", kept, ssmMaxBuffered)
	}
	if !acked[2] {
		t.Error("seq 2 (early, small) not acked")
	}
}

// One websocket message larger than the read limit ends the session.
func TestSSMReadLimit(t *testing.T) {
	floodAgent(t, -1, func(out func(int64, uint32, []byte)) {
		out(1, payOutput, bytes.Repeat([]byte("x"), ssmReadLimit+1))
	})
	c, err := SSMDial(context.Background(), "", "", "i-0abc", "22")
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	done := make(chan error, 1)
	go func() {
		_, err := io.ReadAll(c)
		done <- err
	}()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("the session went on after a message over the limit")
	}
}
