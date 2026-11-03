package cloud

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

// fakeAgent plays the SSM agent's side of a port session: handshake, then
// it sends back each input upper-cased, and counts the acks it gets.
func fakeAgent(t *testing.T, kms bool) (string, *atomic.Int32) {
	t.Helper()
	var acks atomic.Int32
	up := websocket.Upgrader{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ws, err := up.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer ws.Close()
		_, open, _ := ws.ReadMessage()
		var o map[string]string
		if json.Unmarshal(open, &o) != nil || o["TokenValue"] != "tok" {
			return
		}
		seq := int64(0)
		out := func(payType uint32, p []byte) {
			ws.WriteMessage(websocket.BinaryMessage, encodeSSM(ssmMsg{typ: ssmOutput, seq: seq, payType: payType, payload: p}))
			seq++
		}
		actions := `[{"ActionType":"SessionType","ActionParameters":{"SessionType":"Port"}}]`
		if kms {
			actions = `[{"ActionType":"KMSEncryption"}]`
		}
		out(payHandReq, []byte(`{"AgentVersion":"3.3","RequestedClientActions":`+actions+`}`))
		for {
			_, b, err := ws.ReadMessage()
			if err != nil {
				return
			}
			m, err := decodeSSM(b)
			if err != nil {
				t.Errorf("client message: %v", err)
				return
			}
			switch {
			case m.typ == ssmAck:
				acks.Add(1)
			case m.payType == payHandResp:
				if !bytes.Contains(m.payload, []byte(`"ActionStatus":1`)) {
					t.Errorf("handshake response %s", m.payload)
				}
				out(payHandDone, []byte(`{}`))
			case m.payType == payOutput:
				out(payOutput, bytes.ToUpper(m.payload))
			}
		}
	}))
	t.Cleanup(srv.Close)
	return "ws" + strings.TrimPrefix(srv.URL, "http"), &acks
}

func TestSSMSession(t *testing.T) {
	url, acks := fakeAgent(t, false)
	saved := ssmStart
	defer func() { ssmStart = saved }()
	ssmStart = func(ctx context.Context, profile, region, target, port string) (string, string, error) {
		if target != "i-0abc" || port != "22" {
			t.Errorf("target %s port %s", target, port)
		}
		return url, "tok", nil
	}
	c, err := SSMDial(context.Background(), "", "", "i-0abc", "22")
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.Write([]byte("ssh-2.0-hello"))
	buf := make([]byte, 64)
	c.(*ssmConn).ws.SetReadDeadline(time.Now().Add(5 * time.Second))
	n, err := io.ReadAtLeast(c, buf, len("SSH-2.0-HELLO"))
	if err != nil || string(buf[:n]) != "SSH-2.0-HELLO" {
		t.Fatalf("echo %q %v", buf[:n], err)
	}
	time.Sleep(100 * time.Millisecond)
	if acks.Load() < 3 { // handshake request, handshake complete, the data
		t.Errorf("acked %d output messages", acks.Load())
	}
}

func TestSSMRefusesKMS(t *testing.T) {
	url, _ := fakeAgent(t, true)
	saved := ssmStart
	defer func() { ssmStart = saved }()
	ssmStart = func(context.Context, string, string, string, string) (string, string, error) { return url, "tok", nil }
	if _, err := SSMDial(context.Background(), "", "", "i-0abc", "22"); err == nil || !strings.Contains(err.Error(), "KMS") {
		t.Errorf("KMS session: %v", err)
	}
}

func TestSSMMessageFormat(t *testing.T) {
	m := ssmMsg{typ: ssmInput, seq: 7, flags: 0, payType: payOutput, payload: []byte("abc")}
	b := encodeSSM(m)
	if len(b) != 123 || string(bytes.TrimRight(b[4:36], " ")) != ssmInput {
		t.Fatalf("encoded %d bytes, type %q", len(b), b[4:36])
	}
	got, err := decodeSSM(b)
	if err != nil || got.seq != 7 || string(got.payload) != "abc" || got.payType != payOutput {
		t.Errorf("%+v %v", got, err)
	}
	b[len(b)-1] = 'x'
	if _, err := decodeSSM(b); err == nil {
		t.Error("a changed payload must fail its digest")
	}
}
