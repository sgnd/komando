package cloud

import (
	"bytes"
	"context"
	"crypto/cipher"
	"crypto/rand"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/gorilla/websocket"
)

// fakeAgent plays the SSM agent's side of a port session: handshake, then
// it sends back each input upper-cased, and counts the acks it gets. With
// kms it asks for KMS encryption and expects the sealed key fakeKMS hands
// out; then every data payload both ways is encrypted.
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
		_, first, _ := ws.ReadMessage()
		var o map[string]string
		if json.Unmarshal(first, &o) != nil || o["TokenValue"] != "tok" {
			return
		}
		seq := int64(0)
		var open, seal cipher.AEAD
		out := func(payType uint32, p []byte) {
			if seal != nil && payType == payOutput {
				nonce := make([]byte, 12)
				rand.Read(nonce)
				p = seal.Seal(nonce, nonce, p, nil)
			}
			ws.WriteMessage(websocket.BinaryMessage, encodeSSM(ssmMsg{typ: ssmOutput, seq: seq, payType: payType, payload: p}))
			seq++
		}
		actions := `[{"ActionType":"SessionType","ActionParameters":{"SessionType":"Port"}}]`
		if kms {
			actions = `[{"ActionType":"KMSEncryption","ActionParameters":{"KMSKeyId":"alias/ssm"}},{"ActionType":"SessionType","ActionParameters":{"SessionType":"Port"}}]`
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
				var resp struct {
					ProcessedClientActions []struct {
						ActionType   string
						ActionStatus int
						ActionResult struct{ KMSCipherTextKey []byte }
					}
				}
				json.Unmarshal(m.payload, &resp)
				for _, a := range resp.ProcessedClientActions {
					if a.ActionStatus != 1 {
						t.Errorf("handshake response %s", m.payload)
					}
					if a.ActionType == "KMSEncryption" {
						if string(a.ActionResult.KMSCipherTextKey) != "sealed-by-kms" {
							t.Errorf("sealed key %q", a.ActionResult.KMSCipherTextKey)
						}
						seal, _ = gcm(testDataKey[:32]) // the agent writes with the first half
						open, _ = gcm(testDataKey[32:])
					}
				}
				if kms && seal == nil {
					t.Errorf("no KMS key in %s", m.payload)
				}
				out(payHandDone, []byte(`{}`))
			case m.payType == payOutput:
				p := m.payload
				if open != nil {
					var err error
					if p, err = open.Open(nil, p[:12], p[12:], nil); err != nil {
						t.Errorf("client payload does not decrypt: %v", err)
						return
					}
				} else if kms {
					t.Error("data before the KMS key")
				}
				out(payOutput, bytes.ToUpper(p))
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
	ssmStart = func(ctx context.Context, profile, region, target, port string) (ssmSession, error) {
		if target != "i-0abc" || port != "22" {
			t.Errorf("target %s port %s", target, port)
		}
		return ssmSession{id: "sess-1", url: url, token: "tok"}, nil
	}
	echo(t, acks)
}

func echo(t *testing.T, acks *atomic.Int32) {
	t.Helper()
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
	big := bytes.Repeat([]byte("x"), 5000) // more than one message
	c.Write(big)
	got := make([]byte, len(big))
	if _, err := io.ReadFull(c, got); err != nil || !bytes.Equal(got, bytes.ToUpper(big)) {
		t.Fatalf("big echo: %v", err)
	}
	time.Sleep(100 * time.Millisecond)
	if acks.Load() < 3 { // handshake request, handshake complete, the data
		t.Errorf("acked %d output messages", acks.Load())
	}
}

var testDataKey = bytes.Repeat([]byte{1, 2, 3, 4, 5, 6, 7, 8}, 8)

// fakeKMS answers GenerateDataKey through the real SDK client, and checks
// the request binds the key to the session and target.
func fakeKMS(t *testing.T, fail bool) {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Amz-Target") != "TrentService.GenerateDataKey" {
			t.Errorf("KMS call %s", r.Header.Get("X-Amz-Target"))
		}
		var in struct {
			KeyId             string
			NumberOfBytes     int
			EncryptionContext map[string]string
		}
		json.NewDecoder(r.Body).Decode(&in)
		if in.KeyId != "alias/ssm" || in.NumberOfBytes != 64 ||
			in.EncryptionContext["aws:ssm:SessionId"] != "sess-1" || in.EncryptionContext["aws:ssm:TargetId"] != "i-0abc" {
			t.Errorf("GenerateDataKey %+v", in)
		}
		w.Header().Set("Content-Type", "application/x-amz-json-1.1")
		if fail {
			w.WriteHeader(400)
			io.WriteString(w, `{"__type":"AccessDeniedException","message":"not allowed to use alias/ssm"}`)
			return
		}
		json.NewEncoder(w).Encode(map[string]any{"KeyId": "arn:aws:kms:us-east-1:1:key/k", "Plaintext": testDataKey, "CiphertextBlob": []byte("sealed-by-kms")})
	}))
	t.Cleanup(srv.Close)
	t.Setenv("AWS_ENDPOINT_URL_KMS", srv.URL)
	t.Setenv("AWS_ACCESS_KEY_ID", "AKIDTEST")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "secret")
	t.Setenv("AWS_REGION", "us-east-1")
	t.Setenv("AWS_CONFIG_FILE", "/dev/null")
	t.Setenv("AWS_SHARED_CREDENTIALS_FILE", "/dev/null")
	t.Setenv("AWS_PROFILE", "")
}

func TestSSMSessionWithKMS(t *testing.T) {
	fakeKMS(t, false)
	url, acks := fakeAgent(t, true)
	saved := ssmStart
	defer func() { ssmStart = saved }()
	ssmStart = func(context.Context, string, string, string, string) (ssmSession, error) {
		return ssmSession{id: "sess-1", url: url, token: "tok"}, nil
	}
	echo(t, acks)
}

func TestSSMKMSDenied(t *testing.T) {
	fakeKMS(t, true)
	url, _ := fakeAgent(t, true)
	saved := ssmStart
	defer func() { ssmStart = saved }()
	ssmStart = func(context.Context, string, string, string, string) (ssmSession, error) {
		return ssmSession{id: "sess-1", url: url, token: "tok"}, nil
	}
	_, err := SSMDial(context.Background(), "", "", "i-0abc", "22")
	if err == nil || !strings.Contains(err.Error(), "KMS") || !strings.Contains(err.Error(), "AccessDenied") {
		t.Errorf("denied KMS key: %v", err)
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

// TestSSMKMSMoto makes a session data key with a real KMS implementation
// (moto, started by make e2e) and opens the sealed copy the way the agent
// does: only with the same session and target.
func TestSSMKMSMoto(t *testing.T) {
	endpoint := os.Getenv("KOMANDO_E2E_MOTO")
	if endpoint == "" {
		t.Skip("set KOMANDO_E2E_MOTO to moto's URL (make e2e does)")
	}
	t.Setenv("AWS_ENDPOINT_URL", endpoint)
	t.Setenv("AWS_ACCESS_KEY_ID", "test")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "test")
	t.Setenv("AWS_REGION", "us-east-1")
	t.Setenv("AWS_CONFIG_FILE", "/dev/null")
	t.Setenv("AWS_SHARED_CREDENTIALS_FILE", "/dev/null")
	ctx := context.Background()
	cfg, err := AWSConfig(ctx, "", "")
	if err != nil {
		t.Fatal(err)
	}
	k := kms.NewFromConfig(cfg)
	key, err := k.CreateKey(ctx, &kms.CreateKeyInput{})
	if err != nil {
		t.Fatal(err)
	}
	encCtx := map[string]string{"aws:ssm:SessionId": "sess-1", "aws:ssm:TargetId": "i-0abc"}
	plain, sealed, err := ssmDataKey(ctx, "", "", *key.KeyMetadata.KeyId, encCtx)
	if err != nil {
		t.Fatal(err)
	}
	got, err := k.Decrypt(ctx, &kms.DecryptInput{CiphertextBlob: sealed, EncryptionContext: encCtx})
	if err != nil || !bytes.Equal(got.Plaintext, plain) {
		t.Fatalf("the agent cannot open the key: %v", err)
	}
	if _, err := k.Decrypt(ctx, &kms.DecryptInput{CiphertextBlob: sealed, EncryptionContext: map[string]string{"aws:ssm:SessionId": "other", "aws:ssm:TargetId": "i-0abc"}}); err == nil {
		t.Error("the key opened for another session")
	}
}
