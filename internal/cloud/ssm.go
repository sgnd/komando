package cloud

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
	"github.com/gorilla/websocket"
)

// AWS Systems Manager Session Manager without the aws CLI and its
// session-manager-plugin: StartSession (AWS-StartSSHSession) through the
// SDK, then the Session Manager data channel over WebSocket. Each message
// has a 120-byte header (type, sequence number, id, SHA-256 of the
// payload); every output message is acknowledged.
//
// When the account encrypts sessions with KMS, the agent's handshake names
// a KMS key: komando asks KMS for a 64-byte data key (bound to the session
// and target through the encryption context) and hands the agent the
// encrypted copy. The first half of the key decrypts what the agent sends,
// the second half encrypts what komando sends; each data payload is then
// a 12-byte nonce followed by AES-256-GCM output.

// ssmStart is ssm StartSession; tests replace it.
var ssmStart = func(ctx context.Context, profile, region, target, port string) (s ssmSession, err error) {
	cfg, err := AWSConfig(ctx, profile, region)
	if err != nil {
		return s, err
	}
	o, err := ssm.NewFromConfig(cfg).StartSession(ctx, &ssm.StartSessionInput{
		Target: aws.String(target), DocumentName: aws.String("AWS-StartSSHSession"),
		Parameters: map[string][]string{"portNumber": {port}},
	})
	if err != nil {
		return s, awsErr(err)
	}
	return ssmSession{id: aws.ToString(o.SessionId), url: aws.ToString(o.StreamUrl), token: aws.ToString(o.TokenValue)}, nil
}

type ssmSession struct{ id, url, token string }

// ssmDataKey asks KMS for the session's data key: the plain key and the
// copy only KMS can open.
func ssmDataKey(ctx context.Context, profile, region, keyID string, encCtx map[string]string) (plain, sealed []byte, err error) {
	cfg, err := AWSConfig(ctx, profile, region)
	if err != nil {
		return nil, nil, err
	}
	o, err := kms.NewFromConfig(cfg).GenerateDataKey(ctx, &kms.GenerateDataKeyInput{
		KeyId: aws.String(keyID), NumberOfBytes: aws.Int32(64), EncryptionContext: encCtx,
	})
	if err != nil {
		return nil, nil, awsErr(err)
	}
	if len(o.Plaintext) != 64 || len(o.CiphertextBlob) == 0 {
		return nil, nil, errors.New("KMS gave a data key of the wrong size")
	}
	return o.Plaintext, o.CiphertextBlob, nil
}

// SSMDial opens an SSH stream to an EC2 instance through Session Manager.
func SSMDial(ctx context.Context, profile, region, target, port string) (net.Conn, error) {
	sess, err := ssmStart(ctx, profile, region, target, port)
	if err != nil {
		return nil, err
	}
	streamURL, token := sess.url, sess.token
	ws, _, err := websocket.DefaultDialer.DialContext(ctx, streamURL, nil)
	if err != nil {
		return nil, fmt.Errorf("session manager: %w", err)
	}
	ws.SetReadLimit(ssmReadLimit)
	open, _ := json.Marshal(map[string]string{"MessageSchemaVersion": "1.0", "RequestId": newUUID(), "TokenValue": token,
		"ClientId": newUUID(), "ClientVersion": "1.2.0.0"})
	if err := ws.WriteMessage(websocket.TextMessage, open); err != nil {
		ws.Close()
		return nil, err
	}
	c := &ssmConn{ws: ws, in: make(chan []byte, 64), ready: make(chan error, 1), done: make(chan struct{}),
		dataKey: func(keyID string) ([]byte, []byte, error) {
			return ssmDataKey(ctx, profile, region, keyID, map[string]string{"aws:ssm:SessionId": sess.id, "aws:ssm:TargetId": target})
		}}
	go c.readLoop()
	select {
	case err := <-c.ready:
		if err != nil {
			ws.Close()
			return nil, err
		}
	case <-time.After(30 * time.Second):
		ws.Close()
		return nil, errors.New("session manager: the agent did not answer the handshake")
	case <-ctx.Done():
		ws.Close()
		return nil, ctx.Err()
	}
	return c, nil
}

type ssmConn struct {
	ws       *websocket.Conn
	wmu      sync.Mutex
	seq      int64
	expect   int64
	in       chan []byte
	pending  []byte
	ready    chan error
	ronce    sync.Once
	done     chan struct{}
	donce    sync.Once
	ooo      map[int64]ssmMsg // messages that came early, by sequence number
	oooBytes int              // their payload bytes
	dataKey  func(keyID string) (plain, sealed []byte, err error)
	// with KMS: open reads the agent's payloads, seal writes ours
	open, seal cipher.AEAD
}

const (
	ssmInput    = "input_stream_data"
	ssmOutput   = "output_stream_data"
	ssmAck      = "acknowledge"
	ssmClosed   = "channel_closed"
	payOutput   = 1
	payHandReq  = 5
	payHandResp = 6
	payHandDone = 7

	// The agent on the instance numbers its messages. These bound what
	// komando keeps while it waits for a missing one, so a broken or
	// hostile agent cannot fill this computer's memory.
	ssmMaxAhead    = 256     // messages ahead of the next expected one
	ssmMaxBuffered = 4 << 20 // bytes kept out of order
	ssmReadLimit   = 1 << 20 // one websocket message
)

type ssmMsg struct {
	typ     string
	seq     int64
	flags   uint64
	id      [16]byte
	payType uint32
	payload []byte
}

func encodeSSM(m ssmMsg) []byte {
	b := make([]byte, 120+len(m.payload))
	binary.BigEndian.PutUint32(b[0:], 116)
	copy(b[4:36], bytes.Repeat([]byte{' '}, 32))
	copy(b[4:], m.typ)
	binary.BigEndian.PutUint32(b[36:], 1)
	binary.BigEndian.PutUint64(b[40:], uint64(time.Now().UnixMilli()))
	binary.BigEndian.PutUint64(b[48:], uint64(m.seq))
	binary.BigEndian.PutUint64(b[56:], m.flags)
	copy(b[64:80], m.id[:])
	sum := sha256.Sum256(m.payload)
	copy(b[80:112], sum[:])
	binary.BigEndian.PutUint32(b[112:], m.payType)
	binary.BigEndian.PutUint32(b[116:], uint32(len(m.payload)))
	copy(b[120:], m.payload)
	return b
}

func decodeSSM(b []byte) (ssmMsg, error) {
	if len(b) < 120 {
		return ssmMsg{}, errors.New("short message")
	}
	n := binary.BigEndian.Uint32(b[116:])
	if int(n) > len(b)-120 {
		return ssmMsg{}, errors.New("bad payload length")
	}
	m := ssmMsg{typ: strings.TrimRight(string(b[4:36]), " \x00"), seq: int64(binary.BigEndian.Uint64(b[48:])),
		flags: binary.BigEndian.Uint64(b[56:]), payType: binary.BigEndian.Uint32(b[112:]), payload: b[120 : 120+n]}
	copy(m.id[:], b[64:80])
	sum := sha256.Sum256(m.payload)
	if !bytes.Equal(sum[:], b[80:112]) && m.typ != ssmAck {
		return ssmMsg{}, errors.New("payload digest does not match")
	}
	return m, nil
}

func (c *ssmConn) send(payType uint32, payload []byte) error {
	c.wmu.Lock()
	defer c.wmu.Unlock()
	if c.seal != nil && payType == payOutput {
		nonce := make([]byte, c.seal.NonceSize())
		rand.Read(nonce)
		payload = c.seal.Seal(nonce, nonce, payload, nil)
	}
	var id [16]byte
	rand.Read(id[:])
	b := encodeSSM(ssmMsg{typ: ssmInput, seq: c.seq, id: id, payType: payType, payload: payload})
	c.seq++
	return c.ws.WriteMessage(websocket.BinaryMessage, b)
}

func (c *ssmConn) ack(m ssmMsg) {
	p, _ := json.Marshal(map[string]any{"AcknowledgedMessageType": m.typ, "AcknowledgedMessageId": uuidString(m.id),
		"AcknowledgedMessageSequenceNumber": m.seq, "IsSequentialMessage": true})
	var id [16]byte
	rand.Read(id[:])
	c.wmu.Lock()
	defer c.wmu.Unlock()
	c.ws.WriteMessage(websocket.BinaryMessage, encodeSSM(ssmMsg{typ: ssmAck, flags: 3, id: id, payload: p}))
}

func (c *ssmConn) readLoop() {
	defer c.close()
	for {
		_, b, err := c.ws.ReadMessage()
		if err != nil {
			c.ronce.Do(func() { c.ready <- fmt.Errorf("session manager: %w", err) })
			return
		}
		m, err := decodeSSM(b)
		if err != nil {
			continue
		}
		switch m.typ {
		case ssmClosed:
			c.ronce.Do(func() { c.ready <- errors.New("session manager closed the session: " + string(m.payload)) })
			return
		case ssmOutput:
			if m.seq > c.expect {
				// early: keep it for later, within a bounded window. Beyond
				// that it is dropped without an ack, so the agent sends it again.
				if _, dup := c.ooo[m.seq]; !dup {
					if m.seq-c.expect > ssmMaxAhead || c.oooBytes+len(m.payload) > ssmMaxBuffered {
						continue
					}
					if c.ooo == nil {
						c.ooo = map[int64]ssmMsg{}
					}
					m.payload = append([]byte{}, m.payload...)
					c.ooo[m.seq] = m
					c.oooBytes += len(m.payload)
				}
				c.ack(m)
				continue
			}
			c.ack(m)
			if m.seq < c.expect {
				continue // a resend
			}
			c.handle(m)
			c.expect++
			for {
				next, ok := c.ooo[c.expect]
				if !ok {
					break
				}
				delete(c.ooo, c.expect)
				c.oooBytes -= len(next.payload)
				c.handle(next) // with its own payload type
				c.expect++
			}
		}
	}
}

func (c *ssmConn) handle(m ssmMsg) {
	switch m.payType {
	case payHandReq:
		var req struct {
			RequestedClientActions []struct {
				ActionType       string
				ActionParameters json.RawMessage
			}
		}
		json.Unmarshal(m.payload, &req)
		var done []map[string]any
		for _, a := range req.RequestedClientActions {
			r := map[string]any{"ActionType": a.ActionType, "ActionStatus": 1}
			if a.ActionType == "KMSEncryption" {
				sealed, err := c.startKMS(a.ActionParameters)
				if err != nil {
					c.ronce.Do(func() { c.ready <- fmt.Errorf("session manager: KMS encryption: %w", err) })
					return
				}
				r["ActionResult"] = map[string][]byte{"KMSCipherTextKey": sealed}
			}
			done = append(done, r)
		}
		p, _ := json.Marshal(map[string]any{"ClientVersion": "1.2.0.0", "ProcessedClientActions": done, "Errors": []string{}})
		c.send(payHandResp, p)
	case payHandDone:
		c.ronce.Do(func() { c.ready <- nil })
	case payOutput:
		c.ronce.Do(func() { c.ready <- nil }) // older agents skip the handshake
		p := append([]byte{}, m.payload...)
		if c.open != nil {
			n := c.open.NonceSize()
			var err error
			if len(p) < n {
				err = errors.New("short payload")
			} else {
				p, err = c.open.Open(nil, p[:n], p[n:], nil)
			}
			if err != nil {
				c.close() // a payload that does not decrypt ends the session
				return
			}
		}
		select {
		case c.in <- p:
		case <-c.done:
		}
	}
}

// startKMS makes the session's data key for the key the agent named and
// returns KMS's sealed copy for the agent.
func (c *ssmConn) startKMS(params json.RawMessage) ([]byte, error) {
	var p struct{ KMSKeyId string }
	if json.Unmarshal(params, &p) != nil || p.KMSKeyId == "" {
		return nil, errors.New("the agent named no KMS key")
	}
	plain, sealed, err := c.dataKey(p.KMSKeyId)
	if err != nil {
		return nil, err
	}
	open, err := gcm(plain[:32])
	if err != nil {
		return nil, err
	}
	seal, err := gcm(plain[32:])
	if err != nil {
		return nil, err
	}
	c.wmu.Lock()
	c.open, c.seal = open, seal
	c.wmu.Unlock()
	return sealed, nil
}

func gcm(key []byte) (cipher.AEAD, error) {
	b, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(b)
}

func (c *ssmConn) close() {
	c.donce.Do(func() { close(c.done); c.ws.Close() })
}

func (c *ssmConn) Read(b []byte) (int, error) {
	if len(c.pending) == 0 {
		select {
		case p := <-c.in:
			c.pending = p
		case <-c.done:
			select {
			case p := <-c.in:
				c.pending = p
			default:
				return 0, io.EOF
			}
		}
	}
	n := copy(b, c.pending)
	c.pending = c.pending[n:]
	return n, nil
}

func (c *ssmConn) Write(b []byte) (int, error) {
	for off := 0; off < len(b); off += 1024 {
		if err := c.send(payOutput, b[off:min(off+1024, len(b))]); err != nil {
			return off, err
		}
	}
	return len(b), nil
}

func (c *ssmConn) Close() error                       { c.close(); return nil }
func (c *ssmConn) LocalAddr() net.Addr                { return &net.TCPAddr{} }
func (c *ssmConn) RemoteAddr() net.Addr               { return &net.TCPAddr{} }
func (c *ssmConn) SetDeadline(t time.Time) error      { return nil }
func (c *ssmConn) SetReadDeadline(t time.Time) error  { return nil }
func (c *ssmConn) SetWriteDeadline(t time.Time) error { return nil }

// Session Manager writes a UUID's two halves the other way round
// (least significant first).
func uuidString(id [16]byte) string {
	b := append(append([]byte{}, id[8:]...), id[:8]...)
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:])
}

func newUUID() string {
	var b [16]byte
	rand.Read(b[:])
	b[6] = b[6]&0x0f | 0x40
	b[8] = b[8]&0x3f | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:])
}
