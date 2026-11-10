// Package sqs is the Amazon SQS engine of `komando queue`. It speaks the
// SQS JSON API over HTTPS itself, signed with the AWS SDK's SigV4 signer
// (already part of komando for its other AWS clients), so no SQS SDK or
// aws CLI is needed. It registers itself with queuex for sqs:// conns that
// carry their own keys; conns that log in with an AWS profile (SSO, roles)
// are opened by the CLI with OpenKeys. Reading never removes or hides a
// message: peek receives with a visibility timeout of 0 and never deletes.
// See docs/design/queue.md.
package sqs

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"

	"github.com/sgnd/komando/internal/driver"
	"github.com/sgnd/komando/internal/out"
	"github.com/sgnd/komando/internal/queuex"
)

func init() { queuex.Register("sqs", Open) }

// Keys are AWS credentials: an access key ID, its secret, and the session
// token of temporary keys (SSO, an assumed role).
type Keys struct {
	ID, Secret, Token string
}

// SQS is a queuex.Queue on one region of an AWS account.
type SQS struct {
	t       driver.Target
	keys    aws.Credentials
	hc      *http.Client
	base    string // the endpoint's URL, such as https://sqs.eu-west-1.amazonaws.com
	agent   string
	signer  *v4.Signer
	timeout time.Duration
}

// maxResponse is the most komando reads of one answer: ten messages of
// up to 1 MiB each, and room for their attributes.
const maxResponse = 32 << 20

// Open logs in with the access key ID in the conn's URL and the secret key
// from its password reference.
func Open(ctx context.Context, t driver.Target, password string, dial queuex.DialFunc, timeout time.Duration, clientID string) (queuex.Queue, error) {
	switch {
	case t.User == "":
		return nil, out.Usage("this sqs conn has no access key ID: give the AWS login with --option aws_profile=NAME, or sqs://ACCESS_KEY_ID@REGION and --password-ref")
	case password == "":
		return nil, out.Errf(out.ExitUsage, "USAGE", "store the secret access key with `komando secret set NAME`, then `komando conn edit CONN --password-ref secret:NAME`",
			"the sqs conn names the access key ID %s but has no secret key", t.User)
	}
	return OpenKeys(ctx, t, Keys{ID: t.User, Secret: password}, dial, timeout, clientID)
}

// OpenKeys connects with the given keys through dial (direct, --via an SSH
// server, or a VPN) and checks that SQS answers and takes them.
func OpenKeys(ctx context.Context, t driver.Target, k Keys, dial queuex.DialFunc, timeout time.Duration, clientID string) (queuex.Queue, error) {
	if dial == nil {
		dial = (&net.Dialer{Timeout: timeout}).DialContext
	}
	scheme := map[bool]string{true: "https", false: "http"}[t.Secure]
	host := t.Address
	if h, p, err := net.SplitHostPort(host); err == nil && (t.Secure && p == "443" || !t.Secure && p == "80") {
		host = h
	}
	tr := &http.Transport{
		DialContext:         dial,
		TLSHandshakeTimeout: timeout,
		MaxIdleConnsPerHost: 8,
		IdleConnTimeout:     30 * time.Second,
	}
	s := &SQS{
		t:       t,
		keys:    aws.Credentials{AccessKeyID: k.ID, SecretAccessKey: k.Secret, SessionToken: k.Token, Source: "komando"},
		hc:      &http.Client{Transport: tr, Timeout: timeout},
		base:    scheme + "://" + host,
		agent:   clientID,
		signer:  v4.NewSigner(),
		timeout: timeout,
	}
	var lq listQueuesOut
	if err := s.call(ctx, "ListQueues", map[string]any{"MaxResults": 1}, &lq); err != nil {
		tr.CloseIdleConnections()
		return nil, connectErr(t, err)
	}
	return s, nil
}

// Close ends the idle connections.
func (s *SQS) Close() {
	if tr, ok := s.hc.Transport.(*http.Transport); ok {
		tr.CloseIdleConnections()
	}
}

// apiError is an error SQS answered with: its code (QueueDoesNotExist,
// AccessDenied, ...) and its message.
type apiError struct {
	Status  int
	Code    string
	Message string
}

func (e *apiError) Error() string {
	if e.Message == "" {
		return e.Code
	}
	return e.Code + ": " + e.Message
}

// call runs one SQS action (AmazonSQS.<action>) with the JSON body in and
// decodes the answer into res (nil: ignore it).
func (s *SQS) call(ctx context.Context, action string, in, res any) error {
	body, err := json.Marshal(in)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.base+"/", bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-amz-json-1.0")
	req.Header.Set("X-Amz-Target", "AmazonSQS."+action)
	req.Header.Set("User-Agent", s.agent)
	sum := sha256.Sum256(body)
	if err := s.signer.SignHTTP(ctx, s.keys, req, hex.EncodeToString(sum[:]), "sqs", s.t.Region, time.Now()); err != nil {
		return err
	}
	resp, err := s.hc.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxResponse))
	if err != nil {
		return err
	}
	if resp.StatusCode/100 != 2 {
		return answerErr(resp, data)
	}
	if res == nil || len(bytes.TrimSpace(data)) == 0 {
		return nil
	}
	if err := json.Unmarshal(data, res); err != nil {
		return fmt.Errorf("the answer to %s is not SQS JSON (is the endpoint an SQS server?): %w", action, err)
	}
	return nil
}

// answerErr reads an error answer: JSON {"__type": "...#Code", "message"}
// as SQS gives it, or the older x-amzn-query-error header.
func answerErr(resp *http.Response, data []byte) error {
	var e struct {
		Type     string `json:"__type"`
		Code     string `json:"code"`
		Message  string `json:"message"`
		MessageU string `json:"Message"`
	}
	_ = json.Unmarshal(data, &e)
	code := e.Type
	if i := strings.LastIndex(code, "#"); i >= 0 {
		code = code[i+1:]
	}
	if code == "" {
		code = e.Code
	}
	if q := resp.Header.Get("x-amzn-query-error"); code == "" && q != "" {
		code, _, _ = strings.Cut(q, ";")
	}
	if code == "" {
		code = resp.Status
	}
	msg := e.Message + e.MessageU
	if msg == "" && e.Type == "" {
		msg = strings.TrimSpace(string(data))
		if len(msg) > 200 {
			msg = msg[:200] + "..."
		}
	}
	return &apiError{Status: resp.StatusCode, Code: code, Message: msg}
}

type listQueuesOut struct {
	QueueUrls []string `json:"QueueUrls"`
	NextToken string   `json:"NextToken"`
}

// queueNameOf is the name in a queue URL (the last part of its path).
func queueNameOf(u string) string {
	return u[strings.LastIndex(u, "/")+1:]
}

// accountOf is the account ID in a queue URL (/ACCOUNT/NAME), or "".
func accountOf(u string) string {
	p, err := url.Parse(u)
	if err != nil {
		return ""
	}
	parts := strings.Split(strings.Trim(p.Path, "/"), "/")
	if len(parts) < 2 {
		return ""
	}
	return parts[len(parts)-2]
}

// queueURL asks SQS for the URL of a queue by its name (QUEUE_NOT_FOUND
// when there is none); ?account= names a queue of another account.
func (s *SQS) queueURL(ctx context.Context, name string) (string, error) {
	if err := checkName(name); err != nil {
		return "", err
	}
	in := map[string]any{"QueueName": name}
	if s.t.Account != "" {
		in["QueueOwnerAWSAccountId"] = s.t.Account
	}
	var res struct {
		QueueURL string `json:"QueueUrl"`
	}
	if err := s.call(ctx, "GetQueueUrl", in, &res); err != nil {
		return "", opErr(err, name)
	}
	return res.QueueURL, nil
}

// checkName refuses a name SQS would not have: 1 to 80 letters, digits,
// - and _, with .fifo at the end for a FIFO queue.
func checkName(name string) error {
	base := strings.TrimSuffix(name, ".fifo")
	ok := base != "" && len(name) <= 80
	for _, r := range base {
		ok = ok && (r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-' || r == '_')
	}
	if !ok {
		return out.Usage("%q is not an SQS queue name: 1 to 80 letters, digits, - and _, ending in .fifo for a FIFO queue", name)
	}
	return nil
}

// Groups: SQS has no consumer groups.
func (s *SQS) Groups(context.Context) ([]queuex.Group, error) {
	return nil, queuex.NotSupported("queue groups", "sqs", noGroups)
}

// Lag: SQS has no consumer groups.
func (s *SQS) Lag(context.Context, string) (*queuex.GroupLag, error) {
	return nil, queuex.NotSupported("queue lag", "sqs", noGroups)
}

const noGroups = "SQS has no consumer groups: every consumer takes from the same queue. `komando queue describe CONN QUEUE` shows the messages " +
	"waiting (messages), received and not yet deleted (in_flight) and delayed"
