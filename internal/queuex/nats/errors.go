package nats

import (
	"context"
	"errors"
	"net"
	"strings"

	natsgo "github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"

	"github.com/sgnd/komando/internal/driver"
	"github.com/sgnd/komando/internal/out"
	"github.com/sgnd/komando/internal/queuex"
)

// connectErr explains why komando could not reach or log in to the servers.
func connectErr(t driver.Target, err error) error {
	var e *out.Error
	if errors.As(err, &e) {
		return err
	}
	msg := err.Error()
	low := strings.ToLower(msg)
	switch {
	case errors.Is(err, natsgo.ErrAuthorization), errors.Is(err, natsgo.ErrAuthExpired), errors.Is(err, natsgo.ErrAuthRevoked),
		strings.Contains(low, "authorization violation"), strings.Contains(low, "authentication"):
		return out.Errf(out.ExitConnect, "QUEUE_AUTH", "check the user in the URL and the password reference (`komando conn show NAME`); a conn without a user sends its password reference as a token, and ?creds=secret:NAME logs in with a .creds file",
			"the server refused the login: %s", msg)
	case errors.Is(err, natsgo.ErrSecureConnWanted):
		return out.Errf(out.ExitConnect, "QUEUE_CONNECT", "the server has no TLS on this port: use nats:// (--via an SSH server, or ?insecure=1)", "cannot connect to %s: %s", t.Address, msg)
	case errors.Is(err, context.DeadlineExceeded) || errors.Is(err, natsgo.ErrTimeout) || isTimeout(err):
		return out.Errf(out.ExitTimeout, "TIMEOUT", "check the address and the port (4222 is the client port; 8222 is monitoring, 6222 the cluster's own), or raise --connect-timeout", "connecting to %s timed out", t.Address)
	case strings.Contains(msg, "x509:") || strings.Contains(msg, "tls: failed to verify"):
		return out.Errf(out.ExitConnect, "QUEUE_CONNECT", "the server's certificate could not be checked against this computer's CAs: use tls:// with ?ca=secret:NAME (`komando secret set NAME < ca.pem`), or reach the server --via an SSH server",
			"cannot connect to %s: %s", t.Address, msg)
	case strings.Contains(low, "expected 'info'") || strings.Contains(low, "protocol") || strings.Contains(msg, "EOF") || strings.Contains(msg, "connection reset"):
		return out.Errf(out.ExitConnect, "QUEUE_CONNECT", "check that this port speaks the NATS client protocol (4222 by default; not the monitoring port 8222 or a websocket port)",
			"cannot connect to %s: %s", t.Address, msg)
	}
	return out.Errf(out.ExitConnect, "QUEUE_CONNECT", "run `komando conn test NAME` to check reachability, or reach the server --via an SSH server that can",
		"cannot connect to %s: %s", t.Address, msg)
}

func isTimeout(err error) bool {
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}

// opErr turns the server's answer to a command into komando's error codes.
// what names the stream or consumer the command was about.
func (n *Nats) opErr(err error, what string) error {
	if err == nil {
		return nil
	}
	var e *out.Error
	if errors.As(err, &e) {
		return err
	}
	var api *jetstream.APIError
	if async := n.lastAsyncErr(); async != nil && denied(async) && !errors.As(err, &api) && (noAnswer(err) || noJetStream(err)) {
		err = async // a request the server refused shows as no answer; its reason came on its own
	}
	switch {
	case denied(err):
		return out.Errf(out.ExitRemote, "QUEUE_DENIED", "the conn's user may not use this part of the JetStream API ($JS.API.>) or this subject; ask the server's admin, or use a conn whose user may",
			"%s: %v", what, err)
	case noJetStream(err):
		return queuex.NotSupported("JetStream", "this nats account", "streams need JetStream, which is off on this server or for this account (`komando queue info CONN` says jetstream false); a leaf node's JetStream needs ?domain=NAME in the conn's URL")
	case errors.Is(err, jetstream.ErrStreamNotFound):
		return streamNotFound(what)
	case errors.Is(err, jetstream.ErrConsumerNotFound):
		return consumerNotFound(what)
	case errors.Is(err, jetstream.ErrStreamNameAlreadyInUse):
		return streamExists(what)
	case noAnswer(err):
		return out.Errf(out.ExitTimeout, "TIMEOUT", "the server did not answer in time; raise --timeout", "%s: %v", what, err)
	case errors.Is(err, natsgo.ErrMaxPayload):
		return out.Errf(out.ExitRemote, "QUEUE_ERROR", "the message is bigger than the server takes (max_payload, see `komando queue info CONN`)", "%s: %v", what, err)
	case errors.As(err, &api):
		return out.Errf(out.ExitRemote, "QUEUE_ERROR", "read the server's words above; `komando queue describe CONN STREAM` shows the stream's settings", "%s: %s", what, api.Description)
	}
	return out.Errf(out.ExitRemote, "QUEUE_ERROR", "the connection to the server failed; run `komando conn test NAME`", "%s: %v", what, err)
}

func noAnswer(err error) bool {
	return errors.Is(err, context.DeadlineExceeded) || errors.Is(err, natsgo.ErrTimeout) || isTimeout(err)
}

func denied(err error) bool {
	var api *jetstream.APIError
	return errors.Is(err, natsgo.ErrPermissionViolation) || strings.Contains(strings.ToLower(err.Error()), "permissions violation") ||
		(errors.As(err, &api) && api.Code == 403)
}

func noJetStream(err error) bool {
	return errors.Is(err, jetstream.ErrJetStreamNotEnabled) || errors.Is(err, jetstream.ErrJetStreamNotEnabledForAccount) ||
		errors.Is(err, natsgo.ErrNoResponders) || errors.Is(err, jetstream.ErrNoStreamResponse)
}

func streamNotFound(name string) error {
	return out.Errf(out.ExitNotFound, "STREAM_NOT_FOUND", "list streams with `komando queue ls CONN`", "stream %s does not exist", name)
}

func streamExists(name string) error {
	return out.Errf(out.ExitConflict, "STREAM_EXISTS", "pick another name, or see it with `komando queue describe CONN "+name+"`", "stream %s already exists", name)
}

func consumerNotFound(name string) error {
	return out.Errf(out.ExitNotFound, "CONSUMER_NOT_FOUND", "list consumers with `komando queue groups CONN`; name one as STREAM/CONSUMER", "consumer %s does not exist", name)
}
