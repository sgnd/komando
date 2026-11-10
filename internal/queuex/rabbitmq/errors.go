package rabbitmq

import (
	"context"
	"errors"
	"net"
	"strings"

	amqp "github.com/rabbitmq/amqp091-go"

	"github.com/sgnd/komando/internal/driver"
	"github.com/sgnd/komando/internal/out"
)

// connectErr explains why komando could not reach or log in to the server.
func connectErr(t driver.Target, err error) error {
	var e *out.Error
	if errors.As(err, &e) {
		return err
	}
	msg := err.Error()
	var ae *amqp.Error
	switch {
	case errors.As(err, &ae) && ae.Code == amqp.NotAllowed, errors.Is(err, amqp.ErrVhost):
		return out.Errf(out.ExitRemote, "QUEUE_DENIED", "check the vhost in the URL's path (%2F is the default vhost \"/\") and that the user has permissions on it",
			"the server refused the vhost %s: %s", t.Database, msg)
	case errors.As(err, &ae) && ae.Code == amqp.AccessRefused, errors.Is(err, amqp.ErrSASL), errors.Is(err, amqp.ErrCredentials):
		return out.Errf(out.ExitConnect, "QUEUE_AUTH", "check the user in the URL and the password reference (`komando conn show NAME`); a conn without a user logs in as guest, which RabbitMQ lets in only from the server itself",
			"the server refused the login: %s", msg)
	case errors.Is(err, context.DeadlineExceeded) || isTimeout(err) || strings.Contains(msg, "i/o timeout"): // the library wraps a read timeout in its own error
		return out.Errf(out.ExitTimeout, "TIMEOUT", "check the address and the port (5672, or 5671 for amqps://; not the management API's 15672), or raise --connect-timeout", "connecting to %s timed out", t.Address)
	case t.Secure && (strings.Contains(msg, "x509:") || strings.Contains(msg, "tls: failed to verify")):
		return out.Errf(out.ExitConnect, "QUEUE_CONNECT", "the server's certificate could not be checked against this computer's CAs: give the CA that signed it with ?ca=secret:NAME (`komando secret set NAME < ca.pem`), or reach the server --via an SSH server",
			"cannot connect to %s: %s", t.Address, msg)
	case t.Secure && strings.Contains(msg, "first record does not look like a TLS handshake"):
		return out.Errf(out.ExitConnect, "QUEUE_CONNECT", "the server does not speak TLS on this port: use amqp://, or the TLS port (usually 5671)", "cannot connect to %s: %s", t.Address, msg)
	case strings.Contains(msg, "EOF") || strings.Contains(msg, "connection reset") || errors.Is(err, amqp.ErrSyntax):
		return out.Errf(out.ExitConnect, "QUEUE_CONNECT", "the server closed the connection: check that this port speaks AMQP (5672, or 5671 for amqps://) and not the management API (15672)",
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
// what names the queue the command was about.
func opErr(err error, what string) error {
	if err == nil {
		return nil
	}
	var e *out.Error
	if errors.As(err, &e) {
		return err
	}
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) || isTimeout(err) {
		return out.Errf(out.ExitTimeout, "TIMEOUT", "the server did not answer in time; raise --timeout", "%s: %v", what, err)
	}
	var ae *amqp.Error
	if !errors.As(err, &ae) {
		return out.Errf(out.ExitRemote, "QUEUE_ERROR", "the connection to the server failed; run `komando conn test NAME`", "%s: %v", what, err)
	}
	switch ae.Code {
	case amqp.NotFound:
		return queueNotFound(what)
	case amqp.AccessRefused:
		return out.Errf(out.ExitRemote, "QUEUE_DENIED", "the conn's user lacks the RabbitMQ permission for this (configure, write or read on the queue); ask the server's admin, or use a conn whose user has it",
			"%s: %s", what, ae.Reason)
	case amqp.ResourceLocked:
		return out.Errf(out.ExitRemote, "QUEUE_ERROR", "the queue is exclusive: only the connection that made it can use it", "%s: %s", what, ae.Reason)
	case amqp.PreconditionFailed:
		return out.Errf(out.ExitRemote, "QUEUE_ERROR", "the server refused the queue's settings: check --type and --config (RabbitMQ arguments such as x-max-length=1000)", "%s: %s", what, ae.Reason)
	}
	return out.Errf(out.ExitRemote, "QUEUE_ERROR", "read the server's words above; `komando queue describe CONN QUEUE` shows the queue", "%s: %s", what, ae.Reason)
}

func queueNotFound(name string) error {
	return out.Errf(out.ExitNotFound, "QUEUE_NOT_FOUND", "list queues with `komando queue ls CONN` (it needs ?management=PORT in the conn's URL); the vhost is the URL's path",
		"queue %s does not exist", name)
}
