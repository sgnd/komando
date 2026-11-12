package queuex

import (
	"context"
	"errors"
	"net"
	"strings"

	"github.com/twmb/franz-go/pkg/kadm"
	"github.com/twmb/franz-go/pkg/kerr"

	"github.com/sgnd/komando/internal/driver"
	"github.com/sgnd/komando/internal/out"
)

// connectErr explains why the brokers could not be reached or logged in to.
func connectErr(t driver.Target, err error) error {
	var e *out.Error
	if errors.As(err, &e) {
		return err
	}
	msg := err.Error()
	switch {
	case errors.Is(err, kerr.SaslAuthenticationFailed), errors.Is(err, kerr.IllegalSaslState):
		return out.Errf(out.ExitConnect, "QUEUE_AUTH", "check the user in the URL, the sasl= option and the password reference (`komando conn show NAME`)", "the brokers refused the login: %s", msg)
	case errors.Is(err, kerr.UnsupportedSaslMechanism):
		return out.Errf(out.ExitConnect, "QUEUE_AUTH", "the brokers do not take this sasl= mechanism: try scram-sha-512, scram-sha-256 or plain (`komando conn edit NAME --url ...`)", "%s", msg)
	case isAuthz(err):
		return deniedErr(err)
	case errors.Is(err, context.DeadlineExceeded) || IsTimeout(err):
		return out.Errf(out.ExitTimeout, "TIMEOUT", "check the address, or raise --connect-timeout; a broker that speaks TLS needs ?tls=true", "connecting to %s timed out", t.Address)
	case t.Secure && (strings.Contains(msg, "x509:") || strings.Contains(msg, "tls: failed to verify")):
		return out.Errf(out.ExitConnect, "QUEUE_CONNECT", "the broker's certificate could not be checked against this computer's CAs: give the CA that signed it with ?ca=secret:NAME (`komando secret set NAME < ca.pem`), or reach the brokers --via an SSH server",
			"cannot connect to %s: %s", t.Address, msg)
	case t.Secure && strings.Contains(msg, "first record does not look like a TLS handshake"):
		return out.Errf(out.ExitConnect, "QUEUE_CONNECT", "the broker does not speak TLS on this port: check the port, or drop tls=true from the URL", "cannot connect to %s: %s", t.Address, msg)
	case t.SASL != "" && closed(msg):
		return out.Errf(out.ExitConnect, "QUEUE_CONNECT", "the broker closed the connection during the login: check the password reference (`komando conn show NAME`) and the sasl= mechanism; the broker may also want TLS (?tls=true)", "cannot connect to %s: %s", t.Address, msg)
	case !t.Secure && closed(msg):
		return out.Errf(out.ExitConnect, "QUEUE_CONNECT", "the broker closed the connection: it may want TLS (?tls=true) or a SASL login (?sasl=...)", "cannot connect to %s: %s", t.Address, msg)
	}
	return out.Errf(out.ExitConnect, "QUEUE_CONNECT", "run `komando conn test NAME` to check reachability; brokers must be reachable at the addresses they advertise (use --via a server that can reach them)",
		"cannot connect to %s: %s", t.Address, msg)
}

func closed(msg string) bool {
	return strings.Contains(msg, "EOF") || strings.Contains(msg, "connection reset")
}

// IsTimeout reports whether err is a network timeout.
func IsTimeout(err error) bool {
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}

func isAuthz(err error) bool {
	var ae *kadm.AuthError
	return errors.As(err, &ae) || errors.Is(err, kerr.TopicAuthorizationFailed) || errors.Is(err, kerr.GroupAuthorizationFailed) ||
		errors.Is(err, kerr.ClusterAuthorizationFailed) || errors.Is(err, kerr.TransactionalIDAuthorizationFailed)
}

func deniedErr(err error) error {
	return out.Errf(out.ExitRemote, "QUEUE_DENIED", "the conn's user lacks the Kafka ACL for this (topic, group or cluster); ask the cluster's admin, or use a conn whose user has it", "%s", err.Error())
}

// opErr turns a broker's answer to a command into komando's error codes.
// what names the topic or group the command was about.
func opErr(err error, what string) error {
	if err == nil {
		return nil
	}
	var e *out.Error
	switch {
	case errors.As(err, &e):
		return err
	case isAuthz(err):
		return deniedErr(err)
	case errors.Is(err, kerr.UnknownTopicOrPartition), errors.Is(err, kerr.UnknownTopicID):
		return topicNotFound(what)
	case errors.Is(err, kerr.GroupIDNotFound):
		return groupNotFound(what)
	case errors.Is(err, kerr.TopicAlreadyExists):
		return out.Errf(out.ExitConflict, "TOPIC_EXISTS", "pick another name, or see it with `komando queue describe CONN "+what+"`", "topic %s already exists", what)
	case errors.Is(err, context.DeadlineExceeded) || IsTimeout(err):
		return out.Errf(out.ExitTimeout, "TIMEOUT", "the brokers did not answer in time; raise --timeout", "%s: %v", what, err)
	case errors.Is(err, kerr.InvalidReplicationFactor), errors.Is(err, kerr.InvalidPartitions), errors.Is(err, kerr.InvalidConfig),
		errors.Is(err, kerr.InvalidTopicException), errors.Is(err, kerr.PolicyViolation):
		return out.Errf(out.ExitRemote, "QUEUE_ERROR", "the brokers refused the topic's settings: --replicas can be at most the number of brokers (`komando queue info CONN`), and --config names Kafka topic settings such as retention.ms",
			"%s: %v", what, err)
	}
	return out.Errf(out.ExitRemote, "QUEUE_ERROR", "read the broker's words above; `komando queue describe CONN TOPIC` shows the topic's settings", "%s: %v", what, err)
}

func topicNotFound(topic string) error {
	return out.Errf(out.ExitNotFound, "TOPIC_NOT_FOUND", "list topics with `komando queue list CONN`", "no topic named %q", topic)
}

func groupNotFound(group string) error {
	return out.Errf(out.ExitNotFound, "CONSUMER_GROUP_NOT_FOUND", "list consumer groups with `komando queue groups CONN`", "no consumer group named %q", group)
}

// NotSupported is the answer of an engine to a verb or flag it cannot do.
func NotSupported(what, engine, hint string) error {
	return out.Errf(out.ExitUsage, "NOT_SUPPORTED", hint, "%s is not supported for %s", what, engine)
}
