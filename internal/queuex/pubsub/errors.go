package pubsub

import (
	"context"
	"errors"
	"strings"

	"golang.org/x/oauth2"

	"github.com/sgnd/komando/internal/driver"
	"github.com/sgnd/komando/internal/out"
	"github.com/sgnd/komando/internal/queuex"
)

const authHint = "check the Google Cloud login: the service account key in the conn's --password-ref, or else gcloud's (`gcloud auth application-default login`, " +
	"or GOOGLE_APPLICATION_CREDENTIALS naming a key file)"

const deniedHint = "the login lacks the IAM role for this (roles/pubsub.viewer to read, roles/pubsub.subscriber to peek, roles/pubsub.publisher to send, " +
	"roles/pubsub.editor to create and delete); ask the project's admin, or use a login that has it. If the Pub/Sub API is not enabled in the project, enable it first"

// connectErr explains why komando could not reach Pub/Sub or log in.
func connectErr(t driver.Target, err error) error {
	var e *out.Error
	if errors.As(err, &e) {
		return err
	}
	var api *apiError
	var re *oauth2.RetrieveError
	msg := err.Error()
	switch {
	case errors.As(err, &re):
		return out.Errf(out.ExitConnect, "QUEUE_AUTH", authHint, "Google refused the login: %s", msg)
	case errors.As(err, &api) && api.HTTP == 401:
		return out.Errf(out.ExitConnect, "QUEUE_AUTH", authHint, "Pub/Sub refused the login: %s", msg)
	case errors.As(err, &api) && api.HTTP == 403:
		return deniedErr(msg)
	case errors.As(err, &api) && api.HTTP == 404:
		return out.Errf(out.ExitConnect, "QUEUE_CONNECT", "check the project ID in the URL (pubsub://PROJECT; the ID, not the project's display name) and ?endpoint=",
			"project %s: %s", t.Project, msg)
	case errors.As(err, &api):
		return out.Errf(out.ExitConnect, "QUEUE_CONNECT", "check the project in the URL and ?endpoint= (the emulator's address, such as http://localhost:8085)",
			"%s answered: %s", t.Address, msg)
	case errors.Is(err, context.DeadlineExceeded) || queuex.IsTimeout(err):
		return out.Errf(out.ExitTimeout, "TIMEOUT", "check ?endpoint=, or raise --connect-timeout; without internet, reach Pub/Sub --via a server that can (or a Private Service Connect endpoint in ?endpoint=)",
			"connecting to %s timed out", t.Address)
	case strings.Contains(msg, "x509:") || strings.Contains(msg, "tls: failed to verify"):
		return out.Errf(out.ExitConnect, "QUEUE_CONNECT", "the endpoint's certificate could not be checked against this computer's CAs; check ?endpoint=",
			"cannot connect to %s: %s", t.Address, msg)
	case strings.Contains(msg, "not Pub/Sub JSON") || strings.Contains(msg, "server gave HTTP response to HTTPS client"):
		return out.Errf(out.ExitConnect, "QUEUE_CONNECT", "check ?endpoint=: it must be a Pub/Sub server (http:// for the emulator)", "cannot connect to %s: %s", t.Address, msg)
	}
	return out.Errf(out.ExitConnect, "QUEUE_CONNECT", "run `komando test TARGET` to check reachability, or reach Pub/Sub --via a server that can",
		"cannot connect to %s: %s", t.Address, msg)
}

func deniedErr(msg string) error {
	return out.Errf(out.ExitRemote, "QUEUE_DENIED", deniedHint, "%s", msg)
}

// opErr turns Pub/Sub's answer to a command into komando's error codes.
// what names the topic or subscription; missing is the error for a 404.
func opErr(err error, what string, missing func(string) error) error {
	if err == nil {
		return nil
	}
	var e *out.Error
	if errors.As(err, &e) {
		return err
	}
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) || queuex.IsTimeout(err) {
		return out.Errf(out.ExitTimeout, "TIMEOUT", "Pub/Sub did not answer in time; raise --timeout", "%s: %v", what, err)
	}
	var re *oauth2.RetrieveError
	if errors.As(err, &re) {
		return out.Errf(out.ExitConnect, "QUEUE_AUTH", authHint, "%s: Google refused the login: %v", what, err)
	}
	var api *apiError
	if !errors.As(err, &api) {
		return out.Errf(out.ExitRemote, "QUEUE_ERROR", "the connection to Pub/Sub failed; run `komando test TARGET`", "%s: %v", what, err)
	}
	switch {
	case api.HTTP == 404 && missing != nil:
		return missing(what)
	case api.HTTP == 401:
		return out.Errf(out.ExitConnect, "QUEUE_AUTH", authHint, "%s: Pub/Sub refused the login: %v", what, err)
	case api.HTTP == 403:
		return deniedErr(what + ": " + err.Error())
	case api.HTTP == 429 || api.Status == "RESOURCE_EXHAUSTED":
		return out.Errf(out.ExitRemote, "QUEUE_ERROR", "Pub/Sub is asking komando to slow down (or a quota is used up); run it again in a moment", "%s: %v", what, err)
	case api.HTTP == 400:
		return out.Errf(out.ExitRemote, "QUEUE_ERROR", "Pub/Sub refused the request: check --config (Pub/Sub's setting names, such as ackDeadlineSeconds=60 or messageRetentionDuration=7d) and the message's --header names",
			"%s: %v", what, err)
	}
	return out.Errf(out.ExitRemote, "QUEUE_ERROR", "read Pub/Sub's words above; `komando queue describe CONN NAME` shows the topic or subscription", "%s: %v", what, err)
}

func topicNotFound(name string) error {
	return out.Errf(out.ExitNotFound, "TOPIC_NOT_FOUND", "list topics with `komando queue list CONN`; a subscription is written subscriptions/NAME, and the project is the conn URL's host",
		"no topic named %q", name)
}

func subNotFound(name string) error {
	return out.Errf(out.ExitNotFound, "SUBSCRIPTION_NOT_FOUND", "list subscriptions with `komando queue groups CONN`; `komando queue describe CONN TOPIC` shows a topic's own",
		"no subscription named %q", name)
}

func topicExists(name string) error {
	return out.Errf(out.ExitConflict, "TOPIC_EXISTS", "pick another name, or see it with `komando queue describe CONN topics/"+name+"`", "topic %s already exists", name)
}

func subExists(name string) error {
	return out.Errf(out.ExitConflict, "SUBSCRIPTION_EXISTS", "pick another name, or see it with `komando queue describe CONN subscriptions/"+name+"`", "subscription %s already exists", name)
}

// isCode says whether err is komando's error with this code.
func isCode(err error, code string) bool {
	var e *out.Error
	return errors.As(err, &e) && e.Code == code
}

// isStatus says whether err is Pub/Sub's answer with this HTTP status.
func isStatus(err error, status int) bool {
	var api *apiError
	return errors.As(err, &api) && api.HTTP == status
}
