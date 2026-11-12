package sqs

import (
	"context"
	"errors"
	"strings"

	"github.com/sgnd/komando/internal/driver"
	"github.com/sgnd/komando/internal/out"
	"github.com/sgnd/komando/internal/queuex"
)

// loginCodes are SQS's answers to keys it does not take.
var loginCodes = map[string]bool{
	"InvalidClientTokenId": true, "UnrecognizedClientException": true, "SignatureDoesNotMatch": true, "ExpiredToken": true,
	"ExpiredTokenException": true, "InvalidSecurity": true, "MissingAuthenticationToken": true, "IncompleteSignature": true,
	"InvalidAccessKeyId": true, "AuthFailure": true,
}

// deniedCodes are SQS's answers to a login that may not do something.
var deniedCodes = map[string]bool{
	"AccessDenied": true, "AccessDeniedException": true, "KmsAccessDenied": true, "AWS.SimpleQueueService.KmsAccessDenied": true,
	"OptInRequired": true,
}

const authHint = "check the AWS login: the conn's --option aws_profile (a person renews an SSO login with `komando login aws --profile NAME`), " +
	"or the access key ID in the URL and its --password-ref; with neither, komando uses the usual chain (AWS_* variables, ~/.aws, the instance's role)"

// connectErr explains why komando could not reach SQS or log in.
func connectErr(t driver.Target, err error) error {
	var e *out.Error
	if errors.As(err, &e) {
		return err
	}
	var api *apiError
	msg := err.Error()
	switch {
	case errors.As(err, &api) && loginCodes[api.Code]:
		return out.Errf(out.ExitConnect, "QUEUE_AUTH", authHint, "SQS refused the login: %s", msg)
	case errors.As(err, &api) && deniedCodes[api.Code]:
		return deniedErr(msg)
	case errors.As(err, &api):
		return out.Errf(out.ExitConnect, "QUEUE_CONNECT", "check the region in the URL and ?endpoint= (an emulator's address, such as http://localhost:4566)",
			"%s answered: %s", t.Address, msg)
	case errors.Is(err, context.DeadlineExceeded) || queuex.IsTimeout(err):
		return out.Errf(out.ExitTimeout, "TIMEOUT", "check the region and ?endpoint=, or raise --connect-timeout; inside a VPC without internet, use an SQS VPC endpoint (?endpoint=) or reach it --via a server that can",
			"connecting to %s timed out", t.Address)
	case strings.Contains(msg, "x509:") || strings.Contains(msg, "tls: failed to verify"):
		return out.Errf(out.ExitConnect, "QUEUE_CONNECT", "the endpoint's certificate could not be checked against this computer's CAs; check ?endpoint=",
			"cannot connect to %s: %s", t.Address, msg)
	case strings.Contains(msg, "not SQS JSON") || strings.Contains(msg, "server gave HTTP response to HTTPS client"):
		return out.Errf(out.ExitConnect, "QUEUE_CONNECT", "check ?endpoint=: it must be an SQS server (http:// for an emulator without TLS)", "cannot connect to %s: %s", t.Address, msg)
	}
	return out.Errf(out.ExitConnect, "QUEUE_CONNECT", "run `komando test TARGET` to check reachability, or reach SQS --via a server that can",
		"cannot connect to %s: %s", t.Address, msg)
}

func deniedErr(msg string) error {
	return out.Errf(out.ExitRemote, "QUEUE_DENIED", "the AWS login lacks the IAM permission for this (sqs:ListQueues, sqs:ReceiveMessage, sqs:SendMessage ...; a KMS-encrypted queue also needs kms:Decrypt or kms:GenerateDataKey); ask the account's admin, or use a profile that has it",
		"%s", msg)
}

// opErr turns SQS's answer to a command into komando's error codes. what
// names the queue the command was about.
func opErr(err error, what string) error {
	if err == nil {
		return nil
	}
	var e *out.Error
	if errors.As(err, &e) {
		return err
	}
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) || queuex.IsTimeout(err) {
		return out.Errf(out.ExitTimeout, "TIMEOUT", "SQS did not answer in time; raise --timeout", "%s: %v", what, err)
	}
	var api *apiError
	if !errors.As(err, &api) {
		return out.Errf(out.ExitRemote, "QUEUE_ERROR", "the connection to SQS failed; run `komando test TARGET`", "%s: %v", what, err)
	}
	switch c := api.Code; {
	case c == "QueueDoesNotExist" || c == "AWS.SimpleQueueService.NonExistentQueue":
		return queueNotFound(what)
	case c == "QueueNameExists" || c == "QueueAlreadyExists":
		return queueExists(what)
	case loginCodes[c]:
		return out.Errf(out.ExitConnect, "QUEUE_AUTH", authHint, "%s: SQS refused the login: %v", what, err)
	case deniedCodes[c]:
		return deniedErr(what + ": " + err.Error())
	case strings.Contains(c, "QueueDeletedRecently"):
		return out.Errf(out.ExitRemote, "QUEUE_ERROR", "SQS needs 60 seconds after a queue is deleted before a queue of the same name can be made; run it again then",
			"%s: %v", what, err)
	case strings.Contains(c, "PurgeQueueInProgress"):
		return out.Errf(out.ExitRemote, "QUEUE_ERROR", "SQS lets a queue be purged once every 60 seconds, and the last purge may still be deleting; run it again then",
			"%s: %v", what, err)
	case strings.Contains(c, "Throttl") || c == "RequestThrottled" || c == "TooManyRequests":
		return out.Errf(out.ExitRemote, "QUEUE_ERROR", "SQS is asking komando to slow down; run it again in a moment", "%s: %v", what, err)
	case strings.HasPrefix(c, "InvalidAttribute") || c == "InvalidParameterValue" || c == "InvalidParameterCombination" || c == "UnsupportedOperation":
		return out.Errf(out.ExitRemote, "QUEUE_ERROR", "SQS refused a setting: check --config (SQS attribute names such as VisibilityTimeout=60), and that FIFO-only settings go to a queue whose name ends in .fifo",
			"%s: %v", what, err)
	}
	return out.Errf(out.ExitRemote, "QUEUE_ERROR", "read SQS's words above; `komando queue describe CONN QUEUE` shows the queue", "%s: %v", what, err)
}

func queueNotFound(name string) error {
	return out.Errf(out.ExitNotFound, "QUEUE_NOT_FOUND", "list queues with `komando queue list CONN`; a queue of another AWS account needs ?account=ID in the conn's URL, and the region is the URL's host",
		"no queue named %q", name)
}

func queueExists(name string) error {
	return out.Errf(out.ExitConflict, "QUEUE_EXISTS", "pick another name, or see it with `komando queue describe CONN "+name+"`", "queue %s already exists", name)
}
