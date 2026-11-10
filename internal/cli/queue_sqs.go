package cli

import (
	"context"
	"time"

	"github.com/sgnd/komando/internal/out"
	"github.com/sgnd/komando/internal/queuex"
	"github.com/sgnd/komando/internal/queuex/sqs"
	"github.com/sgnd/komando/internal/store"
)

// openQueue connects to a queue conn of any engine. An Amazon SQS conn
// logs in like komando's other AWS clients: with its aws_profile option
// (SSO, an assumed role or temporary keys, renewed by `komando login aws`),
// with the access key ID in its URL and the secret key from its password
// reference, or else with the usual chain (AWS_* variables, ~/.aws, the
// instance's role).
func openQueue(ctx context.Context, c *store.Conn, a *access, timeout time.Duration) (queuex.Queue, error) {
	t := a.Target
	if t.Kind.Name != "sqs" {
		return queuex.Open(ctx, t, a.Password, a.Dial, timeout, "komando/"+actor())
	}
	profile := awsProfile(c)
	switch {
	case profile == "" && t.User != "":
		return sqs.Open(ctx, t, a.Password, a.Dial, timeout, "komando/"+actor())
	case profile == "" && a.Password != "":
		return nil, out.Usage("the conn %s has a password reference but no access key ID: use sqs://ACCESS_KEY_ID@%s, or drop --password-ref to log in with your AWS profile", c.Name, t.Region)
	}
	cr, err := awsCredentials(ctx, profile)
	if err != nil {
		return nil, err
	}
	return sqs.OpenKeys(ctx, t, sqs.Keys{ID: cr.AccessKeyID, Secret: cr.SecretAccessKey, Token: cr.SessionToken}, a.Dial, timeout, "komando/"+actor())
}
