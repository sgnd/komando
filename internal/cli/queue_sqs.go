package cli

import (
	"context"
	"net"
	"time"

	"github.com/sgnd/komando/internal/out"
	"github.com/sgnd/komando/internal/queuex"
	"github.com/sgnd/komando/internal/queuex/sqs"
	"github.com/sgnd/komando/internal/store"
)

// loopback reports an address on this computer (localhost, 127.0.0.1, ::1).
func loopback(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		host = addr
	}
	ip := net.ParseIP(host)
	return host == "localhost" || ip != nil && ip.IsLoopback()
}

// openQueue connects to a queue conn of any engine. An Amazon SQS conn
// logs in like komando's other AWS clients: with its aws_profile option
// (SSO, an assumed role or temporary keys, renewed by `komando login aws`),
// with the access key ID in its URL and the secret key from its password
// reference, with any key for an emulator at localhost, or else with the
// usual chain (AWS_* variables, ~/.aws, the instance's role).
func openQueue(cl *call, ctx context.Context, c *store.Conn, a *access, timeout time.Duration) (queuex.Queue, error) {
	t := a.Target
	if t.Kind.Name != "sqs" {
		return queuex.Open(ctx, t, a.Password, a.Dial, timeout, "komando/"+actor(cl))
	}
	profile := awsProfile(c)
	switch {
	case profile == "" && t.User != "":
		return sqs.Open(ctx, t, a.Password, a.Dial, timeout, "komando/"+actor(cl))
	case profile == "" && a.Password != "":
		return nil, out.Usage("the conn %s has a password reference but no access key ID: use sqs://ACCESS_KEY_ID@%s, or drop the password reference (`komando conn edit %s --unset password-ref`) to log in with your AWS profile", c.Name, t.Region, c.Name)
	case profile == "" && loopback(t.Address):
		// an emulator at localhost (LocalStack, moto) takes any key;
		// the AWS chain would first wait seconds for an EC2 instance role
		return sqs.OpenKeys(ctx, t, sqs.Keys{ID: "test", Secret: "test"}, a.Dial, timeout, "komando/"+actor(cl))
	}
	cr, err := awsCredentials(ctx, profile)
	if err != nil {
		return nil, err
	}
	return sqs.OpenKeys(ctx, t, sqs.Keys{ID: cr.AccessKeyID, Secret: cr.SecretAccessKey, Token: cr.SessionToken}, a.Dial, timeout, "komando/"+actor(cl))
}
