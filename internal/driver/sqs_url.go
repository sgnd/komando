package driver

import (
	"net/url"
	"regexp"
	"strings"

	"github.com/sgnd/komando/internal/out"
)

var (
	awsRegion  = regexp.MustCompile(`^[a-z]{2}(-[a-z0-9]+)+-[0-9]+$`)
	awsAccount = regexp.MustCompile(`^[0-9]{12}$`)
)

// parseSQS reads sqs://[ACCESS_KEY_ID@]REGION for Amazon SQS
// (docs/features/queues.md). The conn is one region of one AWS account;
// queues are given to each command. The login is the person's AWS one
// (--option aws_profile, or the usual chain), or the access key ID in the
// URL with the secret key from --password-ref. Options:
//
//	?endpoint=URL   another SQS endpoint: an emulator (LocalStack, moto),
//	                a VPC endpoint
//	?account=ID     the 12-digit account that owns the queues, when it is
//	                not the login's own
//	?insecure=1     accept an http:// endpoint across the network
func parseSQS(u *url.URL, t Target) (Target, error) {
	t.Region = u.Host
	if !awsRegion.MatchString(t.Region) {
		return Target{}, out.Usage("sqs URL is sqs://REGION, such as sqs://eu-west-1 (the AWS region; queues are given to each command), not %q", u.Host)
	}
	if p := strings.Trim(u.Path, "/"); p != "" {
		return Target{}, out.Usage("an sqs URL names a region only: drop %q from it (queues are given to each command)", "/"+p)
	}
	t.User = u.User.Username()
	q := u.Query()
	if err := onlyOptions(q, "sqs", "endpoint", "account", "insecure"); err != nil {
		return Target{}, err
	}
	def := "https://sqs." + t.Region + ".amazonaws.com"
	if strings.HasPrefix(t.Region, "cn-") {
		def += ".cn"
	}
	if err := endpointOf(q, "sqs", def, &t); err != nil {
		return Target{}, err
	}
	if t.Path != "" {
		return Target{}, out.Usage("the sqs endpoint is a server only, such as http://localhost:4566: drop %q from it", "/"+t.Path)
	}
	if t.Account = q.Get("account"); t.Account != "" && !awsAccount.MatchString(t.Account) {
		return Target{}, out.Usage("sqs account option is the 12-digit AWS account ID, not %q", t.Account)
	}
	if v := q.Get("insecure"); v != "" && v != "1" {
		return Target{}, out.Usage("sqs insecure option can only be 1")
	}
	return t, nil
}
