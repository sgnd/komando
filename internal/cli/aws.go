package cli

import (
	"context"
	"errors"
	"regexp"

	"github.com/sgnd/komando/internal/cloud"
	"github.com/sgnd/komando/internal/out"
	"github.com/sgnd/komando/internal/store"
)

// AWS logins (SSO, assumed roles, temporary keys) are read from the
// person's ~/.aws profile by komando itself (no aws CLI): a conn names the
// profile with `--option aws_profile=NAME` ("default" for the usual chain).
// `komando login aws` renews an SSO login.

type awsCreds struct {
	AccessKeyID, SecretAccessKey, SessionToken string
}

// awsProfile is the conn's aws_profile option, or "".
func awsProfile(c *store.Conn) string { return c.Options["aws_profile"] }

// awsCredentials are the profile's current keys.
func awsCredentials(ctx context.Context, profile string) (awsCreds, error) {
	c, err := cloud.AWSCredentials(ctx, profile)
	if err != nil {
		return awsCreds{}, awsErr(profile, err)
	}
	return awsCreds{c.AccessKeyID, c.SecretAccessKey, c.SessionToken}, nil
}

// awsErr turns an AWS SDK error into komando's: a missing profile, or a
// login a person renews.
func awsErr(profile string, err error) error {
	if profile == "" {
		profile = "default"
	}
	switch {
	case cloud.AWSProfileMissing(err):
		return out.Errf(out.ExitNotFound, "AWS_PROFILE_NOT_FOUND", "add the profile to ~/.aws/config (or fix --option aws_profile)",
			"there is no AWS profile %q", profile)
	case errors.Is(err, cloud.ErrAWSLogin):
		// a person logs in, like VPN MFA: agents ask for it
		return out.Errf(out.ExitConnect, "AWS_LOGIN_REQUIRED", "a person runs `komando login aws --profile "+profile+"` once, then try again",
			"AWS profile %s: %v", profile, err)
	}
	return out.Errf(out.ExitConnect, "AWS_FAILED", "check the profile in ~/.aws/config", "AWS profile %s: %v", profile, err)
}

var ecrHost = regexp.MustCompile(`^\d+\.dkr\.ecr(-fips)?\.([a-z0-9-]+)\.amazonaws\.com(\.cn)?$`)

// ecrRegion is the region of an Amazon ECR registry host, or "".
func ecrRegion(host string) string {
	if m := ecrHost.FindStringSubmatch(host); m != nil {
		return m[2]
	}
	return ""
}

// ecrToken gets a fresh ECR login (it lasts 12 hours).
func ecrToken(ctx context.Context, profile, region string) (string, error) {
	tok, err := cloud.ECRToken(ctx, profile, region)
	if err != nil {
		return "", awsErr(profile, err)
	}
	return tok, nil
}
