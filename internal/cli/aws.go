package cli

import (
	"context"
	"errors"
	"net"
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
// login a person renews. Only an SSO profile can be renewed with `komando
// login aws`; a profile without SSO lacks keys, and says where they go.
func awsErr(profile string, err error) error {
	if profile == "" {
		profile = "default"
	}
	switch {
	case errors.Is(err, context.Canceled):
		return toErr(err) // Ctrl-C: CANCELLED
	case cloud.AWSProfileMissing(err):
		return out.Errf(out.ExitNotFound, "AWS_PROFILE_NOT_FOUND", "add the profile to ~/.aws/config (or fix --option aws_profile)",
			"there is no AWS profile %q", profile)
	case errors.Is(err, cloud.ErrAWSNotSSO):
		return out.Errf(out.ExitConnect, "AWS_FAILED", awsKeysHint(profile), "AWS profile %s has no SSO login (no sso_start_url or sso_session)", profile)
	case errors.Is(err, cloud.ErrAWSLogin):
		if _, serr := cloud.AWSProfileSSO(context.Background(), profile); errors.Is(serr, cloud.ErrAWSNotSSO) {
			return out.Errf(out.ExitConnect, "AWS_FAILED", awsKeysHint(profile), "AWS profile %s has no keys and no SSO login: %v", profile, err)
		}
		// a person logs in, like VPN MFA: agents ask for it
		return out.Errf(out.ExitConnect, "AWS_LOGIN_REQUIRED", "a person runs `komando login aws --profile "+profile+"` once, then try again",
			"AWS profile %s: %v", profile, err)
	}
	return out.Errf(out.ExitConnect, "AWS_FAILED", "check the profile in ~/.aws/config", "AWS profile %s: %v", profile, err)
}

// awsKeysHint is the next step for a profile without SSO: there is nothing
// to log in to, its keys are missing.
func awsKeysHint(profile string) string {
	return "this profile has no SSO login, so `komando login aws` cannot renew it: put its keys under [" + profile +
		"] in ~/.aws/credentials (aws_access_key_id, aws_secret_access_key), or use an SSO profile (--option aws_profile=NAME)"
}

var ecrHost = regexp.MustCompile(`^\d+\.dkr\.ecr(-fips)?\.([a-z0-9-]+)\.amazonaws\.com(\.cn)?$`)

// ecrRegion is the region of an Amazon ECR registry host, or "". A port
// (host:443) does not change which registry it is.
func ecrRegion(host string) string {
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
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
