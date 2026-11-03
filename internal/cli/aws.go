package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"net"
	"os/exec"
	"regexp"
	"strings"
	"time"

	"github.com/sgnd/komando/internal/out"
	"github.com/sgnd/komando/internal/store"
)

// AWS logins (SSO, assumed roles, temporary keys) come from the aws CLI, so
// they work exactly as the person has set them up: a conn names the profile
// with `--option aws_profile=NAME` ("default" for the usual chain).

type awsCreds struct {
	AccessKeyID     string `json:"AccessKeyId"`
	SecretAccessKey string `json:"SecretAccessKey"`
	SessionToken    string `json:"SessionToken"`
}

// awsProfile is the conn's aws_profile option, or "".
func awsProfile(c *store.Conn) string { return c.Options["aws_profile"] }

// runAWS runs the aws CLI with the profile and returns its stdout.
func runAWS(ctx context.Context, profile string, args ...string) ([]byte, error) {
	if _, err := exec.LookPath("aws"); err != nil {
		return nil, out.Errf(out.ExitNotFound, "AWS_CLI_MISSING", "install the AWS CLI v2 (https://aws.amazon.com/cli/) and log in with it once",
			"conns with aws_profile need the aws CLI on this computer")
	}
	if profile != "" && profile != "default" {
		args = append(args, "--profile", profile)
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "aws", args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err != nil {
		msg := strings.TrimSpace(stderr.String())
		hint := "check the profile with `aws sts get-caller-identity --profile " + profile + "`"
		if strings.Contains(msg, "sso") || strings.Contains(msg, "SSO") || strings.Contains(msg, "expired") {
			// a person logs in, like VPN MFA: agents ask for it
			hint = "a person runs `aws sso login --profile " + profile + "` once, then try again"
		}
		return nil, out.Errf(out.ExitConnect, "AWS_LOGIN_REQUIRED", hint, "aws %s: %s", args[0], firstNonEmpty(msg, err.Error()))
	}
	return stdout.Bytes(), nil
}

// awsCredentials asks the aws CLI for the profile's current keys.
func awsCredentials(ctx context.Context, profile string) (awsCreds, error) {
	b, err := runAWS(ctx, profile, "configure", "export-credentials", "--format", "process")
	if err != nil {
		return awsCreds{}, err
	}
	var c awsCreds
	if json.Unmarshal(b, &c) != nil || c.AccessKeyID == "" {
		return awsCreds{}, out.Errf(out.ExitConnect, "AWS_LOGIN_REQUIRED", "check the profile with `aws configure list`", "the aws CLI gave no credentials for profile %q", profile)
	}
	return c, nil
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

// ecrToken gets a fresh ECR login (it lasts 12 hours) from the aws CLI.
func ecrToken(ctx context.Context, profile, region string) (string, error) {
	b, err := runAWS(ctx, profile, "ecr", "get-login-password", "--region", region)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(b)), nil
}
