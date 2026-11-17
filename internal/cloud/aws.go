// Package cloud holds komando's own clients for cloud and secret-manager
// APIs, so no vendor CLI (aws, gcloud, vault) has to be installed
// (docs/design/code-layout.md). Logins stay with the person: komando reads the
// credentials they already have and never stores them.
package cloud

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awshttp "github.com/aws/aws-sdk-go-v2/aws/transport/http"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials/ssocreds"
	"github.com/aws/aws-sdk-go-v2/service/ecr"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"

	"github.com/sgnd/komando/internal/transport"
)

// ErrAWSLogin is wrapped by errors that a person fixes by logging in again
// (an expired or missing SSO session).
var ErrAWSLogin = errors.New("AWS login required")

// AWSConfig is the SDK configuration for a profile: "" or "default" is the
// usual chain (environment, ~/.aws/config and credentials, SSO, roles,
// instance metadata). region overrides the profile's region when set.
func AWSConfig(ctx context.Context, profile, region string) (aws.Config, error) {
	stsEndpointFromGlobal()
	var opts []func(*config.LoadOptions) error
	if profile != "" && profile != "default" {
		opts = append(opts, config.WithSharedConfigProfile(profile))
	}
	if region != "" {
		opts = append(opts, config.WithRegion(region))
	}
	cfg, err := loadAWS(ctx, opts...)
	if err != nil {
		return aws.Config{}, awsErr(err)
	}
	if err := checkAWSTokenFile(cfg); err != nil {
		return aws.Config{}, err
	}
	return cfg, nil
}

// loadAWS is config.LoadDefaultConfig with komando's transport: the SDK's
// own client would take a proxy from an AI agent's HTTPS_PROXY and add
// its AWS_CA_BUNDLE to the CAs, and so read secret values, SSO tokens and
// temporary keys. For an agent, AWS_CA_BUNDLE is ignored; a person's, or
// the ca_bundle of a profile in their ~/.aws/config, still counts.
func loadAWS(ctx context.Context, opts ...func(*config.LoadOptions) error) (aws.Config, error) {
	if transport.EnvDistrusted() {
		_ = os.Unsetenv("AWS_CA_BUNDLE")
	}
	defer agentAWSEnv()()
	hc := awshttp.NewBuildableClient().WithTransportOptions(func(tr *http.Transport) { tr.Proxy = transport.Proxy() })
	return config.LoadDefaultConfig(ctx, append(opts, config.WithHTTPClient(hc))...)
}

// stsEndpointFromGlobal makes AWS_ENDPOINT_URL cover STS too. The SDK
// applies it to every client but the STS one it makes for a role profile
// (role_arn), so with an emulator (LocalStack, moto) the role's AssumeRole
// went to the real AWS with the source access key. AWS_ENDPOINT_URL_STS,
// when set, still wins.
func stsEndpointFromGlobal() {
	if transport.EnvDistrusted() {
		return // an AI agent's endpoint variables are not followed at all (agentAWSEnv)
	}
	if e := os.Getenv("AWS_ENDPOINT_URL"); e != "" && os.Getenv("AWS_ENDPOINT_URL_STS") == "" {
		os.Setenv("AWS_ENDPOINT_URL_STS", e)
	}
}

// AWSCredentials are the profile's current keys.
func AWSCredentials(ctx context.Context, profile string) (aws.Credentials, error) {
	cfg, err := AWSConfig(ctx, profile, "")
	if err != nil {
		return aws.Credentials{}, err
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	c, err := cfg.Credentials.Retrieve(ctx)
	if err != nil {
		return aws.Credentials{}, awsErr(err)
	}
	return c, nil
}

// AWSProfileAccess is what a profile in the given config and credentials
// files gives: its current keys, region and custom endpoint ("" for AWS).
func AWSProfileAccess(ctx context.Context, profile, configFile, credsFile string) (aws.Credentials, string, string, error) {
	stsEndpointFromGlobal()
	opts := []func(*config.LoadOptions) error{config.WithSharedConfigProfile(profile),
		config.WithSharedConfigFiles([]string{configFile}), config.WithSharedCredentialsFiles([]string{credsFile})}
	cfg, err := loadAWS(ctx, opts...)
	if err != nil {
		return aws.Credentials{}, "", "", awsErr(err)
	}
	if err := checkAWSTokenFile(cfg); err != nil {
		return aws.Credentials{}, "", "", err
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	c, err := cfg.Credentials.Retrieve(ctx)
	if err != nil {
		return aws.Credentials{}, "", "", awsErr(err)
	}
	return c, cfg.Region, aws.ToString(cfg.BaseEndpoint), nil
}

// AWSSecret reads a Secrets Manager secret (name or ARN) as text.
func AWSSecret(ctx context.Context, id string) (string, error) {
	cfg, err := AWSConfig(ctx, "", "")
	if err != nil {
		return "", err
	}
	if arnRegion := arnPart(id, 3); arnRegion != "" {
		cfg.Region = arnRegion
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	o, err := secretsmanager.NewFromConfig(cfg).GetSecretValue(ctx, &secretsmanager.GetSecretValueInput{SecretId: aws.String(id)})
	if err != nil {
		return "", awsErr(err)
	}
	if o.SecretString != nil {
		return *o.SecretString, nil
	}
	return string(o.SecretBinary), nil
}

// ECRToken is a registry password for Amazon ECR (it lasts 12 hours).
func ECRToken(ctx context.Context, profile, region string) (string, error) {
	cfg, err := AWSConfig(ctx, profile, region)
	if err != nil {
		return "", err
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	o, err := ecr.NewFromConfig(cfg).GetAuthorizationToken(ctx, &ecr.GetAuthorizationTokenInput{})
	if err != nil {
		return "", awsErr(err)
	}
	if len(o.AuthorizationData) == 0 || o.AuthorizationData[0].AuthorizationToken == nil {
		return "", errors.New("ECR gave no login")
	}
	b, err := base64.StdEncoding.DecodeString(*o.AuthorizationData[0].AuthorizationToken)
	if err != nil {
		return "", fmt.Errorf("ECR login: %w", err)
	}
	_, pw, ok := strings.Cut(string(b), ":") // "AWS:<password>"
	if !ok {
		return "", errors.New("komando cannot read the ECR login AWS sent")
	}
	return pw, nil
}

// arnPart is field i of an ARN (arn:partition:service:region:account:...).
func arnPart(s string, i int) string {
	if !strings.HasPrefix(s, "arn:") {
		return ""
	}
	p := strings.Split(s, ":")
	if len(p) <= i {
		return ""
	}
	return p[i]
}

// awsErr keeps the SDK's message (it names no secret) and marks the ones a
// login fixes.
func awsErr(err error) error {
	var tok *ssocreds.InvalidTokenError
	msg := err.Error()
	if errors.As(err, &tok) || strings.Contains(msg, "SSO session") || strings.Contains(msg, "token has expired") ||
		strings.Contains(msg, "failed to refresh cached credentials") || strings.Contains(msg, "no EC2 IMDS role found") ||
		strings.Contains(msg, "failed to retrieve credentials") {
		return fmt.Errorf("%w: %s", ErrAWSLogin, msg)
	}
	return err
}
