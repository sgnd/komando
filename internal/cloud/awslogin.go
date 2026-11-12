package cloud

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials/ssocreds"
	"github.com/aws/aws-sdk-go-v2/service/ssooidc"
	"github.com/aws/aws-sdk-go-v2/service/ssooidc/types"
)

// ssoOIDCEndpoint points the SSO login at a test server when set.
var ssoOIDCEndpoint = ""

// AWSProfileMissing reports whether err says the profile is not in
// ~/.aws/config or ~/.aws/credentials.
func AWSProfileMissing(err error) bool {
	var e config.SharedConfigProfileNotExistError
	return errors.As(err, &e)
}

// ErrAWSNotSSO says a profile has no IAM Identity Center (SSO) login:
// its keys come from ~/.aws/credentials or the environment, so there is
// nothing to log in to.
var ErrAWSNotSSO = errors.New("the profile does not use SSO")

// awsSharedConfig is a profile of ~/.aws/config and credentials, with the
// environment's file names, as LoadDefaultConfig uses them.
func awsSharedConfig(ctx context.Context, profile string) (config.SharedConfig, error) {
	return config.LoadSharedConfigProfile(ctx, profile, func(o *config.LoadSharedConfigOptions) {
		if f := os.Getenv("AWS_CONFIG_FILE"); f != "" {
			o.ConfigFiles = []string{f}
		}
		if f := os.Getenv("AWS_SHARED_CREDENTIALS_FILE"); f != "" {
			o.CredentialsFiles = []string{f}
		}
	})
}

// AWSSSO is the SSO login a profile uses: its own, or that of the profile
// its role is assumed from (role_arn with source_profile). key names the
// token's cache file.
type AWSSSO struct {
	Profile, StartURL, Region, key string
	scopes                         []string
}

// AWSProfileSSO is the SSO login behind a profile, or an error wrapping
// ErrAWSNotSSO when it has none.
func AWSProfileSSO(ctx context.Context, profile string) (AWSSSO, error) {
	if profile == "" {
		profile = "default"
	}
	sc, err := awsSharedConfig(ctx, profile)
	if err != nil {
		return AWSSSO{}, err
	}
	for p := &sc; p != nil; p = p.Source {
		if p.SSOSession != nil && p.SSOSession.SSOStartURL != "" && p.SSOSession.SSORegion != "" {
			return AWSSSO{p.Profile, p.SSOSession.SSOStartURL, p.SSOSession.SSORegion, p.SSOSessionName, []string{"sso:account:access"}}, nil
		}
		if p.SSOStartURL != "" && p.SSORegion != "" {
			return AWSSSO{p.Profile, p.SSOStartURL, p.SSORegion, p.SSOStartURL, nil}, nil
		}
	}
	return AWSSSO{}, fmt.Errorf("%w: profile %s has no sso_start_url or sso_session; its keys come from ~/.aws/credentials or the environment", ErrAWSNotSSO, profile)
}

// AWSSSOLogin logs a person in to the IAM Identity Center (SSO) of a
// profile, the way `aws sso login` does: the device-code flow. A profile
// that assumes a role from an SSO profile logs in to that one. show gets
// the page and the code to confirm there. The token is written to the same
// cache file the aws CLI uses (~/.aws/sso/cache), so the SDK, the aws CLI
// and komando share the login.
func AWSSSOLogin(ctx context.Context, profile string, show func(url, code string)) (string, error) {
	sso, err := AWSProfileSSO(ctx, profile)
	if err != nil {
		return "", err
	}
	startURL, region, key, scopes := sso.StartURL, sso.Region, sso.key, sso.scopes
	client := ssooidc.New(ssooidc.Options{Region: region}, func(o *ssooidc.Options) {
		if ssoOIDCEndpoint != "" {
			o.BaseEndpoint = aws.String(ssoOIDCEndpoint)
		}
	})
	reg, err := client.RegisterClient(ctx, &ssooidc.RegisterClientInput{ClientName: aws.String("komando"), ClientType: aws.String("public"), Scopes: scopes})
	if err != nil {
		return "", fmt.Errorf("SSO: %w", err)
	}
	dev, err := client.StartDeviceAuthorization(ctx, &ssooidc.StartDeviceAuthorizationInput{
		ClientId: reg.ClientId, ClientSecret: reg.ClientSecret, StartUrl: aws.String(startURL)})
	if err != nil {
		return "", fmt.Errorf("SSO: %w", err)
	}
	show(aws.ToString(firstPtr(dev.VerificationUriComplete, dev.VerificationUri)), aws.ToString(dev.UserCode))

	interval := time.Duration(max(dev.Interval, 1)) * time.Second
	deadline := time.Now().Add(time.Duration(max(dev.ExpiresIn, 60)) * time.Second)
	for {
		if time.Now().After(deadline) {
			return "", errors.New("SSO: the code expired before it was confirmed; run the login again")
		}
		select {
		case <-ctx.Done():
			return "", ctx.Err()
		case <-time.After(interval):
		}
		tok, err := client.CreateToken(ctx, &ssooidc.CreateTokenInput{
			ClientId: reg.ClientId, ClientSecret: reg.ClientSecret, DeviceCode: dev.DeviceCode,
			GrantType: aws.String("urn:ietf:params:oauth:grant-type:device_code")})
		var pending *types.AuthorizationPendingException
		var slow *types.SlowDownException
		switch {
		case errors.As(err, &pending):
			continue
		case errors.As(err, &slow):
			interval += 5 * time.Second
			continue
		case err != nil:
			return "", fmt.Errorf("SSO: %w", err)
		}
		path, err := ssocreds.StandardCachedTokenFilepath(key)
		if err != nil {
			return "", err
		}
		cache := map[string]any{
			"startUrl":              startURL,
			"region":                region,
			"accessToken":           aws.ToString(tok.AccessToken),
			"expiresAt":             time.Now().Add(time.Duration(tok.ExpiresIn) * time.Second).UTC().Format(time.RFC3339),
			"clientId":              aws.ToString(reg.ClientId),
			"clientSecret":          aws.ToString(reg.ClientSecret),
			"registrationExpiresAt": time.Unix(reg.ClientSecretExpiresAt, 0).UTC().Format(time.RFC3339),
		}
		if tok.RefreshToken != nil {
			cache["refreshToken"] = *tok.RefreshToken
		}
		b, _ := json.Marshal(cache)
		return path, writeTokenFile(path, b)
	}
}

// writeTokenFile replaces path with b, readable by this user only. The
// temporary file is new (never one that is already there, or a link to
// somewhere else), so the token is never in a file others can read.
func writeTokenFile(path string, b []byte) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	f, err := os.CreateTemp(dir, ".komando-*.tmp") // mode 0600
	if err != nil {
		return err
	}
	_, err = f.Write(b)
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		err = os.Rename(f.Name(), path)
	}
	if err != nil {
		os.Remove(f.Name())
	}
	return err
}

func firstPtr(v ...*string) *string {
	for _, p := range v {
		if p != nil && *p != "" {
			return p
		}
	}
	return nil
}
