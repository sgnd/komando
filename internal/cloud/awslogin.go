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

// AWSSSOLogin logs a person in to the IAM Identity Center (SSO) of a
// profile, the way `aws sso login` does: the device-code flow. show gets the
// page and the code to confirm there. The token is written to the same
// cache file the aws CLI uses (~/.aws/sso/cache), so the SDK, the aws CLI
// and komando share the login.
func AWSSSOLogin(ctx context.Context, profile string, show func(url, code string)) (string, error) {
	if profile == "" {
		profile = "default"
	}
	sc, err := config.LoadSharedConfigProfile(ctx, profile, func(o *config.LoadSharedConfigOptions) {
		// the environment's file names, as LoadDefaultConfig uses them
		if f := os.Getenv("AWS_CONFIG_FILE"); f != "" {
			o.ConfigFiles = []string{f}
		}
		if f := os.Getenv("AWS_SHARED_CREDENTIALS_FILE"); f != "" {
			o.CredentialsFiles = []string{f}
		}
	})
	if err != nil {
		return "", err
	}
	startURL, region, key := sc.SSOStartURL, sc.SSORegion, sc.SSOStartURL
	var scopes []string
	if sc.SSOSession != nil {
		startURL, region, key = sc.SSOSession.SSOStartURL, sc.SSOSession.SSORegion, sc.SSOSessionName
		scopes = []string{"sso:account:access"}
	}
	if startURL == "" || region == "" {
		return "", fmt.Errorf("profile %s does not use SSO (no sso_start_url); its keys come from ~/.aws/credentials or the environment", profile)
	}
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
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			return "", err
		}
		tmp := path + ".tmp"
		if err := os.WriteFile(tmp, b, 0o600); err != nil {
			return "", err
		}
		return path, os.Rename(tmp, path)
	}
}

func firstPtr(v ...*string) *string {
	for _, p := range v {
		if p != nil && *p != "" {
			return p
		}
	}
	return nil
}
