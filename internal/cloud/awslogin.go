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
	awssso "github.com/aws/aws-sdk-go-v2/service/sso"
	"github.com/aws/aws-sdk-go-v2/service/ssooidc"
	"github.com/aws/aws-sdk-go-v2/service/ssooidc/types"

	"github.com/sgnd/komando/internal/tmpclean"
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
// files, when given, are the config and credentials file instead.
func awsSharedConfig(ctx context.Context, profile string, files ...string) (config.SharedConfig, error) {
	return config.LoadSharedConfigProfile(ctx, profile, func(o *config.LoadSharedConfigOptions) {
		if f := os.Getenv("AWS_CONFIG_FILE"); f != "" {
			o.ConfigFiles = []string{f}
		}
		if f := os.Getenv("AWS_SHARED_CREDENTIALS_FILE"); f != "" {
			o.CredentialsFiles = []string{f}
		}
		if len(files) == 2 {
			o.ConfigFiles, o.CredentialsFiles = files[:1], files[1:]
		}
	})
}

// AWSSSO is the SSO login a profile uses: its own, or that of the profile
// its role is assumed from (role_arn with source_profile). key names the
// token's cache file.
type AWSSSO struct {
	Profile, StartURL, Region, key string
	scopes                         []string
	// Role is the profile's role_arn, also when there is no SSO behind it
	Role string
}

// AWSProfileSSO is the SSO login behind a profile, or an error wrapping
// ErrAWSNotSSO when it has none.
// files, when given, are the config and credentials file to read (import).
func AWSProfileSSO(ctx context.Context, profile string, files ...string) (AWSSSO, error) {
	if profile == "" {
		profile = "default"
	}
	sc, err := awsSharedConfig(ctx, profile, files...)
	if err != nil {
		return AWSSSO{}, err
	}
	for p := &sc; p != nil; p = p.Source {
		if p.SSOSession != nil && p.SSOSession.SSOStartURL != "" && p.SSOSession.SSORegion != "" {
			return AWSSSO{p.Profile, p.SSOSession.SSOStartURL, p.SSOSession.SSORegion, p.SSOSessionName, []string{"sso:account:access"}, sc.RoleARN}, nil
		}
		if p.SSOStartURL != "" && p.SSORegion != "" {
			return AWSSSO{p.Profile, p.SSOStartURL, p.SSORegion, p.SSOStartURL, nil, sc.RoleARN}, nil
		}
	}
	return AWSSSO{Role: sc.RoleARN}, fmt.Errorf("%w: profile %s has no sso_start_url or sso_session; its keys come from ~/.aws/credentials or the environment", ErrAWSNotSSO, profile)
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
	tmpclean.Sweep(dir, ".komando-", ".tmp")       // a run killed before its rename
	f, err := os.CreateTemp(dir, ".komando-*.tmp") // mode 0600
	if err != nil {
		return err
	}
	defer tmpclean.Add(f.Name())()
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

// ssoEndpoint points the SSO logout at a test server when set.
var ssoEndpoint = ""

// AWSLogin is an IAM Identity Center (SSO) login saved in the aws CLI's
// cache (~/.aws/sso/cache): by komando login aws, aws sso login or an
// SDK. It never holds the token itself.
type AWSLogin struct {
	Profiles   []string  `json:"profiles"`              // the ~/.aws/config profiles that use it
	StartURL   string    `json:"sso_start_url"`         // the sign-in page
	Region     string    `json:"sso_region"`            // where IAM Identity Center runs
	Session    string    `json:"sso_session,omitempty"` // the [sso-session NAME] it belongs to
	LoggedInAt time.Time `json:"logged_in_at,omitzero"` // when the token was saved
	ExpiresAt  time.Time `json:"expires_at"`            // when the token runs out
	// Renews: it has a refresh token, so the SDKs and komando get a new
	// token after expires_at, for as long as the AWS session lasts
	Renews bool   `json:"renews,omitempty"`
	File   string `json:"-"`
}

// ssoCache is the part of a cache file komando reads.
type ssoCache struct {
	StartURL              string `json:"startUrl"`
	Region                string `json:"region"`
	AccessToken           string `json:"accessToken"`
	ExpiresAt             string `json:"expiresAt"`
	RefreshToken          string `json:"refreshToken"`
	RegistrationExpiresAt string `json:"registrationExpiresAt"`
}

// readSSOCache reads the cache file of sso; ok is false when there is no
// login that still works (no file, no token, run out and not renewable).
func readSSOCache(sso AWSSSO, now time.Time) (AWSLogin, ssoCache, bool) {
	path, err := ssocreds.StandardCachedTokenFilepath(sso.key)
	if err != nil {
		return AWSLogin{}, ssoCache{}, false
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return AWSLogin{}, ssoCache{}, false
	}
	var c ssoCache
	if json.Unmarshal(b, &c) != nil || c.AccessToken == "" {
		return AWSLogin{}, ssoCache{}, false
	}
	exp, _ := time.Parse(time.RFC3339, c.ExpiresAt)
	reg, _ := time.Parse(time.RFC3339, c.RegistrationExpiresAt)
	renews := c.RefreshToken != "" && now.Before(reg)
	if !now.Before(exp) && !renews {
		return AWSLogin{}, ssoCache{}, false
	}
	l := AWSLogin{Profiles: []string{sso.Profile}, StartURL: cmpOr(c.StartURL, sso.StartURL), Region: cmpOr(c.Region, sso.Region),
		ExpiresAt: exp.UTC(), Renews: renews, File: path}
	if sso.scopes != nil {
		l.Session = sso.key // an sso-session: its cache file is named after it
	}
	if fi, err := os.Stat(path); err == nil {
		l.LoggedInAt = fi.ModTime().UTC()
	}
	return l, c, true
}

func cmpOr(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

// AWSSSOLogins are the SSO logins that still work among the given
// profiles, one per cache file with every profile that uses it. It reads
// only files on this computer.
func AWSSSOLogins(ctx context.Context, profiles []string) []AWSLogin {
	var ls []AWSLogin
	at := map[string]int{}
	now := time.Now()
	for _, p := range profiles {
		sso, err := AWSProfileSSO(ctx, p)
		if err != nil {
			continue
		}
		l, _, ok := readSSOCache(sso, now)
		if !ok {
			continue
		}
		if i, seen := at[l.File]; seen {
			ls[i].Profiles = append(ls[i].Profiles, p)
			continue
		}
		at[l.File] = len(ls)
		l.Profiles = []string{p}
		ls = append(ls, l)
	}
	return ls
}

// AWSSSOLogout ends the SSO login a profile uses, as `aws sso logout`
// does: IAM Identity Center is told to end the token (revoked; best
// effort, it needs the network), then its cache file is deleted. ok is
// false when the profile has no login that still works.
func AWSSSOLogout(ctx context.Context, profile string) (l AWSLogin, revoked, ok bool, err error) {
	sso, err := AWSProfileSSO(ctx, profile)
	if err != nil {
		return AWSLogin{}, false, false, err
	}
	l, c, ok := readSSOCache(sso, time.Now())
	if !ok {
		return AWSLogin{}, false, false, nil
	}
	l.Profiles = []string{profile}
	rctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	client := sso.client()
	_, lerr := client.Logout(rctx, &awssso.LogoutInput{AccessToken: aws.String(c.AccessToken)})
	if err := os.Remove(l.File); err != nil && !os.IsNotExist(err) {
		return l, lerr == nil, true, err
	}
	return l, lerr == nil, true, nil
}

// client is the SSO portal client of sso's region.
func (s AWSSSO) client() *awssso.Client {
	return awssso.New(awssso.Options{Region: s.Region}, func(o *awssso.Options) {
		if ssoEndpoint != "" {
			o.BaseEndpoint = aws.String(ssoEndpoint)
		}
	})
}
