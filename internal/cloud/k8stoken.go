package cloud

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials/stscreds"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/aws/smithy-go/middleware"
	smithyhttp "github.com/aws/smithy-go/transport/http"
)

// EKSToken is a bearer token for an Amazon EKS cluster, made the way
// `aws eks get-token` and aws-iam-authenticator make it: a presigned STS
// GetCallerIdentity URL naming the cluster, valid for 15 minutes. roleARN,
// when set, is assumed first.
func EKSToken(ctx context.Context, profile, region, cluster, roleARN string) (string, error) {
	cfg, err := AWSConfig(ctx, profile, region)
	if err != nil {
		return "", err
	}
	if roleARN != "" {
		cfg.Credentials = aws.NewCredentialsCache(stscreds.NewAssumeRoleProvider(sts.NewFromConfig(cfg), roleARN))
	}
	if cfg.Region == "" {
		cfg.Region = "us-east-1"
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	p := sts.NewPresignClient(sts.NewFromConfig(cfg))
	req, err := p.PresignGetCallerIdentity(ctx, &sts.GetCallerIdentityInput{}, func(o *sts.PresignOptions) {
		o.ClientOptions = append(o.ClientOptions, func(so *sts.Options) {
			so.APIOptions = append(so.APIOptions,
				smithyhttp.AddHeaderValue("X-K8s-Aws-Id", cluster),
				func(stack *middleware.Stack) error {
					return stack.Build.Add(middleware.BuildMiddlewareFunc("komandoEKSExpiry",
						func(ctx context.Context, in middleware.BuildInput, next middleware.BuildHandler) (middleware.BuildOutput, middleware.Metadata, error) {
							if r, ok := in.Request.(*smithyhttp.Request); ok {
								q := r.URL.Query()
								q.Set("X-Amz-Expires", "60")
								r.URL.RawQuery = q.Encode()
							}
							return next.HandleBuild(ctx, in)
						}), middleware.After)
				})
		})
	})
	if err != nil {
		return "", awsErr(err)
	}
	return "k8s-aws-v1." + base64.RawURLEncoding.EncodeToString([]byte(req.URL)), nil
}

// ErrGCPNoCredentials is wrapped, with ErrGCPLogin, when no Google
// credentials were found at all (not one that failed).
var ErrGCPNoCredentials = errors.New("none found")

// GCPAccessToken is an OAuth access token from the application-default
// credentials, as gke-gcloud-auth-plugin gives GKE and `gcloud auth
// print-access-token` a registry login.
func GCPAccessToken(ctx context.Context) (string, error) {
	creds, err := gcpCredentials(ctx)
	if err != nil {
		if gcpCredentialsSet() {
			// a key file or gcloud login that is there but broken
			return "", fmt.Errorf("%w: %v", ErrGCPLogin, err)
		}
		return "", fmt.Errorf("%w (%w): %v", ErrGCPLogin, ErrGCPNoCredentials, err)
	}
	t, err := creds.TokenSource.Token()
	if err != nil {
		return "", fmt.Errorf("%w: %v", ErrGCPLogin, err)
	}
	return t.AccessToken, nil
}

// gcpCredentialsSet says whether Google credentials are set up on this
// computer: GOOGLE_APPLICATION_CREDENTIALS, or the file that `gcloud auth
// application-default login` writes, where the Google library looks for it.
// Then a lookup that fails means they are broken, not missing.
func gcpCredentialsSet() bool {
	if os.Getenv("GOOGLE_APPLICATION_CREDENTIALS") != "" {
		return true
	}
	var dir string
	if runtime.GOOS == "windows" {
		dir = os.Getenv("APPDATA")
	} else if dir = os.Getenv("HOME"); dir == "" {
		dir, _ = os.UserHomeDir()
	}
	if runtime.GOOS != "windows" {
		dir = filepath.Join(dir, ".config")
	}
	_, err := os.Stat(filepath.Join(dir, "gcloud", "application_default_credentials.json"))
	return err == nil
}
