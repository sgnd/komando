package cloud

import (
	"context"
	"encoding/base64"
	"fmt"
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

// GCPAccessToken is an OAuth access token from the application-default
// credentials, as gke-gcloud-auth-plugin gives GKE.
func GCPAccessToken(ctx context.Context) (string, error) {
	creds, err := gcpCredentials(ctx)
	if err != nil {
		return "", fmt.Errorf("%w: %v", ErrGCPLogin, err)
	}
	t, err := creds.TokenSource.Token()
	if err != nil {
		return "", fmt.Errorf("%w: %v", ErrGCPLogin, err)
	}
	return t.AccessToken, nil
}
