package cli

import (
	"cmp"
	"context"
	"errors"
	"net"
	"os"
	"regexp"
	"strings"

	"github.com/sgnd/komando/internal/cloud"
	"github.com/sgnd/komando/internal/out"
	"github.com/sgnd/komando/internal/registry"
	"github.com/sgnd/komando/internal/store"
)

// Cloud registries log in with the person's cloud login when the conn has
// no --password-ref of its own: Amazon ECR and Azure Container Registry
// logins last hours, so komando gets a fresh one each time and keeps none.

// azureToken gets an Azure AD access token, and gcpToken a Google one;
// tests replace them.
var (
	azureToken = cloud.AzureToken
	gcpToken   = cloud.GCPAccessToken
)

// googleRegistry matches Google Artifact Registry (REGION-docker.pkg.dev)
// and Container Registry (gcr.io and its regional hosts).
var googleRegistry = regexp.MustCompile(`^([a-z0-9-]+-docker\.pkg\.dev|((us|eu|asia)\.)?gcr\.io)$`)

// isGoogleRegistry says whether host is one; a port does not change it.
func isGoogleRegistry(host string) bool {
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	return googleRegistry.MatchString(strings.ToLower(host))
}

// acrHost is an Azure Container Registry host, with the Azure cloud's
// resource manager address (what `az acr login` exchanges a token for).
var acrHost = regexp.MustCompile(`^[a-z0-9]{5,50}\.azurecr\.(io|cn|us)$`)

var acrResources = map[string]string{
	"io": "https://management.core.windows.net/",
	"cn": "https://management.core.chinacloudapi.cn/",
	"us": "https://management.core.usgovcloudapi.net/",
}

// acrResource is the Azure AD resource for an ACR host, or "". A port
// (host:443) does not change which registry it is.
func acrResource(host string) string {
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	if m := acrHost.FindStringSubmatch(strings.ToLower(host)); m != nil {
		return acrResources[m[1]]
	}
	return ""
}

// cloudRegistryLogin logs rc in with a cloud login when c is a cloud
// registry without a --password-ref: Amazon ECR, Azure Container Registry,
// or Google Artifact Registry and Container Registry. Without any Google
// credentials, a Google registry is used without a login, so public
// images there stay readable.
func cloudRegistryLogin(ctx context.Context, c *store.Conn, host string, rc *registry.Client) error {
	if c.PasswordRef != "" {
		return nil
	}
	host = strings.TrimSuffix(host, ":443")
	if region := ecrRegion(host); region != "" {
		tok, err := ecrToken(ctx, cmp.Or(awsProfile(c), "default"), region)
		if err != nil {
			return err
		}
		rc.User, rc.Password = "AWS", tok
		return nil
	}
	if isGoogleRegistry(host) {
		if !rc.CheckedTLS() {
			return uncheckedCloudLogin("a Google", host)
		}
		tok, err := gcpToken(ctx)
		switch {
		case errors.Is(err, cloud.ErrGCPNoCredentials):
			return nil
		case err != nil:
			return out.Errf(out.ExitConnect, "GCP_LOGIN_REQUIRED",
				"a person runs `gcloud auth application-default login` again, or set GOOGLE_APPLICATION_CREDENTIALS to a service account key file; on Google Cloud the machine's service account is used",
				"%s: %v", host, err)
		}
		rc.User, rc.Password = "oauth2accesstoken", tok
		return nil
	}
	if res := acrResource(host); res != "" {
		if !rc.CheckedTLS() {
			return uncheckedCloudLogin("an Azure", host)
		}
		tok, err := azureToken(ctx, res)
		if err != nil {
			return azureErr(host, res, err)
		}
		if err := rc.ACRLogin(ctx, tok, cmp.Or(os.Getenv("AZURE_TENANT_ID"), cloud.AzureTenant(tok))); err != nil {
			var re *registry.Error
			if errors.As(err, &re) && (re.Status == 401 || re.Status == 403) {
				return out.Errf(out.ExitConnect, "REGISTRY_AUTH",
					"give the Azure login the AcrPull role on the registry (AcrPush to copy into it, AcrDelete to delete), or use a token or the admin user with --password-ref",
					"%s: %s", host, re.Message)
			}
			return registryErr(err)
		}
	}
	return nil
}

// uncheckedCloudLogin refuses to send a cloud login over plain http or
// to a registry whose certificate is not checked (?tls=skip-verify): the
// token is good for the whole cloud account, not only the registry.
func uncheckedCloudLogin(what, host string) error {
	return out.Usage("%s login goes to %s only over https with its certificate checked: take ?tls=false or ?tls=skip-verify out of the conn URL (?ca= trusts a private CA), or log in with a registry token and --password-ref", what, host)
}

// azureErr turns an Azure login error into komando's.
func azureErr(what, resource string, err error) error {
	if errors.Is(err, cloud.ErrAzureLogin) {
		// a person signs in, as with an expired AWS SSO login: agents ask
		return out.Errf(out.ExitConnect, "AZURE_LOGIN_REQUIRED", cloud.AzureLoginHint(resource), "%s: %v", what, err)
	}
	return out.Errf(out.ExitConnect, "AZURE_FAILED", "check that this computer reaches login.microsoftonline.com", "%s: %v", what, err)
}
