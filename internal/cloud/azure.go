package cloud

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// Azure logins, read by komando itself (no az program): a service
// principal or workload identity from the standard AZURE_* variables, a
// token the Azure CLI saved and that has not expired yet, or the managed
// identity of the Azure machine komando runs on. komando keeps no token.

// ErrAzureLogin is wrapped by errors that an Azure login fixes.
var ErrAzureLogin = errors.New("no Azure login")

// Azure addresses. Tests point them at a local server; a program changes
// the sign-in host only with AZURE_AUTHORITY_HOST (https only), as the
// Azure SDKs do for the national clouds.
var (
	azureAuthority = "https://login.microsoftonline.com"
	azureIMDS      = "http://169.254.169.254/metadata/identity/oauth2/token"
	azureClient    = &http.Client{Timeout: 30 * time.Second}
	// the metadata address answers at once on Azure; elsewhere it is not
	// there, so a short wait, and never through a proxy
	azureIMDSClient = &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{
		Proxy: nil, DialContext: (&net.Dialer{Timeout: 2 * time.Second}).DialContext}}
)

var azureTenantID = regexp.MustCompile(`^[A-Za-z0-9.-]{1,100}$`)

// AzureToken is an access token for resource (an Azure AD resource such as
// https://vault.azure.net), from the first login that is there:
//
//  1. a service principal: AZURE_TENANT_ID, AZURE_CLIENT_ID and
//     AZURE_CLIENT_SECRET;
//  2. a workload identity (AKS): AZURE_TENANT_ID, AZURE_CLIENT_ID and
//     AZURE_FEDERATED_TOKEN_FILE;
//  3. a token for resource that the Azure CLI saved and that is still good
//     (az refreshes it; komando cannot without the CLI's own app id);
//  4. the managed identity of this Azure machine (AZURE_CLIENT_ID picks a
//     user-assigned one).
func AzureToken(ctx context.Context, resource string) (string, error) {
	tenant, client := os.Getenv("AZURE_TENANT_ID"), os.Getenv("AZURE_CLIENT_ID")
	if tenant != "" && client != "" {
		form := url.Values{"client_id": {client}}
		if s := os.Getenv("AZURE_CLIENT_SECRET"); s != "" {
			form.Set("client_secret", s)
			return azureClientToken(ctx, tenant, form, resource)
		}
		if f := os.Getenv("AZURE_FEDERATED_TOKEN_FILE"); f != "" {
			b, err := os.ReadFile(f)
			if err != nil {
				return "", fmt.Errorf("%w: AZURE_FEDERATED_TOKEN_FILE: %v", ErrAzureLogin, err)
			}
			form.Set("client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer")
			form.Set("client_assertion", strings.TrimSpace(string(b)))
			return azureClientToken(ctx, tenant, form, resource)
		}
	}
	if tok := azureCLIToken(resource, tenant, time.Now()); tok != "" {
		return tok, nil
	}
	tok, err := azureManagedIdentity(ctx, resource, client)
	if err != nil {
		return "", fmt.Errorf("%w: no service principal (AZURE_TENANT_ID, AZURE_CLIENT_ID, AZURE_CLIENT_SECRET), no Azure CLI token for %s that is still good, and %v",
			ErrAzureLogin, resource, err)
	}
	return tok, nil
}

// azureScope is the Azure AD v2 scope for a resource: ARM's resource ends
// in a slash, and its scope is then ".../" + "/.default", as the Azure CLI
// asks for it.
func azureScope(resource string) string { return resource + "/.default" }

// azureClientToken is the OAuth2 client-credentials call to Azure AD.
func azureClientToken(ctx context.Context, tenant string, form url.Values, resource string) (string, error) {
	if !azureTenantID.MatchString(tenant) {
		return "", fmt.Errorf("%w: AZURE_TENANT_ID is not a tenant id or domain", ErrAzureLogin)
	}
	authority := azureAuthority
	if h := os.Getenv("AZURE_AUTHORITY_HOST"); h != "" {
		if !strings.HasPrefix(h, "https://") {
			return "", fmt.Errorf("%w: AZURE_AUTHORITY_HOST must start with https://", ErrAzureLogin)
		}
		authority = strings.TrimSuffix(h, "/")
	}
	form.Set("grant_type", "client_credentials")
	form.Set("scope", azureScope(resource))
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, "POST", authority+"/"+tenant+"/oauth2/v2.0/token", strings.NewReader(form.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return azureTokenReply(azureClient.Do(req))
}

// azureManagedIdentity asks this machine's managed identity: App Service
// and Functions give IDENTITY_ENDPOINT and IDENTITY_HEADER, a VM, scale set
// or AKS node has the metadata address.
func azureManagedIdentity(ctx context.Context, resource, clientID string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	q := url.Values{"resource": {resource}}
	if clientID != "" {
		q.Set("client_id", clientID)
	}
	if ep, h := os.Getenv("IDENTITY_ENDPOINT"), os.Getenv("IDENTITY_HEADER"); ep != "" && h != "" {
		q.Set("api-version", "2019-08-01")
		req, err := http.NewRequestWithContext(ctx, "GET", ep+"?"+q.Encode(), nil)
		if err != nil {
			return "", err
		}
		req.Header.Set("X-IDENTITY-HEADER", h)
		return azureTokenReply(azureIMDSClient.Do(req))
	}
	q.Set("api-version", "2018-02-01")
	req, err := http.NewRequestWithContext(ctx, "GET", azureIMDS+"?"+q.Encode(), nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Metadata", "true")
	resp, err := azureIMDSClient.Do(req)
	if err != nil {
		return "", errors.New("no managed identity (komando is not running on Azure)")
	}
	tok, err := azureTokenReply(resp, nil)
	if err != nil {
		return "", fmt.Errorf("managed identity: %v", err)
	}
	return tok, nil
}

// azureTokenReply reads a token answer from Azure AD or a managed
// identity. Its error words name no secret.
func azureTokenReply(resp *http.Response, err error) (string, error) {
	if err != nil {
		return "", fmt.Errorf("%w: %v", ErrAzureLogin, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	var r struct {
		AccessToken string `json:"access_token"`
		Error       string `json:"error"`
		Description string `json:"error_description"`
		Message     string `json:"message"`
	}
	_ = json.Unmarshal(body, &r)
	if resp.StatusCode != http.StatusOK || r.AccessToken == "" {
		msg := firstOf(r.Description, r.Message, r.Error, resp.Status)
		msg, _, _ = strings.Cut(msg, "\r\n") // Azure AD adds trace and time lines
		msg, _, _ = strings.Cut(msg, "\n")
		return "", fmt.Errorf("%w: %s", ErrAzureLogin, msg)
	}
	return r.AccessToken, nil
}

// azureCLIToken is the Azure CLI's saved access token for resource with
// the most time left, or "". The CLI keeps them in msal_token_cache.json
// in its folder (AZURE_CONFIG_DIR, or ~/.azure) on Linux and macOS; on
// Windows that file is encrypted and is not read. A token with less than
// five minutes left is not used.
func azureCLIToken(resource, tenant string, now time.Time) string {
	dir := os.Getenv("AZURE_CONFIG_DIR")
	if dir == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return ""
		}
		dir = filepath.Join(home, ".azure")
	}
	b, err := os.ReadFile(filepath.Join(dir, "msal_token_cache.json"))
	if err != nil {
		return ""
	}
	var cache struct {
		AccessToken map[string]struct {
			Secret    string `json:"secret"`
			Target    string `json:"target"`
			Realm     string `json:"realm"`
			ExpiresOn string `json:"expires_on"`
		} `json:"AccessToken"`
	}
	if json.Unmarshal(b, &cache) != nil {
		return ""
	}
	prefix := strings.ToLower(strings.TrimSuffix(resource, "/") + "/")
	best, bestExp := "", now.Add(5*time.Minute).Unix()
	for _, t := range cache.AccessToken {
		exp, _ := strconv.ParseInt(t.ExpiresOn, 10, 64)
		if t.Secret == "" || exp <= bestExp || (tenant != "" && !strings.EqualFold(t.Realm, tenant)) {
			continue
		}
		for _, s := range strings.Fields(t.Target) {
			if strings.HasPrefix(strings.ToLower(s), prefix) {
				best, bestExp = t.Secret, exp
				break
			}
		}
	}
	return best
}

// AzureTenant is the tenant an Azure AD access token was given in (its tid
// claim), or "". The token is not checked: the service it goes to does.
func AzureTenant(token string) string {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return ""
	}
	b, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return ""
	}
	var c struct {
		Tid string `json:"tid"`
	}
	if json.Unmarshal(b, &c) != nil || !azureTenantID.MatchString(c.Tid) {
		return ""
	}
	return c.Tid
}

// AzureLoginHint says how to give komando an Azure login for resource.
// The Azure CLI saves a resource manager token at `az login` and renews it
// with each az command; a token for another resource only when asked.
func AzureLoginHint(resource string) string {
	cli := "`az account get-access-token --resource " + resource + "`"
	if strings.HasPrefix(resource, "https://management.") {
		cli = "`az login` (any later az command renews its token)"
	}
	return "set AZURE_TENANT_ID, AZURE_CLIENT_ID and AZURE_CLIENT_SECRET for a service principal, run komando on Azure with a managed identity, " +
		"or a person runs " + cli + ": komando uses the token the Azure CLI keeps while it lasts (about an hour)"
}
