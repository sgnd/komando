package cloud

import (
	"net/url"
	"os"
	"strings"
	"sync"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"

	"github.com/sgnd/komando/internal/transport"
)

// CheckLocalFile is asked before a file of this computer that the
// environment or a cloud config file names is read to be sent as a login
// (what names the setting). The cli sets it: for an AI agent it refuses a
// file the agent may not send (a private key, komando's own data, a
// credential store).
var CheckLocalFile = func(what, path string) error { return nil }

// azureAuthorities are Azure's sign-in hosts: the public cloud, China and
// US Government. Tests add their own server.
var azureAuthorities = map[string]bool{
	"login.microsoftonline.com": true,
	"login.chinacloudapi.cn":    true,
	"login.microsoftonline.us":  true,
}

// azureAuthorityHost is the sign-in address AZURE_AUTHORITY_HOST names,
// when it is one of Azure's over https. The client secret or the workload
// token goes there, so any other host is refused: the variable picks a
// national cloud, it does not move the login.
func azureAuthorityHost(h string) (string, bool) {
	u, err := url.Parse(h)
	if err != nil || u.Scheme != "https" || u.User != nil || strings.Trim(u.Path, "/") != "" || u.RawQuery != "" || !azureAuthorities[strings.ToLower(u.Host)] {
		return "", false
	}
	return "https://" + strings.ToLower(u.Host), true
}

// checkAWSTokenFile puts the web identity token file of a loaded
// configuration to CheckLocalFile: AWS_WEB_IDENTITY_TOKEN_FILE, or
// web_identity_token_file of the profile. The SDK reads it and sends it to
// STS (AWS_ENDPOINT_URL moves that), so it is checked before the first
// credentials are asked for.
func checkAWSTokenFile(cfg aws.Config) error {
	for _, src := range cfg.ConfigSources {
		switch s := src.(type) {
		case config.EnvConfig:
			if s.WebIdentityTokenFilePath != "" {
				if err := CheckLocalFile("AWS_WEB_IDENTITY_TOKEN_FILE", s.WebIdentityTokenFilePath); err != nil {
					return err
				}
			}
		case config.SharedConfig:
			for p := &s; p != nil; p = p.Source {
				if p.WebIdentityTokenFile != "" {
					if err := CheckLocalFile("web_identity_token_file of AWS profile "+p.Profile, p.WebIdentityTokenFile); err != nil {
						return err
					}
				}
			}
		}
	}
	return nil
}

// containerHosts are the addresses ECS and EKS give containers their
// credentials at.
var containerHosts = map[string]bool{"169.254.170.2": true, "169.254.170.23": true, "fd00:ec2::23": true}

// agentAWSEnv takes out of an AI agent's environment, while the AWS
// configuration is read, what moves where AWS logins go; restore puts
// the variables back (the SDK keeps what it read). AWS_ENDPOINT_URL and
// its per-service forms (and endpoint_url in a profile) would send the
// saved SSO token or a web identity token file to a listener of the
// agent's; AWS_CONTAINER_CREDENTIALS_FULL_URI would send it the file
// AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE names. A conn's own endpoint
// (an emulator, a VPC endpoint) is in the conn, which a person allows.
func agentAWSEnv() (restore func()) {
	if !transport.EnvDistrusted() {
		return func() {}
	}
	awsEnvMu.Lock()
	saved := map[string]*string{}
	set := func(name string, v *string) {
		if _, ok := saved[name]; !ok {
			if old, was := os.LookupEnv(name); was {
				saved[name] = &old
			} else {
				saved[name] = nil
			}
		}
		if v == nil {
			_ = os.Unsetenv(name)
		} else {
			_ = os.Setenv(name, *v)
		}
	}
	for _, kv := range os.Environ() {
		if name, _, _ := strings.Cut(kv, "="); name == "AWS_ENDPOINT_URL" || strings.HasPrefix(name, "AWS_ENDPOINT_URL_") {
			set(name, nil)
		}
	}
	yes := "true"
	set("AWS_IGNORE_CONFIGURED_ENDPOINT_URLS", &yes)
	if full := os.Getenv("AWS_CONTAINER_CREDENTIALS_FULL_URI"); full != "" {
		if u, err := url.Parse(full); err != nil || !containerHosts[u.Hostname()] {
			for _, n := range []string{"AWS_CONTAINER_CREDENTIALS_FULL_URI", "AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE", "AWS_CONTAINER_AUTHORIZATION_TOKEN"} {
				set(n, nil)
			}
		}
	}
	return func() {
		for name, v := range saved {
			if v == nil {
				_ = os.Unsetenv(name)
			} else {
				_ = os.Setenv(name, *v)
			}
		}
		awsEnvMu.Unlock()
	}
}

// awsEnvMu keeps two loads from changing the environment at once.
var awsEnvMu sync.Mutex
