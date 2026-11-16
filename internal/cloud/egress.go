package cloud

import (
	"net/url"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
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
