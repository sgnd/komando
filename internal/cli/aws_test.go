package cli

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestECRRegion(t *testing.T) {
	for host, want := range map[string]string{
		"123456789012.dkr.ecr.eu-west-1.amazonaws.com":      "eu-west-1",
		"123456789012.dkr.ecr-fips.us-east-1.amazonaws.com": "us-east-1",
		"ghcr.io": "", "registry.example.com": "",
	} {
		if got := ecrRegion(host); got != want {
			t.Errorf("ecrRegion(%q) = %q, want %q", host, got, want)
		}
	}
}

// TestAWSCredentialsBuiltIn reads a profile without the aws CLI on PATH.
func TestAWSCredentialsBuiltIn(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("PATH", "/nonexistent")
	t.Setenv("AWS_CONFIG_FILE", filepath.Join(home, "config"))
	t.Setenv("AWS_SHARED_CREDENTIALS_FILE", filepath.Join(home, "credentials"))
	t.Setenv("AWS_EC2_METADATA_DISABLED", "true")
	for _, k := range []string{"AWS_PROFILE", "AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN"} {
		t.Setenv(k, "")
	}
	os.WriteFile(filepath.Join(home, "credentials"), []byte("[prod]\naws_access_key_id = AKIA1\naws_secret_access_key = s3cr3t\naws_session_token = tok\n"), 0o600)
	c, err := awsCredentials(context.Background(), "prod")
	if err != nil || c.AccessKeyID != "AKIA1" || c.SessionToken != "tok" {
		t.Fatalf("creds %+v %v", c, err)
	}
	if _, err := awsCredentials(context.Background(), "nope"); err == nil || toErr(err).Code != "AWS_PROFILE_NOT_FOUND" {
		t.Errorf("missing profile: %v", err)
	}
	os.WriteFile(filepath.Join(home, "config"), []byte("[profile sso]\nsso_session = s\nsso_account_id = 1\nsso_role_name = r\n[sso-session s]\nsso_start_url = https://x.awsapps.com/start\nsso_region = eu-west-1\n"), 0o600)
	if _, err := awsCredentials(context.Background(), "sso"); err == nil || toErr(err).Code != "AWS_LOGIN_REQUIRED" ||
		!strings.Contains(toErr(err).Hint, "komando login aws --profile sso") {
		t.Errorf("SSO without a login: %+v", toErr(err))
	}
}
