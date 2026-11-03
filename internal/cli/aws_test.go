package cli

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestECRRegion(t *testing.T) {
	for host, want := range map[string]string{
		"123456789012.dkr.ecr.eu-west-1.amazonaws.com":      "eu-west-1",
		"123456789012.dkr.ecr-fips.us-east-1.amazonaws.com": "us-east-1",
		"123456789012.dkr.ecr.us-east-1.amazonaws.com:443":  "us-east-1",
		"123456789012.dkr.ecr.us-east-1.amazonaws.com:5000": "us-east-1",
		"ghcr.io": "", "registry.example.com": "",
	} {
		if got := ecrRegion(host); got != want {
			t.Errorf("ecrRegion(%q) = %q, want %q", host, got, want)
		}
	}
}

// fakeAWS puts an aws script on PATH that prints canned answers and logs
// its arguments.
func fakeAWS(t *testing.T, script string) string {
	dir := t.TempDir()
	log := filepath.Join(dir, "args")
	os.WriteFile(filepath.Join(dir, "aws"), []byte("#!/bin/sh\necho \"$@\" >> "+log+"\n"+script), 0o755)
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	return log
}

func TestAWSCredentialsFromCLI(t *testing.T) {
	log := fakeAWS(t, `echo '{"Version":1,"AccessKeyId":"AKIA1","SecretAccessKey":"s3cr3t","SessionToken":"tok"}'`)
	c, err := awsCredentials(context.Background(), "prod")
	if err != nil || c.AccessKeyID != "AKIA1" || c.SessionToken != "tok" {
		t.Fatalf("creds %+v %v", c, err)
	}
	if b, _ := os.ReadFile(log); string(b) != "configure export-credentials --format process --profile prod\n" {
		t.Errorf("aws args: %q", b)
	}
	fakeAWS(t, `echo "Error loading SSO Token: Token for prod does not exist" >&2; exit 255`)
	if _, err := awsCredentials(context.Background(), "prod"); err == nil || toErr(err).Code != "AWS_LOGIN_REQUIRED" {
		t.Errorf("expired SSO must ask for a login: %v", err)
	}
}
