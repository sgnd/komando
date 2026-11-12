package cli

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
)

// TestImportAWS reads two profiles against moto's S3 (make e2e starts it):
// one with keys in the credentials file, one only in config; each bucket
// becomes a conn that uses the profile, and no key is copied.
func TestImportAWS(t *testing.T) {
	endpoint := os.Getenv("KOMANDO_E2E_MOTO")
	if endpoint == "" {
		t.Skip("set KOMANDO_E2E_MOTO to moto's URL (make e2e does)")
	}
	for _, k := range []string{"AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN", "AWS_PROFILE", "AWS_ENDPOINT_URL", "AWS_REGION", "AWS_SHARED_CREDENTIALS_FILE", "AWS_CONFIG_FILE"} {
		t.Setenv(k, "")
		os.Unsetenv(k)
		resetApproval()
	}
	host := strings.TrimPrefix(endpoint, "http://")
	mc, err := minio.New(host, &minio.Options{Creds: credentials.NewStaticV4("test", "test", ""), Region: "us-east-1"})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	for _, b := range []string{"imp-logs", "imp-backups"} {
		if err := mc.MakeBucket(ctx, b, minio.MakeBucketOptions{Region: "us-east-1"}); err != nil {
			if ok, _ := mc.BucketExists(ctx, b); !ok {
				t.Fatal(err)
			}
		}
	}
	dir := t.TempDir()
	cfg := filepath.Join(dir, "config")
	os.WriteFile(cfg, []byte("[default]\nregion = us-east-1\nendpoint_url = "+endpoint+"\n\n[profile prod]\nregion = us-east-1\nendpoint_url = "+endpoint+
		"\naws_access_key_id = test\naws_secret_access_key = test\n\n[profile broken]\nregion = us-east-1\nendpoint_url = http://127.0.0.1:1\naws_access_key_id = x\naws_secret_access_key = y\n"), 0o600)
	os.WriteFile(filepath.Join(dir, "credentials"), []byte("[default]\naws_access_key_id = test\naws_secret_access_key = test\n"), 0o600)
	p, err := importAWS(cfg)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for _, c := range p.Conns {
		got[c.Name] = c.Options["aws_profile"] + " " + c.URL
		if strings.Contains(c.URL, "test@") || c.PasswordRef != "" {
			t.Errorf("%s copies a key: %s %s", c.Name, c.URL, c.PasswordRef)
		}
	}
	if !strings.HasPrefix(got["imp-logs"], "default s3://imp-logs?") || !strings.HasPrefix(got["prod-imp-backups"], "prod s3://imp-backups?") ||
		!strings.Contains(got["imp-logs"], "endpoint=") {
		t.Errorf("conns %v", got)
	}
	if len(p.Secrets) != 0 {
		t.Error("a secret was stored")
	}
	if notes := strings.Join(p.Notes, "\n"); !strings.Contains(notes, "profile broken") {
		t.Errorf("notes %q", notes)
	}
}

// A profile that cannot log in says what fixes it: `komando login aws` only
// for an SSO profile, the credentials file for one without SSO. No AWS
// endpoint is reached.
func TestImportAWSNotes(t *testing.T) {
	awsHome(t)
	dir := t.TempDir()
	cfg := filepath.Join(dir, "config")
	os.WriteFile(cfg, []byte("[profile corp]\nsso_session = s\nsso_account_id = 1\nsso_role_name = r\n[sso-session s]\n"+
		"sso_start_url = https://x.awsapps.com/start\nsso_region = eu-west-1\n[profile bare]\nregion = eu-west-1\n"), 0o600)
	t.Setenv("AWS_SHARED_CREDENTIALS_FILE", "")
	os.Unsetenv("AWS_SHARED_CREDENTIALS_FILE")
	p, err := importAWS(cfg)
	if err != nil {
		t.Fatal(err)
	}
	notes := strings.Join(p.Notes, "\n")
	if !strings.Contains(notes, "profile corp: no valid SSO login; a person runs `komando login aws --profile corp`") ||
		!strings.Contains(notes, "profile bare: no keys and no SSO login; put its keys under [bare] in "+filepath.Join(dir, "credentials")) ||
		strings.Contains(notes, "login aws --profile bare") {
		t.Errorf("notes:\n%s", notes)
	}
	if len(p.Conns) != 0 {
		t.Errorf("conns %v", p.Conns)
	}
}
