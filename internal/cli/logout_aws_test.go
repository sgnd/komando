package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/sgnd/komando/internal/cloud"
)

// status lists AWS SSO logins with the profiles that use them and when
// they end, and names the command that ends one.
func TestStatusShowsAWSLogins(t *testing.T) {
	invHome(t)
	saved := awsLogins
	defer func() { awsLogins = saved }()
	now := time.Now()
	awsLogins = func(*call) []cloud.AWSLogin {
		return []cloud.AWSLogin{{Profiles: []string{"dev", "ops"}, StartURL: "https://corp.awsapps.com/start", Region: "eu-west-1",
			Session: "corp", LoggedInAt: now.Add(-time.Hour), ExpiresAt: now.Add(3 * time.Hour)}}
	}
	d := mustRun(t, "status")
	ls, _ := d["aws_logins"].([]any)
	if len(ls) != 1 || ls[0].(map[string]any)["sso_session"] != "corp" || ls[0].(map[string]any)["expires_at"] == nil {
		t.Fatalf("status: %v", d)
	}
	txt := runningStatus(tcl, mustState(t)).Text()
	if !strings.Contains(txt, "aws") || !strings.Contains(txt, "dev,ops") || !strings.Contains(txt, "`komando logout aws --profile dev` ends it") {
		t.Errorf("text:\n%s", txt)
	}
}

// logout aws: a dry run names the profile; a profile without a login
// says so; --profile and --all do not go together.
func TestLogoutAWS(t *testing.T) {
	invHome(t)
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("AWS_PROFILE", "")
	t.Setenv("AWS_CONFIG_FILE", filepath.Join(home, "config"))
	if err := os.WriteFile(filepath.Join(home, "config"), []byte("[profile dev]\nsso_start_url = https://corp.awsapps.com/start\nsso_region = eu-west-1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if d := mustRun(t, "logout", "aws", "--profile", "dev", "--dry-run"); strings.Join(anyStrings(d["would_log_out"]), ",") != "dev" {
		t.Errorf("dry run: %v", d)
	}
	if d := mustRun(t, "logout", "aws", "--profile", "dev"); strings.Join(anyStrings(d["not_logged_in"]), ",") != "dev" {
		t.Errorf("no login: %v", d)
	}
	wantCode(t, "USAGE", "logout", "aws", "--profile", "dev", "--all")
}

func anyStrings(v any) []string {
	var s []string
	l, _ := v.([]any)
	for _, x := range l {
		s = append(s, x.(string))
	}
	return s
}
