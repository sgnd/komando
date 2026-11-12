package cli

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"
)

// emptyLine is S-9.5: `no <things> yet` with the add command, or
// `no <things> match <filter>`, and an aside in brackets.
var emptyLine = regexp.MustCompile("^no [^\n]+ (yet(: `komando [^`]+`)?|match [^\n]+?)( \\([^\n]+\\))?\n$")

// S-9.5: a list with nothing in it says so on stdout, in one wording.
func TestStandardEmptyLines(t *testing.T) {
	invHome(t)
	mustRun(t, "host", "add", "web1", "u@10.0.0.1") // so host list is not the empty inventory
	for _, a := range []string{"conn list", "vpn list", "key list", "secret list", "job list", "tunnel list", "vpn status", "audit --failed"} {
		s, err := textRun(t, strings.Fields(a)...)
		if err != nil || !emptyLine.MatchString(s) {
			t.Errorf("%s: %q (%v)", a, s, err)
		}
	}
	mustRun(t, "host", "rm", "web1")
	mustRun(t, "conn", "add", "app-db", "postgres://app@10.0.0.9/app")
	if s, _ := textRun(t, "host", "list"); s != "no servers yet: `komando host add NAME USER@ADDRESS`\n" {
		t.Errorf("host list: %q", s)
	}
	// the lists that read a server or a conn, as they render nothing
	for name, x := range map[string]interface{ Text() string }{
		"group list": groupList{}, "db schema": schemaData{}, "db activity": activityData{},
		"storage list": objectList{Conn: "backups"}, "storage list PREFIX": objectList{Conn: "backups", Prefix: "logs/"},
		"cluster list": kubeList{"type": "Pod"}, "fs list": lsResult{Path: "/tmp/x"},
		"cluster history": historyData{}, "cluster helm history": helmHistory{}, "cluster helm list": helmList{},
		"cluster events": eventList{}, "cache keys": keyList{}, "cache keys PATTERN": keyList{Pattern: "user:*"},
		"queue list": queueTopics{Conn: "prod-kafka"}, "queue groups": queueGroups{}, "registry list": lsData{},
		"audit": auditList{},
	} {
		if s := x.Text(); !emptyLine.MatchString(s) {
			t.Errorf("%s: %q", name, s)
		}
	}
	// the wordings this replaced do not come back
	old := regexp.MustCompile(`return "(\(none\)|\(empty folder\)|no [a-zA-Z %]+ found|nothing under )`)
	files, _ := filepath.Glob("*.go")
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		b, _ := os.ReadFile(f)
		for i, l := range strings.Split(string(b), "\n") {
			if old.MatchString(l) {
				t.Errorf("%s:%d: an empty list worded the old way; use noneYet or noneMatch: %s", f, i+1, strings.TrimSpace(l))
			}
		}
	}
}

// S-9.6: tables write a boolean as yes or -, a moment as local time with
// its zone, an age as 3h, and header words with spaces, through yesCell,
// timeCell and ageCell.
func TestStandardTableCells(t *testing.T) {
	if yesCell(true) != "yes" || yesCell(false) != "-" || ageCell(time.Time{}) != "-" || timeCell(time.Time{}) != "-" {
		t.Error("yesCell, ageCell or timeCell")
	}
	if got := ageCell(time.Now().Add(-3 * time.Hour)); got != "3h" {
		t.Errorf("ageCell: %q", got)
	}
	at := time.Date(2026, 11, 7, 7, 30, 0, 0, time.UTC)
	if got, want := timeCell(at), at.Local().Format("2006-01-02 15:04 ")+at.Local().Format("MST"); got != want || !strings.Contains(got, " ") {
		t.Errorf("timeCell: %q, want %q", got, want)
	}
	bad := map[string]*regexp.Regexp{
		"a yes/no map; use yesCell":             regexp.MustCompile(`true: "yes", false: "no"`),
		"a time without its zone; use timeCell": regexp.MustCompile(`Format\("2006-01-02 15:04(:05)?"\)`),
		"a header with _; use a space":          regexp.MustCompile(`[tT]able\(\[\]string\{[^}]*"[A-Za-z]+_[A-Za-z_]+"`),
	}
	files, _ := filepath.Glob("*.go")
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") || f == "textfmt.go" {
			continue
		}
		b, _ := os.ReadFile(f)
		for i, l := range strings.Split(string(b), "\n") {
			for why, re := range bad {
				if re.MatchString(l) && !strings.Contains(l, `+ " UTC"`) { // journalctl's --since, in UTC
					t.Errorf("%s:%d: %s: %s", f, i+1, why, strings.TrimSpace(l))
				}
			}
		}
	}
}
