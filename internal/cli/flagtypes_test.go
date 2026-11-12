package cli

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"

	"github.com/sgnd/komando/internal/out"
)

// S-5.2: one duration type. Go units and days; a bare number only as 0.
func TestStandardDurations(t *testing.T) {
	for in, want := range map[string]time.Duration{"0": 0, "30s": 30 * time.Second, "90m": 90 * time.Minute, "1h30m": 90 * time.Minute, "7d": 7 * 24 * time.Hour} {
		if d, err := parseSpan(in); err != nil || d != want {
			t.Errorf("parseSpan(%q) = %v, %v; want %v", in, d, err, want)
		}
	}
	for _, in := range []string{"30", "-5m", "soon", "", "1.5d"} {
		if _, err := parseSpan(in); err == nil {
			t.Errorf("parseSpan(%q) took it", in)
		}
	}
	// every span flag in the tree has the one type, and shows its default short
	walkLeaves(newRoot(), func(path string, f *pflag.Flag) {
		switch f.Name {
		case "timeout", "connect-timeout", "interval", "expires", "ttl", "older-than", "warn", "idle":
		case "wait":
			if f.Value.Type() == "bool" { // cluster deploy/rollback/...: kept a bool (S-5.1 exception)
				return
			}
		default:
			if f.Value.Type() == "duration" {
				if _, ok := f.Value.(*durFlag); !ok {
					t.Errorf("%s --%s: a duration flag outside durFlag", path, f.Name)
				}
			}
			return
		}
		if f.Value.Type() != "duration" {
			t.Errorf("%s --%s: type %s, want duration", path, f.Name, f.Value.Type())
		}
		if _, ok := f.Value.(*durFlag); !ok {
			t.Errorf("%s --%s: not the shared duration type", path, f.Name)
		}
		if strings.HasSuffix(f.DefValue, "0s") || strings.HasSuffix(f.DefValue, "h0m") {
			t.Errorf("%s --%s: default %q is not the short form", path, f.Name, f.DefValue)
		}
	})
	invHome(t)
	for _, args := range [][]string{
		{"storage", "rm", "s3", "--prefix", "a/", "--older-than", "30", "--dry-run"},
		{"storage", "rm", "s3", "--prefix", "a/", "--older-than", "0", "--dry-run"},
		{"cache", "set", "c", "k", "v", "--ttl", "30", "--dry-run"},
		{"cert", "check", "web1", "--warn", "-1d", "--dry-run"},
		{"list", "--timeout", "30"},
	} {
		if e := mainErr(t, args...); e.Code != "USAGE" || e.Exit != out.ExitUsage {
			t.Errorf("%v: %+v, want USAGE exit 2", args, e)
		}
	}
	if e := mainErr(t, "storage", "rm", "s3", "--prefix", "a/", "--older-than", "30", "--dry-run"); !strings.Contains(e.Message, "30d") || !strings.HasPrefix(e.Message, "--older-than: ") {
		t.Errorf("--older-than 30 names the units: %q", e.Message)
	}
}

// A bare number of seconds on svc/reboot --wait is a retired shape: it
// works and is noted.
func TestWaitSecondsNoted(t *testing.T) {
	c := &cobra.Command{Use: "x", RunE: func(*cobra.Command, []string) error { return nil }}
	var d time.Duration
	c.Flags().Var(&durFlag{d: &d, seconds: true, name: "wait"}, "wait", "")
	out.P.Reset()
	if err := c.ParseFlags([]string{"--wait", "10"}); err != nil || d != 10*time.Second {
		t.Fatalf("parse: %v %v", err, d)
	}
	noteRetiredFlags(c)
	if m := metaDeprecated(); m == nil || m.Used != "--wait 10" || m.Now != "--wait 10s" {
		t.Errorf("meta.deprecated %+v", m)
	}
	out.P.Reset()
	_ = c.ParseFlags([]string{"--wait", "10s"})
	noteRetiredFlags(c)
	if m := metaDeprecated(); m != nil {
		t.Errorf("10s is noted: %+v", m)
	}
}

// mainErr runs komando as the program does and returns its error envelope.
func mainErr(t *testing.T, args ...string) out.Error {
	t.Helper()
	code, s := runMain(t, args...)
	var env struct {
		Error out.Error `json:"error"`
	}
	lines := strings.Split(strings.TrimSpace(s), "\n")
	if err := json.Unmarshal([]byte(lines[len(lines)-1]), &env); err != nil {
		t.Fatalf("%v: exit %d, no envelope: %q", args, code, s)
	}
	env.Error.Exit = code
	return env.Error
}

// walkLeaves calls fn for every flag of every command, hidden ones too.
func walkLeaves(root *cobra.Command, fn func(path string, f *pflag.Flag)) {
	for _, c := range allCommands(root) {
		c.LocalFlags().VisitAll(func(f *pflag.Flag) { fn(c.CommandPath(), f) })
	}
	root.PersistentFlags().VisitAll(func(f *pflag.Flag) { fn("komando", f) })
}
