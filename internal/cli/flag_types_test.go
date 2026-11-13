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

// S-5.3: one byte-size type; KB = KiB = 1024.
func TestStandardBytes(t *testing.T) {
	n := 0
	walkLeaves(newRoot(), func(path string, f *pflag.Flag) {
		if f.Name != "max-bytes" && f.Name != "max-output" {
			return
		}
		n++
		if _, ok := f.Value.(*bytesFlag); !ok || f.Value.Type() != "bytes" {
			t.Errorf("%s --%s: type %s, want the shared bytes type", path, f.Name, f.Value.Type())
		}
	})
	if n < 6 {
		t.Errorf("found %d size flags, want --max-output and 5 --max-bytes", n)
	}
	for in, want := range map[string]int64{"1048576": 1 << 20, "256KiB": 256 << 10, "256KB": 256 << 10, "10GB": 10 << 30, "1MiB": 1 << 20, "0": 0} {
		var got int64
		if err := (&bytesFlag{n: &got}).Set(in); err != nil || got != want {
			t.Errorf("%s: %d %v, want %d", in, got, err, want)
		}
	}
	for _, in := range []string{"-1", "lots", "10XB"} {
		var got int64
		if err := (&bytesFlag{n: &got}).Set(in); err == nil {
			t.Errorf("%s was taken as %d", in, got)
		}
	}
	invHome(t)
	if code, s := runMain(t, "list", "--max-output", "256KiB"); code != 0 {
		t.Errorf("--max-output 256KiB: exit %d %s", code, s)
	}
	if e := mainErr(t, "list", "--max-output", "lots"); e.Code != "USAGE" || !strings.HasPrefix(e.Message, "--max-output: ") {
		t.Errorf("--max-output lots: %+v", e)
	}
}

// S-5.7: an unset optional number shows no default, never -1, and -1 is
// not a value one can give.
func TestStandardNoMinusOneDefault(t *testing.T) {
	walkLeaves(newRoot(), func(path string, f *pflag.Flag) {
		if f.DefValue == "-1" {
			t.Errorf("%s --%s shows default -1", path, f.Name)
		}
	})
	p := 0
	v := &optInt{&p}
	p = -1
	if v.String() != "" || v.Set("-1") == nil || p != -1 || v.Set("2") != nil || p != 2 || v.Set("-2") == nil {
		t.Errorf("optInt: %d", p)
	}
}

// S-5.7: a default taken from a setting keeps `default` and names the
// setting in `default_from`; the setting is a real `komando config` key.
func TestStandardDefaultFrom(t *testing.T) {
	keys := map[string]bool{}
	for _, s := range settings {
		keys[s.Key] = true
	}
	walkLeaves(newRoot(), func(path string, f *pflag.Flag) {
		fs := newFlagSchema(f)
		inText := strings.Contains(f.Usage, "(default: setting")
		if inText != (fs.DefaultFrom != "") {
			t.Errorf("%s --%s: usage %q but default_from %q", path, f.Name, f.Usage, fs.DefaultFrom)
		}
		if k, ok := strings.CutPrefix(fs.DefaultFrom, "setting:"); fs.DefaultFrom != "" && (!ok || !keys[k] || !strings.Contains(f.Usage, "setting "+k+",")) {
			t.Errorf("%s --%s: default_from %q is no setting named in its usage", path, f.Name, fs.DefaultFrom)
		}
	})
	invHome(t)
	_, s := runMain(t, "schema")
	if !strings.Contains(s, `"name":"timeout","type":"duration","default":"0","default_from":"setting:default_timeout"`) {
		t.Errorf("schema --timeout: %s", s[strings.Index(s, `"global_flags"`):][:600])
	}
}

// S-5.1: KEY=VALUE flags are repeatable, never split on commas, and a
// second KEY= after a comma is a usage error, never one value.
func TestStandardKeyValue(t *testing.T) {
	n := 0
	walkLeaves(newRoot(), func(path string, f *pflag.Flag) {
		switch {
		case f.Name == "label" || f.Name == "option" || f.Name == "env" && strings.HasPrefix(path, "komando host "):
			n++
			if _, ok := f.Value.(*kvArray); !ok || f.Value.Type() != "stringArray" {
				t.Errorf("%s --%s: type %s, want the KEY=VALUE type", path, f.Name, f.Value.Type())
			}
		}
	})
	if n != 22 {
		t.Errorf("%d KEY=VALUE flags, want 22 (--env x2, --label x12, --option x8)", n)
	}
	var got []string
	v := &kvArray{p: &got, name: "option"}
	for _, s := range []string{"a=x,y", "b=", "dsn=host:5432,other"} {
		if err := v.Set(s); err != nil {
			t.Errorf("%s: %v", s, err)
		}
	}
	if strings.Join(got, "|") != "a=x,y|b=|dsn=host:5432,other" {
		t.Errorf("kept %q", got)
	}
	invHome(t)
	e := mainErr(t, "conn", "add", "pg", "postgres://u@10.0.0.9/app", "--option", "sslmode=require,secret_pw=hunter2")
	if e.Code != "USAGE" || e.Exit != out.ExitUsage || !strings.Contains(e.Message, "repeat --option for each KEY=VALUE") ||
		e.Message != "--option: sslmode=...,secret_pw=... holds 2 KEY=VALUE pairs; repeat --option for each KEY=VALUE" ||
		e.Hint != "for example: --option sslmode=... --option secret_pw=..." {
		t.Errorf("two pairs in one: %+v", e)
	}
	if strings.Contains(e.Message+e.Hint, "hunter2") || strings.Contains(e.Message+e.Hint, "require") {
		t.Errorf("the values are shown: %+v", e)
	}
	mustRun(t, "host", "add", "web1", "u@10.0.0.1", "--env", "A=1", "--env", "B=x,y", "--label", "team=ops", "--label", "env=prod")
	h := mustRun(t, "host", "show", "web1")
	if s := jsonStr(h); !strings.Contains(s, `"B":"x,y"`) || !strings.Contains(s, `"team":"ops"`) || !strings.Contains(s, `"env":"prod"`) {
		t.Errorf("host show: %s", s)
	}
}
