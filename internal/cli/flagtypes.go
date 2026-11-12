package cli

import (
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/pflag"

	"github.com/sgnd/komando/internal/dbx"
)

// The flag value types every command shares (docs/design/command-standard.md,
// S-5.2, S-5.3 and S-5.7): one duration type, one byte-size type and one
// optional number. A value that is wrong is refused while the flags are read,
// with one message per type wherever the flag is.

// flagHint joins a message and its hint in a flag value's error.
func flagHint(msg, hint string) error { return errors.New(msg + flagHintSep + hint) }

// flagHintSep parts a flag value's error into its message and its hint:
// pflag puts the error in its own words ("invalid argument ... flag:
// MESSAGE"), and usageErr splits them again into error.message and
// error.hint.
const flagHintSep = "\nhint: "

// valueChecker is a flag value that checks an answer without keeping it,
// so a form asks again with the flag's own words.
type valueChecker interface{ check(s string) error }

// retiredShaper is a flag value that was given in a retired shape (a bare
// number of seconds); noteRetiredFlags notes it with retiredName.
type retiredShaper interface{ retiredShape() (used, now string) }

// parseSpan reads a span: Go units (90s, 10m, 1h30m) or whole days (7d). A
// bare number is accepted only as 0; every other span needs a unit, so 30
// is never 30 seconds or 30 days. A negative span is refused.
func parseSpan(s string) (time.Duration, error) {
	s = strings.TrimSpace(s)
	if s == "0" {
		return 0, nil
	}
	if days, ok := strings.CutSuffix(s, "d"); ok {
		if n, err := strconv.Atoi(days); err == nil && n >= 0 && n <= 100000 {
			return time.Duration(n) * 24 * time.Hour, nil
		}
	}
	if d, err := time.ParseDuration(s); err == nil && d >= 0 {
		return d, nil
	}
	if _, err := strconv.Atoi(s); err == nil {
		return 0, fmt.Errorf("%s needs a unit: %ss, %sm, %sh or %sd", s, s, s, s, s)
	}
	return 0, fmt.Errorf("give a time like 30s, 10m, 2h or 7d (got %q)", s)
}

// shortSpan is d as people write it: 1h, not 1h0m0s; 0 for none.
func shortSpan(d time.Duration) string {
	if d == 0 {
		return "0"
	}
	s := d.String()
	if strings.HasSuffix(s, "m0s") {
		s = s[:len(s)-2]
	}
	if strings.HasSuffix(s, "h0m") {
		s = s[:len(s)-2]
	}
	return s
}

// durFlag is every span flag (Type "duration"): --timeout, --wait,
// --interval, --expires, --ttl, --warn, --older-than and the rest.
type durFlag struct {
	d        *time.Duration
	text     *string // when set: the span as typed, for results that echo it
	positive bool    // 0 is refused (an age, a warning window)
	seconds  bool    // a bare number is seconds: the retired shape of svc/reboot --wait
	name     string
	used     string // the retired shape given, for meta.deprecated
}

func (v *durFlag) String() string {
	if v.text != nil {
		return *v.text
	}
	if v.d == nil {
		return "0"
	}
	return shortSpan(*v.d)
}

func (v *durFlag) Type() string { return "duration" }

func (v *durFlag) Set(s string) error {
	d, err := v.parse(s)
	if err != nil {
		return err
	}
	v.used = ""
	if v.seconds {
		if n, aerr := strconv.Atoi(strings.TrimSpace(s)); aerr == nil && n > 0 {
			v.used = s
		}
	}
	*v.d = d
	if v.text != nil {
		*v.text = s
	}
	return nil
}

func (v *durFlag) parse(s string) (time.Duration, error) {
	if v.seconds {
		if n, err := strconv.Atoi(strings.TrimSpace(s)); err == nil && n >= 0 {
			return time.Duration(n) * time.Second, nil
		}
	}
	d, err := parseSpan(s)
	if err == nil && v.positive && d == 0 {
		err = fmt.Errorf("give a time of more than 0, like 30d, 12h or 90m")
	}
	return d, err
}

func (v *durFlag) check(s string) error { _, err := v.parse(s); return err }

func (v *durFlag) retiredShape() (used, now string) {
	if v.used == "" {
		return "", ""
	}
	return "--" + v.name + " " + v.used, "--" + v.name + " " + v.used + "s"
}

// durVar adds a span flag that holds a time.Duration.
func durVar(fs *pflag.FlagSet, p *time.Duration, name string, def time.Duration, usage string) *durFlag {
	*p = def
	v := &durFlag{d: p, name: name}
	fs.Var(v, name, usage)
	return v
}

// spanText adds a span flag kept as the text typed (empty when not given):
// results and the audit log echo it as before, and the command reads it
// with parseAge.
func spanText(fs *pflag.FlagSet, p *string, name, def string, positive bool, usage string) {
	*p = def
	var d time.Duration
	fs.Var(&durFlag{d: &d, text: p, positive: positive, name: name}, name, usage)
}

// bytesFlag is every byte-size flag (Type "bytes"): --max-bytes and
// --max-output. It takes a number of bytes or KB/MB/GB (KiB, MiB, GiB),
// where KB = KiB = 1024 bytes.
type bytesFlag struct {
	n    *int64
	i    *int    // or this one, for an int variable
	text *string // or this one: the size as typed, "" when not given
}

func (v *bytesFlag) String() string {
	switch {
	case v.text != nil:
		return *v.text
	case v.i != nil:
		return strconv.Itoa(*v.i)
	}
	return strconv.FormatInt(*v.n, 10)
}

func (v *bytesFlag) Type() string { return "bytes" }

func (v *bytesFlag) Set(s string) error {
	n, err := parseSize(s)
	if err != nil {
		return err
	}
	switch {
	case v.text != nil:
		*v.text = s
	case v.i != nil:
		*v.i = int(n)
	default:
		*v.n = n
	}
	return nil
}

func (v *bytesFlag) check(s string) error { _, err := parseSize(s); return err }

func parseSize(s string) (int64, error) {
	n, err := dbx.ParseBytes(s)
	if err != nil {
		return 0, fmt.Errorf("give a size like 1048576, 256KiB, 10MB or 1GB (got %q)", s)
	}
	return n, nil
}

// optInt is a number that may be left out: the other side (the broker)
// decides then. It shows no default, never -1 (S-5.7).
type optInt struct{ p *int } // -1 while not given

func (v *optInt) String() string {
	if *v.p < 0 {
		return ""
	}
	return strconv.Itoa(*v.p)
}

func (v *optInt) Type() string { return "int" }

func (v *optInt) Set(s string) error {
	n, err := strconv.Atoi(strings.TrimSpace(s))
	if err != nil || n < -1 { // -1, the old way to write "left out", still means that
		return fmt.Errorf("give a whole number of 0 or more (got %q)", s)
	}
	*v.p = n
	return nil
}

func (v *optInt) check(s string) error { return (&optInt{p: new(int)}).Set(s) }

// optIntVar adds an optInt flag; *p is -1 until it is given.
func optIntVar(fs *pflag.FlagSet, p *int, name, usage string) {
	*p = -1
	fs.Var(&optInt{p}, name, usage)
}

// kvArray is a KEY=VALUE flag (--env, --label, --option): repeatable, and
// never split on commas, so a value keeps its commas. A value whose text
// after a comma starts like KEY= was meant as two flags: that is refused,
// never read as one value (S-5.1).
type kvArray struct {
	p    *[]string
	name string
	set  bool
}

func (v *kvArray) String() string { return "[" + strings.Join(*v.p, ",") + "]" }

func (v *kvArray) Type() string { return "stringArray" }

func (v *kvArray) Set(s string) error {
	if err := v.check(s); err != nil {
		return err
	}
	if !v.set {
		*v.p = nil // the first one given replaces the default
		v.set = true
	}
	*v.p = append(*v.p, s)
	return nil
}

func (v *kvArray) check(s string) error {
	parts := strings.Split(s, ",")
	keys := []string{}
	for i, p := range parts {
		if i == 0 || kvStart.MatchString(p) {
			k, _, _ := strings.Cut(p, "=")
			keys = append(keys, k)
		}
	}
	if len(keys) < 2 {
		return nil
	}
	// the values are left out of the words: a value may be a password
	var ex []string
	for _, k := range keys {
		ex = append(ex, "--"+v.name+" "+shellQuote(k+"=..."))
	}
	return flagHint(fmt.Sprintf("%s=... holds %d KEY=VALUE pairs; repeat --%s for each KEY=VALUE", strings.Join(keys, "=...,"), len(keys), v.name),
		"for example: "+strings.Join(ex, " "))
}

// kvStart is the start of a KEY=VALUE pair: a name, then =.
var kvStart = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_.-]*=`)

func (v *kvArray) Append(s string) error { return v.Set(s) }
func (v *kvArray) Replace(s []string) error {
	*v.p = nil
	for _, one := range s {
		if err := v.Set(one); err != nil {
			return err
		}
	}
	return nil
}
func (v *kvArray) GetSlice() []string { return *v.p }

// kvVar adds a KEY=VALUE flag.
func kvVar(fs *pflag.FlagSet, p *[]string, name, short, usage string) {
	fs.VarP(&kvArray{p: p, name: name}, name, short, usage)
}
