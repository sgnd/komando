package cli

import (
	"cmp"
	"strconv"
	"strings"

	"github.com/spf13/cobra"

	"github.com/sgnd/komando/internal/out"
	"github.com/sgnd/komando/internal/store"
)

// setting is one key of `komando config`. set validates the value and
// stores it; guards for safety settings are part of set.
type setting struct {
	Key, Values, Help string
	get               func(s *store.Settings) string
	set               func(st *store.State, v string) error
}

// minOutputBytes: below this, error messages and hints no longer fit.
const minOutputBytes = 1024

func positiveDur(key, v string, zeroOK bool) (string, error) {
	if zeroOK && (v == "0" || strings.EqualFold(v, "off")) {
		return "0", nil
	}
	d, err := parseDur(v)
	if err != nil || d < 0 || (d == 0 && !zeroOK) {
		ex := "e.g. 30s, 5m, 1h"
		if zeroOK {
			ex += ", or 0 for never"
		}
		return "", out.Errf(out.ExitUsage, "USAGE", key+" takes a duration: "+ex, "invalid %s %q", key, v)
	}
	return v, nil
}

func intAtLeast(key, v string, minV int) (int, error) {
	n, err := strconv.Atoi(v)
	if err != nil || n < minV {
		return 0, out.Errf(out.ExitUsage, "USAGE", key+" takes a whole number of at least "+strconv.Itoa(minV), "invalid %s %q", key, v)
	}
	return n, nil
}

var settings = []setting{
	{"host_key_policy", "accept-new | strict | off", "how server identity is checked: accept-new pins a new server's key, strict needs `host trust` first, off checks nothing (needs --yes)",
		func(s *store.Settings) string { return s.HostKeyPolicy },
		func(st *store.State, v string) error {
			v = strings.ToLower(v)
			if v != "accept-new" && v != "strict" && v != "off" {
				return out.Errf(out.ExitUsage, "USAGE", "use accept-new (the default), strict or off", "invalid host_key_policy %q", v)
			}
			rank := map[string]int{"off": 0, "accept-new": 1, "": 1, "strict": 2}
			if rank[v] < rank[st.Settings.HostKeyPolicy] {
				if err := guardSafety("loosening server identity checks to " + v); err != nil {
					return err
				}
			}
			st.Settings.HostKeyPolicy = v
			return nil
		}},
	{"default_user", "a login name", "user for servers that have none (empty: your own user name)",
		func(s *store.Settings) string { return s.DefaultUser },
		func(st *store.State, v string) error {
			if v != "" {
				if err := validUser(v); err != nil {
					return err
				}
			}
			st.Settings.DefaultUser = v
			return nil
		}},
	{"default_timeout", "duration > 0", "how long a remote command may run (--timeout overrides it)",
		func(s *store.Settings) string { return s.DefaultTimeout },
		func(st *store.State, v string) (err error) {
			st.Settings.DefaultTimeout, err = positiveDur("default_timeout", v, false)
			return err
		}},
	{"connect_timeout", "duration > 0", "how long connecting may take (--connect-timeout overrides it)",
		func(s *store.Settings) string { return s.ConnectTimeout },
		func(st *store.State, v string) (err error) {
			st.Settings.ConnectTimeout, err = positiveDur("connect_timeout", v, false)
			return err
		}},
	{"parallel", "1 or more", "how many servers a command works on at once (-P overrides it)",
		func(s *store.Settings) string { return strconv.Itoa(s.Parallel) },
		func(st *store.State, v string) (err error) {
			st.Settings.Parallel, err = intAtLeast("parallel", v, 1)
			return err
		}},
	{"max_output_bytes", "1024 or more", "output kept per stream and server, in bytes (--max-output overrides it)",
		func(s *store.Settings) string { return strconv.Itoa(s.MaxOutputBytes) },
		func(st *store.State, v string) (err error) {
			st.Settings.MaxOutputBytes, err = intAtLeast("max_output_bytes", v, minOutputBytes)
			return err
		}},
	{"audit", "on | off", "keep the audit log (turning it off needs --yes)",
		func(s *store.Settings) string { return map[bool]string{true: "on", false: "off"}[s.Audit] },
		func(st *store.State, v string) error {
			on, ok := map[string]bool{"true": true, "on": true, "1": true, "false": false, "off": false, "0": false}[strings.ToLower(v)]
			if !ok {
				return out.Errf(out.ExitUsage, "USAGE", "use on or off", "invalid audit %q", v)
			}
			if !on && st.Settings.Audit {
				if err := guardSafety("turning off the audit log"); err != nil {
					return err
				}
			}
			st.Settings.Audit = on
			return nil
		}},
	{"audit_sql", "full | hash | off", "how SQL text is kept in the audit log: hash keeps a SHA-256 so repeated queries can be matched (off needs --yes)",
		func(s *store.Settings) string { return s.AuditSQL },
		func(st *store.State, v string) error {
			v = strings.ToLower(v)
			if v != "full" && v != "hash" && v != "off" {
				return out.Errf(out.ExitUsage, "USAGE", "use full (the default), hash or off", "invalid audit_sql %q", v)
			}
			if v == "off" && st.Settings.AuditSQL != "off" {
				if err := guardSafety("leaving SQL out of the audit log"); err != nil {
					return err
				}
			}
			st.Settings.AuditSQL = v
			return nil
		}},
	{"audit_syslog", "udp://HOST:514 | tcp://HOST:514 | tls://HOST:6514 | off", "also send each audit record to a log server (syslog, RFC 5424); changing it needs --yes",
		func(s *store.Settings) string {
			if s.AuditSyslog == "" {
				return "off"
			}
			return s.AuditSyslog
		},
		func(st *store.State, v string) error {
			if strings.EqualFold(v, "off") {
				v = ""
			}
			if _, _, err := syslogTarget(v); err != nil {
				return err
			}
			if v != st.Settings.AuditSyslog {
				// where the audit goes, or that it stops going there: a person decides
				if err := guardSafety("sending the audit log to " + cmp.Or(v, "no log server")); err != nil {
					return err
				}
			}
			st.Settings.AuditSyslog = v
			return nil
		}},
	{"mask_personal", "protected | all | off", "where AI agents see email addresses, phone numbers, card numbers and IBANs hidden: on protected servers and conns (the default), on all, or nowhere (less needs --yes)",
		func(s *store.Settings) string { return s.MaskPersonal },
		func(st *store.State, v string) error {
			v = strings.ToLower(v)
			rank := map[string]int{"off": 0, "protected": 1, "all": 2}
			n, ok := rank[v]
			if !ok {
				return out.Errf(out.ExitUsage, "USAGE", "use protected (the default), all or off", "invalid mask_personal %q", v)
			}
			if n < rank[st.Settings.MaskPersonal] {
				if err := guardSafety("showing AI agents more personal data (mask_personal " + v + ")"); err != nil {
					return err
				}
			}
			st.Settings.MaskPersonal = v
			return nil
		}},
	{"login_for", "duration", "how long `komando login HOST` keeps a server's login for later commands (an AI agent's too)",
		func(s *store.Settings) string { return s.LoginFor },
		func(st *store.State, v string) (err error) {
			v, err = positiveDur("login_for", v, false)
			if err != nil {
				return err
			}
			now, _ := parseDur(st.Settings.LoginFor)
			if d, _ := parseDur(v); d > now {
				if err := guardSafety("keeping server logins longer (login_for " + v + ")"); err != nil {
					return err
				}
			}
			st.Settings.LoginFor = v
			return nil
		}},
	{"vpn_idle", "duration, 0 = never", "a VPN kept up with `vpn up` is closed after this long unused",
		func(s *store.Settings) string { return s.VpnIdle },
		func(st *store.State, v string) (err error) {
			st.Settings.VpnIdle, err = positiveDur("vpn_idle", v, true)
			return err
		}},
}

func settingKeys() []string {
	k := make([]string, len(settings))
	for i, s := range settings {
		k[i] = s.Key
	}
	return k
}

func findSetting(key string) (*setting, error) {
	for i := range settings {
		if settings[i].Key == strings.ToLower(strings.ReplaceAll(key, "-", "_")) {
			return &settings[i], nil
		}
	}
	hint := "settings: " + strings.Join(settingKeys(), ", ")
	if c := closest(key, settingKeys()); c != "" {
		hint = "did you mean " + c + "? (" + hint + ")"
	}
	return nil, out.Errf(out.ExitUsage, "UNKNOWN_SETTING", hint, "unknown setting %q", key)
}

type configRow struct {
	Key     string `json:"key"`
	Value   string `json:"value"`
	Default string `json:"default"`
	Values  string `json:"values"`
}

type configShow struct {
	Settings store.Settings    `json:"settings"`
	Home     string            `json:"home"`
	Files    map[string]string `json:"files"`
	Rows     []configRow       `json:"-"`
}

func (c configShow) Text() string {
	var rows [][]string
	for _, r := range c.Rows {
		rows = append(rows, []string{r.Key, r.Value, r.Default, r.Values})
	}
	t := textTable([]string{"KEY", "VALUE", "DEFAULT", "ALLOWED"}, rows)
	if len(c.Settings.ExtraDenyPattern) > 0 {
		t += "\ncustom deny rules: " + strings.Join(c.Settings.ExtraDenyPattern, "  ") + "\n"
	}
	var files [][]string
	for _, k := range []string{"state", "vault", "known_hosts", "audit"} {
		files = append(files, []string{k, c.Files[k]})
	}
	return t + "\n" + textTable([]string{"FILE", "PATH"}, files)
}

type configValue struct {
	Key     string `json:"key"`
	Value   string `json:"value"`
	Default string `json:"default"`
	Old     string `json:"old,omitempty"`
}

func (c configValue) Text() string { return c.Value }

// configSet is what `config set` prints: the same fields, and for people
// the change in one line (parallel: 10 → 5).
type configSet struct{ configValue }

func (c configSet) Text() string {
	if c.Old == c.Value {
		return c.Key + ": already " + dash(c.Value) + "\n"
	}
	return c.Key + ": " + dash(c.Old) + " → " + dash(c.Value) + "\n"
}

func configCmd() *cobra.Command {
	c := &cobra.Command{Use: "config", Short: "Show or change settings: timeouts, parallelism, host keys, audit"}
	var keysHelp strings.Builder
	for _, s := range settings {
		keysHelp.WriteString("  " + s.Key + strings.Repeat(" ", 17-len(s.Key)) + s.Values + "\n      " + s.Help + "\n")
	}
	def := store.DefaultSettings()
	c.AddCommand(&cobra.Command{
		Use:   "show",
		Short: "Show settings, their defaults and file locations",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			st, err := loadState()
			if err != nil {
				return err
			}
			res := configShow{Settings: st.Settings, Home: store.Home(), Files: dataFiles()}
			for _, s := range settings {
				res.Rows = append(res.Rows, configRow{s.Key, s.get(&st.Settings), s.get(&def), s.Values})
			}
			out.P.Print("config.show", res, nil)
			return nil
		},
	})
	c.AddCommand(&cobra.Command{
		Use:     "get KEY",
		Short:   "Print one setting",
		Example: "  komando config get parallel\n  komando config get host_key_policy -o text",
		Args:    cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			s, err := findSetting(args[0])
			if err != nil {
				return err
			}
			st, err := loadState()
			if err != nil {
				return err
			}
			out.P.Print("config.get", configValue{Key: s.Key, Value: s.get(&st.Settings), Default: s.get(&def)}, nil)
			return nil
		},
	})
	set := &cobra.Command{
		Use:   "set KEY VALUE",
		Short: "Change a setting",
		Long:  "Settings:\n" + keysHelp.String() + "\nA value that starts with - goes after --: komando config set vpn_idle -- 0",
		Example: `  komando config set parallel 20
  komando config set default_timeout 10m
  komando config set host_key_policy strict
  komando config set audit_sql hash`,
		Args: cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			s, err := findSetting(args[0])
			if err != nil {
				return err
			}
			var res configValue
			// validate and ask a person (a safety change) on a copy first:
			// the state file stays unlocked while someone answers
			if st0, err := loadState(); err == nil {
				if err := s.set(st0, strings.TrimSpace(args[1])); err != nil {
					return err
				}
			}
			err = store.Update(func(st *store.State) error {
				old := s.get(&st.Settings)
				if err := s.set(st, strings.TrimSpace(args[1])); err != nil {
					return err
				}
				res = configValue{Key: s.Key, Value: s.get(&st.Settings), Default: s.get(&def), Old: old}
				return nil
			})
			if err != nil {
				return err
			}
			audit(nil, "config.set", nil, "", true, map[string]any{"key": res.Key, "old": res.Old, "new": res.Value})
			out.P.Print("config.set", configSet{res}, nil)
			return nil
		},
	}
	// `config set parallel -3`: say what is wrong with the value, not
	// "unknown shorthand flag"
	set.SetFlagErrorFunc(func(cmd *cobra.Command, err error) error {
		if strings.Contains(err.Error(), "shorthand flag") || strings.Contains(err.Error(), "unknown flag") {
			for _, a := range cmd.Flags().Args() {
				if s, e := findSetting(a); e == nil {
					return out.Errf(out.ExitUsage, "USAGE", "a value starting with - goes after --: komando config set "+s.Key+" -- VALUE ("+s.Key+" takes "+s.Values+")",
						"%v", err)
				}
			}
			return out.Errf(out.ExitUsage, "USAGE", "a value starting with - goes after --: komando config set KEY -- VALUE", "%v", err)
		}
		return err
	})
	c.AddCommand(set, approvalCodeCmd())
	return c
}

// dataFiles is where komando keeps each kind of data: one sealed file for
// all but the runtime data.
func dataFiles() map[string]string {
	db := store.Path(store.StoreFile)
	return map[string]string{"state": db, "runtime": store.Path("runtime.json"), "vault": db, "known_hosts": db, "audit": db}
}
