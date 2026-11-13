package cli

import (
	"slices"
	"strings"
	"testing"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"

	"github.com/sgnd/komando/internal/driver"
	"github.com/sgnd/komando/internal/netx"
	"github.com/sgnd/komando/internal/store"
)

// formParse checks that komando takes a line a form built: the command
// exists, its flags exist and parse, its arguments fit the command.
func formParse(t *testing.T, source string, args []string) *cobra.Command {
	t.Helper()
	root := newRoot()
	cmd, rest, err := root.Find(args)
	if err != nil || cmd == root || !cmd.Runnable() {
		t.Errorf("%s: `komando %s`: no such command", source, strings.Join(args, " "))
		return nil
	}
	if err := cmd.ParseFlags(rest); err != nil {
		t.Errorf("%s: `komando %s`: %v", source, menuCommandLine(args), err)
		return nil
	}
	if err := cmd.ValidateArgs(cmd.Flags().Args()); err != nil {
		t.Errorf("%s: `komando %s`: %v", source, menuCommandLine(args), err)
	}
	return cmd
}

// formSample is an answer a question takes: its first choice, its example
// or a plain word.
func formSample(st *store.State, q formQ, a formAnswers) string {
	if q.choices != nil {
		if rows := q.choices(st, a); len(rows) > 0 {
			return rows[0].value
		}
	}
	if d := formDefault(st, q, a); d != "" {
		return d
	}
	if q.check != nil {
		for _, v := range []string{"web9", "10.0.0.5", "5", "5m", "1.5", "x", "my-project", "eu-west-1", "123456789012"} {
			if q.check(st, a, v) == "" {
				return v
			}
		}
	}
	return "web9"
}

// Every command's generated questions build a line komando takes, with
// only the asked questions answered and with every flag set too.
func TestFormEveryCommandBuilds(t *testing.T) {
	st := testState()
	n := 0
	var walk func(c *cobra.Command)
	walk = func(c *cobra.Command) {
		for _, s := range c.Commands() {
			walk(s)
			if !s.Runnable() || s.Hidden || s.Name() == "help" { // a hand-made form's command has Every option too
				continue
			}
			n++
			sp := formCmdSpec(s)
			for _, every := range []bool{false, true} {
				a := formAnswers{}
				for _, q := range sp.qs {
					if q.visible(st, a) && (every || !q.advanced) {
						a[q.key] = formSample(st, q, a)
					}
				}
				for _, line := range sp.build(st, a) {
					formParse(t, commandKey(s), line)
					formNoApproval(t, commandKey(s), line)
				}
				// Try it first is a dry run, never the real thing
				if dry := formDry(sp.build(st, a)); true {
					if c := formParse(t, commandKey(s)+" (try)", dry); c != nil {
						if f := c.Flags().Lookup("dry-run"); f == nil || !f.Changed {
							t.Errorf("%s: Try it first runs `komando %s` for real", commandKey(s), menuCommandLine(dry))
						}
					}
				}
			}
		}
	}
	walk(newRoot())
	if n < 150 {
		t.Errorf("only %d commands have questions", n)
	}
}

// formNoApproval: a form's line never carries a flag that approves or
// shows something for the person (docs/design/principles.md, section 11).
func formNoApproval(t *testing.T, source string, line []string) {
	t.Helper()
	for _, w := range line {
		if w == "--" {
			return // the rest is the remote command's own words
		}
		name := strings.SplitN(strings.TrimLeft(w, "-"), "=", 2)[0]
		if strings.HasPrefix(w, "--") && slices.Contains([]string{"yes", "allow-dangerous", "reveal", "dry-run"}, name) {
			t.Errorf("%s: `komando %s` has %s", source, menuCommandLine(line), w)
		}
	}
}

// Even a hint that names an approval flag, or adds it to every line,
// cannot put it in a form's command.
func TestFormHintCannotApprove(t *testing.T) {
	root := &cobra.Command{Use: "komando"}
	c := &cobra.Command{Use: "zap TARGET", Run: func(*cobra.Command, []string) {}}
	for _, n := range []string{"yes", "allow-dangerous", "reveal", "force"} {
		c.Flags().Bool(n, false, n)
	}
	root.AddCommand(c)
	formHints["zap"] = formHint{flags: []formFlag{{name: "yes"}, {name: "reveal"}, {name: "force"}},
		always: []string{"--allow-dangerous", "--yes=true"}}
	defer delete(formHints, "zap")
	sp := formCmdSpec(c)
	a := formAnswers{"arg0": "web-1", "flag:yes": "true", "flag:reveal": "true", "flag:allow-dangerous": "true", "flag:force": "true"}
	for _, q := range sp.qs {
		if q.key == "flag:yes" || q.key == "flag:reveal" || q.key == "flag:allow-dangerous" {
			t.Errorf("asked %s", q.key)
		}
	}
	got := sp.build(nil, a)[0]
	formNoApproval(t, "zap", got)
	if !slices.Contains(got, "--force") {
		t.Errorf("an ordinary flag was lost: %v", got)
	}
}

// Every command is in an area of formAreas.
func TestFormEveryCommandHasAnArea(t *testing.T) {
	root := newRoot()
	var walk func(c *cobra.Command)
	walk = func(c *cobra.Command) {
		for _, s := range c.Commands() {
			walk(s)
			if s.Runnable() && !s.Hidden && s.Deprecated == "" && s.Name() != "help" && formAreaOf(s) < 0 {
				t.Errorf("%s is in no area of formAreas", commandKey(s))
			}
		}
	}
	walk(root)
	for p, h := range formHints {
		c, _, err := root.Find(strings.Fields(p))
		if err != nil || commandKey(c) != p {
			t.Errorf("hint for %q: no such command", p)
			continue
		}
		if h.area != "" && !slices.ContainsFunc(formAreas, func(a struct {
			label, detail string
			words         []string
		}) bool {
			return a.label == h.area
		}) {
			t.Errorf("hint for %q: no area %q", p, h.area)
		}
		for _, f := range h.flags {
			if c.Flags().Lookup(f.name) == nil {
				t.Errorf("hint for %q: no flag --%s", p, f.name)
			}
		}
	}
}

// The hand-made Add forms build lines komando takes, and conn URLs the
// drivers read, for every kind and every choice of their first questions.
func TestFormAddKindsBuild(t *testing.T) {
	for _, st := range []*store.State{testState(), {Hosts: map[string]*store.Host{}}} {
		for _, g := range formGroups() {
			for _, k := range g.kinds {
				sp := k.spec()
				a := formAnswers{}
				for _, q := range sp.qs {
					if q.visible(st, a) {
						a[q.key] = formSample(st, q, a)
					}
				}
				for _, line := range sp.build(st, a) {
					cmd := formParse(t, g.label+"/"+k.label, line)
					if cmd != nil && commandKey(cmd) == "conn add" {
						if _, err := driver.Parse(cmd.Flags().Arg(1)); err != nil {
							t.Errorf("%s/%s: URL %q: %v", g.label, k.label, cmd.Flags().Arg(1), err)
						}
					}
				}
			}
		}
	}
}

func TestFormUseArgs(t *testing.T) {
	cases := map[string]string{
		"query CONN [SQL]":                                               "CONN [SQL]",
		"exec TARGET [--] COMMAND...":                                    "TARGET --COMMAND...",
		"add NAME [user@address[:port]]":                                 "NAME [user@address]",
		"replace TARGET PATH --old TEXT --new TEXT":                      "TARGET PATH",
		"grant CONN USER (--privileges P,... --on OBJECT | --role ROLE)": "CONN USER",
		"edit NAME|TARGET...":                                            "NAME...",
		"start TARGET [-L spec | -R spec | -D spec]":                     "TARGET",
		"list [flags]":                                                   "",
	}
	for use, want := range cases {
		var got []string
		for _, u := range formUseArgs(use, nil) {
			w := u.name
			if u.many {
				w += "..."
			}
			if u.dashes {
				w = "--" + w
			}
			if u.optional {
				w = "[" + w + "]"
			}
			got = append(got, w)
		}
		if strings.Join(got, " ") != want {
			t.Errorf("%q: %q, want %q", use, strings.Join(got, " "), want)
		}
	}
}

func TestPastedSecret(t *testing.T) {
	cases := map[string]string{
		"root:hunter2@203.0.113.20":          "root@203.0.113.20",
		"root:p@ssw0rd@203.0.113.20":         "root@203.0.113.20",
		"postgres://app:s3cret@10.0.0.5/app": "postgres://app@10.0.0.5/app",
		"root@203.0.113.20":                  "",
		"10.0.0.5:2222":                      "",
		"https://minio.internal:9000":        "",
		"deploy@[2001:db8::1]":               "",
	}
	for in, want := range cases {
		got, found := pastedSecret(in)
		if found != (want != "") || (found && got != want) {
			t.Errorf("%q: %q %v, want %q", in, got, found, want)
		}
	}
}

func TestFormNameProblem(t *testing.T) {
	st := testState()
	for _, n := range menuNames(st.Hosts, "host")[:1] {
		p := formNameProblem(st, "host", strings.ToUpper(n))
		if !strings.Contains(p, "already a server") || strings.Contains(p, "like "+n+",") {
			t.Errorf("taken name %s: %q", n, p)
		}
	}
	for v, want := range map[string]string{"all": "means everything", "-x": "letters", "a b": "letters", "fresh1": ""} {
		if p := formNameProblem(st, "host", v); (want == "") != (p == "") || !strings.Contains(p, want) {
			t.Errorf("%q: %q, want %q", v, p, want)
		}
	}
}

// `komando host add` alone at a person's terminal asks the server's own
// questions line by line; a pasted user:password@ is never drawn, the
// lines are shown before they run, and No adds nothing.
func TestFormHostAddAtATerminal(t *testing.T) {
	if testing.Short() {
		t.Skip("starts a process")
	}
	invHome(t)
	p := startPTYEnv(t, []string{"KOMANDO_PTY_AS=person"}, "host", "add")
	p.answer("Name, like web1: ", "web1\r")
	p.answer("Address, like", "root:hun@ter2@203.0.113.20\r")
	p.answer("a password was in it", "\r") // User [root]
	p.answer("System [Linux]: ", "\r")
	p.answer("Port [22]: ", "\r")
	p.answer("Login [My SSH key]: ", "2\r") // A password
	p.answer("Production [Yes, protect it]: ", "\r")
	p.waitFor("$ komando host add web1 root@203.0.113.20 --ask-password --protected")
	p.waitFor("$ komando test web1")
	p.answer("Run it? [y/N, d = --dry-run first]: ", "\r") // Enter is No: exit 6 (S-8.9)
	if code := p.exit(); code != 6 || !strings.Contains(p.shown(), "Cancelled. Nothing was changed.") {
		t.Errorf("exit %d; the screen:\n%s", code, p.shown())
	}
	if strings.Contains(p.shown(), "ter2") || strings.Contains(p.shown(), "hun") {
		t.Errorf("the pasted password was drawn:\n%s", p.shown())
	}
	if _, err := invRun(t, "host", "show", "web1"); err == nil {
		t.Error("web1 was added after No")
	}
}

// Ctrl-C at any question of an add stops it, and nothing was added.
func TestFormAddCtrlC(t *testing.T) {
	if testing.Short() {
		t.Skip("starts a process")
	}
	invHome(t)
	p := startPTYEnv(t, []string{"KOMANDO_PTY_AS=person"}, "db", "add")
	p.answer("KIND: ", "\x03")
	if code := p.exit(); code != 1 || !strings.Contains(p.shown(), "Stopped.") {
		t.Errorf("exit %d; the screen:\n%s", code, p.shown())
	}
	if echo, _ := p.leftTerminal(); !echo {
		t.Error("the terminal was left without echo")
	}
}

// An AI agent (or a script) that types an add command alone gets the usual
// usage error, never questions.
func TestFormAddAloneForAgents(t *testing.T) {
	invHome(t)
	for _, kind := range []string{"host", "conn", "vpn"} {
		_, e := invRun(t, kind, "add")
		if e == nil || e.Code != "USAGE" || !strings.Contains(e.Hint, "alone at a terminal") {
			t.Errorf("%s add: %+v", kind, e)
		}
	}
}

func TestFormDryRunBeforeDashes(t *testing.T) {
	got := formDry([][]string{{"exec", "web1", "--", "systemctl restart nginx"}})
	if strings.Join(got, "|") != "exec|web1|--dry-run|--|systemctl restart nginx" {
		t.Errorf("exec dry run: %q", got)
	}
	got = formDry([][]string{{"secret", "set", "x-authkey"}, {"vpn", "add", "x", "tailscale"}})
	if got[0] != "vpn" {
		t.Errorf("Try it first tries the secret set: %q", got)
	}
}

func TestFormSplitWords(t *testing.T) {
	cases := map[string]string{
		`-c 'ls | wc -l'`:     `-c|ls | wc -l`,
		`a "b c" d`:           `a|b c|d`,
		`  one   two `:        `one|two`,
		`it\'s`:               `it's`,
		`find /tmp -mtime +7`: `find|/tmp|-mtime|+7`,
	}
	for in, want := range cases {
		if got := strings.Join(formSplitWords(in), "|"); got != want {
			t.Errorf("%q: %q, want %q", in, got, want)
		}
	}
}

// Nothing is left out of the menu: every command it lists has a hint
// (written for it, even an empty one), every conn kind and VPN kind has an
// Add form, and every flag a person could need is offered.
func TestFormEveryCommandHasAHint(t *testing.T) {
	var walk func(c *cobra.Command)
	walk = func(c *cobra.Command) {
		for _, s := range c.Commands() {
			walk(s)
			if formListed(s) && s.Name() != "help" {
				if _, ok := formHints[commandKey(s)]; !ok {
					t.Errorf("%s has no formHint: give it one (form_hints_*.go), so its questions read well", commandKey(s))
				}
			}
		}
	}
	walk(newRoot())
}

// formKindCovers says which conn kinds (driver) and VPN kinds (netx) each
// Add form adds. A new kind needs a form and a line here.
var formKindCovers = map[string][]string{
	"Server": nil, "PostgreSQL": {"postgres"}, "MySQL or MariaDB": {"mysql"}, "MongoDB": {"mongodb"}, "SQLite": {"sqlite"},
	"Redis or Valkey": {"redis"}, "Memcached": {"memcached"},
	"S3 bucket": {"s3"}, "SFTP file server": {"sftp"}, "FTP or FTPS file server": {"ftp", "ftps"},
	"Google Cloud Storage bucket": {"gcs"}, "Azure Blob Storage container": {"azblob"}, "WebDAV folder": {"webdav"},
	"Kubernetes": {"k8s"}, "Docker Swarm": nil,
	"Docker Hub": {"registry"}, "GitHub": {"registry"}, "GitLab": {"registry"}, "Amazon ECR": {"registry"},
	"Your own registry": {"registry"}, "From docker login": {"registry"},
	"WireGuard": {"wireguard"}, "OpenVPN or Pritunl": {"openvpn"}, "Tailscale or Headscale": {"tailscale"},
	"GlobalProtect": {"globalprotect"}, "FortiClient": {"fortinet"}, "Cisco AnyConnect": {"anyconnect"},
	"Pulse Secure or Ivanti": {"pulse"}, "F5 BIG-IP": {"f5"}, "L2TP/IPsec": {"l2tp"}, "Cisco IPsec": {"ipsec"},
	"IKEv2": {"ikev2"}, "A VPN on this computer": {"system"}, "SOCKS proxy": {"socks"}, "HTTP proxy": {"proxy"},
	"SQL Server": {"sqlserver"}, "Oracle Database": {"oracle"}, "ClickHouse": {"clickhouse"},
	"Snowflake": {"snowflake"}, "Google BigQuery": {"bigquery"},
	"Apache Kafka": {"kafka"}, "RabbitMQ": {"rabbitmq"}, "NATS JetStream": {"nats"}, "Amazon SQS": {"sqs"},
	"Google Cloud Pub/Sub": {"pubsub"}, "Windows share (SMB)": {"smb"},
	"Azure Container Registry": {"registry"}, "Google Artifact Registry": {"registry"},
}

func TestFormEveryKindHasAnAddForm(t *testing.T) {
	covered := map[string]bool{}
	for _, g := range formGroups() {
		for _, k := range g.kinds {
			kinds, ok := formKindCovers[k.label]
			if !ok {
				t.Errorf("Add form %q is not in formKindCovers", k.label)
			}
			for _, x := range kinds {
				covered[x] = true
			}
		}
	}
	for _, k := range driver.Kinds() {
		if !covered[k.Name] {
			t.Errorf("conn kind %s has no Add form", k.Name)
		}
	}
	for _, k := range netx.KindNames() {
		if !covered[k] {
			t.Errorf("VPN kind %s has no Add form", k)
		}
	}
}

// Every example in every command's --help can be made from its questions:
// each flag it uses is offered (the menu leaves out only --yes,
// --allow-dangerous, --reveal, -o and --dry-run, which a person gives when
// the command asks), and its words fit the command's arguments.
func TestFormEveryHelpExampleIsReachable(t *testing.T) {
	root := newRoot()
	n := 0
	var walk func(c *cobra.Command)
	walk = func(c *cobra.Command) {
		for _, s := range c.Commands() {
			walk(s)
			if !formListed(s) || s.Name() == "help" {
				continue
			}
			offered := map[string]bool{}
			for _, q := range formCmdSpec(s).qs {
				if f, ok := strings.CutPrefix(q.key, "flag:"); ok {
					offered[f] = true
				}
			}
			for _, line := range strings.Split(s.Example, "\n") {
				line = strings.TrimSpace(line)
				if i := strings.Index(line, " #"); i >= 0 {
					line = line[:i]
				}
				words := formSplitWords(line)
				key := strings.Fields(commandKey(s))
				if len(words) < len(key)+1 || words[0] != "komando" {
					continue // prose
				}
				if found, _, err := root.Find(words[1:]); err != nil || found != s {
					continue // an example of another command (login aws in login's help)
				}
				n++
				for i := len(key) + 1; i < len(words); i++ {
					w := words[i]
					if w == "--" {
						break
					}
					if !strings.HasPrefix(w, "-") || w == "-" {
						continue
					}
					name, _, _ := strings.Cut(strings.TrimLeft(w, "-"), "=")
					f := s.Flags().Lookup(name)
					if f == nil && len(name) == 1 {
						f = s.Flags().ShorthandLookup(name)
					}
					if f == nil {
						t.Errorf("%s example %q: no flag %s", commandKey(s), line, w)
						continue
					}
					if f.Value.Type() != "bool" && !strings.Contains(w, "=") {
						i++ // its value
					}
					h := formHints[commandKey(s)]
					_, why := formHides[commandKey(s)+" "+f.Name]
					if f.Hidden || why || slices.Contains(h.always, "--"+f.Name) {
						continue // an old alias of an offered flag, or added to every line
					}
					if !offered[f.Name] && !slices.Contains(formNeverFlags, f.Name) && root.PersistentFlags().Lookup(f.Name) == nil {
						t.Errorf("%s: the menu never offers --%s, which its example `%s` uses", commandKey(s), f.Name, line)
					}
				}
			}
		}
	}
	walk(root)
	if n < 200 {
		t.Errorf("only %d examples checked", n)
	}
}

// A flag the command marks required is asked among the first questions.
func TestFormRequiredFlagsAreAsked(t *testing.T) {
	var walk func(c *cobra.Command)
	walk = func(c *cobra.Command) {
		for _, s := range c.Commands() {
			walk(s)
			if !formListed(s) {
				continue
			}
			sp := formCmdSpec(s)
			s.Flags().VisitAll(func(f *pflag.Flag) {
				if _, req := f.Annotations[cobra.BashCompOneRequiredFlag]; !req {
					return
				}
				i := slices.IndexFunc(sp.qs, func(q formQ) bool { return q.key == "flag:"+f.Name })
				if i < 0 || sp.qs[i].advanced || sp.qs[i].optional {
					t.Errorf("%s: required flag --%s is not one of the first questions", commandKey(s), f.Name)
				}
			})
		}
	}
	walk(newRoot())
}

// formHides are the flags a hint keeps out of the menu, each with why. Any
// other hide fails: the menu leaves nothing out without a reason.
var formHides = map[string]string{
	"host edit group":        "-g is --add-group, which is asked",
	"host edit tag":          "-t is --add-tag, which is asked",
	"conn edit group":        "-g is --add-group, which is asked",
	"conn edit tag":          "-t is --add-tag, which is asked",
	"job start cmd":          "the same as the command words, which are asked",
	"exec cmd":               "the same as the command words, which are asked",
	"guide install no-guard": "it turns off the guard that keeps AI agents away from secret files",
	"rename starts-with":     "always added: the menu renames by the start of the names",
}

func TestFormHidesHaveAReason(t *testing.T) {
	for p, h := range formHints {
		for _, f := range h.hide {
			if _, ok := formHides[p+" "+f]; !ok {
				t.Errorf("%s hides --%s with no reason in formHides", p, f)
			}
		}
	}
}

// A database to back up is picked like any conn, at a prompt and by shell
// completion; saved commands, what to go through and settings are lists.
func TestFormPickKinds(t *testing.T) {
	invHome(t)
	mustRun(t, "host", "add", "web1", "root@10.0.0.5")
	mustRun(t, "conn", "add", "app-db", "postgres://app@10.0.0.9/app")
	mustRun(t, "recipe", "add", "up", "uptime")
	root := newRoot()
	c, _, _ := root.Find([]string{"db", "dump"})
	got, _ := c.ValidArgsFunction(c, nil, "")
	if !slices.Contains(got, "app-db") {
		t.Errorf("db dump <TAB>: %v", got)
	}
	if p, _ := formArgPick("SERVER"); p != "server" {
		t.Errorf("SERVER picks %q", p) // one server (S-4.2)
	}
	st, _ := loadState()
	names := func(rows []menuRow) (n []string) {
		for _, r := range rows {
			n = append(n, r.value)
		}
		return n
	}
	for kind, want := range map[string]string{"recipe": "up", "via": "web1", "setting": "audit"} {
		if got := names(formPickRows(st, kind)); !slices.Contains(got, want) {
			t.Errorf("%s rows: %v, want %s in them", kind, got, want)
		}
	}
	e, _, _ := root.Find([]string{"host", "edit"})
	for _, q := range formCmdSpec(e).qs {
		if q.key == "flag:via" && q.choices == nil {
			t.Error("--via is typed, not picked")
		}
	}
}
