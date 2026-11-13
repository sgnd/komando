package cli

import (
	"bufio"
	"cmp"
	"fmt"
	"net/url"
	"os"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/sgnd/komando/internal/driver"
	"github.com/sgnd/komando/internal/out"
	"github.com/sgnd/komando/internal/store"
	"github.com/sgnd/komando/internal/vault"
)

// `komando import SOURCE` brings in what people already have: ssh config,
// .pgpass, my.cnf, .env files and komando exports. Passwords found along
// the way go to the vault and are referenced as secret:NAME; they never
// reach state.json, the output or the audit log.

// importPlan is what a source would add. Secrets maps vault names to
// values and is never printed.
type importPlan struct {
	Hosts   []*store.Host
	Conns   []*store.Conn
	Recipes []*store.Snippet
	Vpns    []*store.Vpn
	Secrets map[string]string
	Notes   []string // things in the source komando did not import, and why
	// NoPassword: conns the source keeps no password for (DBeaver). The
	// note that says how to set one is written after the import, with the
	// name the conn got (shop-2 when shop is taken), and only if it is added.
	NoPassword map[*store.Conn]bool
	// ConnNotes are about a conn the import adds (how it logs in); they
	// land in the result's notes only if it is added.
	ConnNotes map[*store.Conn][]string
	// Strict: a server komando refuses stops the whole import (a CSV is a
	// list the user wrote for komando; a half import would surprise them).
	Strict bool
	// OwnRefs: the file is the user's own list of servers, like typing
	// `host add` for each row, so its password and sudo references are
	// kept even when they name secrets that exist already.
	OwnRefs bool
	// DenyRules and Settings come from a whole komando export. Deny rules
	// are added (they only stop more); settings are compared, never set,
	// as a file from someone else must not turn a check off.
	DenyRules []string
	Settings  map[string]string
}

type importSource struct {
	Name, Default, Desc string
	Parse               func(path string) (*importPlan, error)
}

var importSources = []importSource{
	{"ssh-config", "~/.ssh/config", "servers from your OpenSSH config", importSSHConfig},
	{"pgpass", "~/.pgpass", "PostgreSQL databases and their passwords", importPgpass},
	{"mycnf", "~/.my.cnf", "MySQL/MariaDB databases from [client] sections", importMycnf},
	{"env", ".env", "database, cache and storage URLs (DATABASE_URL, REDIS_URL, ...)", importEnv},
	{"kubeconfig", "~/.kube/config", "Kubernetes clusters, one conn per context", importKubeconfig},
	{"docker", "~/.docker/config.json", "container registries you are logged in to", importDocker},
	{"filezilla", "~/.config/filezilla/sitemanager.xml", "SFTP sites from FileZilla's Site Manager", importFileZilla},
	{"rclone", "~/.config/rclone/rclone.conf", "SFTP remotes from rclone", importRclone},
	{"aws", "~/.aws/config", "an S3 storage conn per bucket of each AWS profile (uses the profile; no key is copied)", importAWS},
	{"aws-ec2", "~/.aws/config", "a server per running EC2 instance of each AWS profile, in its region (read only, with the profile's login)", importAWSEC2},
	{"dbeaver", "~/Library/DBeaverData/workspace6/General/.dbeaver/data-sources.json", "databases from DBeaver (passwords set afterwards)", importDBeaver},
	{"komando", "", "a file made by `komando export` (moving to another computer)", importKomando},
	{"csv", "", "servers from a spreadsheet (CSV, first row names the columns: " + csvColumnList + ")", importCSV},
}

func importCmd() *cobra.Command {
	var groups []string
	var overwrite bool
	var names []string
	for _, s := range importSources {
		line := fmt.Sprintf("  %-11s %s", s.Name, s.Desc)
		if s.Default != "" {
			line += " (default " + s.Default + ")"
		}
		names = append(names, line)
	}
	c := &cobra.Command{
		Use:   "import SOURCE [FILE]",
		Short: "Bring in what you have: ssh config, .pgpass, my.cnf, .env",
		Long: "Adds servers, conns, VPNs and recipes from files you already have.\n\nSources:\n" + strings.Join(names, "\n") + `

Passwords go to the vault (as <name>-pass; a kubeconfig as
<name>-kubeconfig) and are referenced from the conn; they are never
printed. Existing names are skipped unless
--overwrite (replacing a protected one also needs --yes). Proxy commands
from an ssh config run on this computer, so an AI agent needs a person's yes
for them. Try --dry-run first to see what would be added.`,
		Example: `  komando import ssh-config --dry-run
  komando import pgpass
  komando import env ./app/.env --group shop
  komando import komando backup.json`,
		Args: cobra.RangeArgs(1, 2),
		RunE: func(cmd *cobra.Command, args []string) error {
			path := ""
			if len(args) == 2 {
				path = args[1]
			}
			return runImport(args[0], path, groups, overwrite)
		},
	}
	c.Flags().StringSliceVarP(&groups, "group", "g", nil, "add everything imported to these groups")
	c.Flags().BoolVar(&overwrite, "overwrite", false, "replace servers, conns and recipes with the same name")
	return c
}

// runImport is `komando import SOURCE [FILE]`; an empty path is the
// source's usual file.
func runImport(source, path string, groups []string, overwrite bool) error {
	var src *importSource
	for i := range importSources {
		if importSources[i].Name == source {
			src = &importSources[i]
		}
	}
	if src == nil {
		var all []string
		for _, s := range importSources {
			all = append(all, s.Name)
		}
		return out.Errf(out.ExitUsage, "USAGE", "use one of: "+strings.Join(all, ", ")+" (`komando import --help` says what each brings in)",
			"komando cannot import from %q", source)
	}
	if path == "" {
		path = src.Default
		if env := os.Getenv("KUBECONFIG"); src.Name == "kubeconfig" && env != "" {
			path = env // the files kubectl reads, a:b merged as kubectl merges them
		}
	}
	if path == "" {
		return out.Errf(out.ExitUsage, "USAGE", "for example: komando import "+src.Name+" "+map[string]string{"komando": "komando-backup.json", "csv": "servers.csv"}[src.Name],
			"give the file to import")
	}
	plan, err := src.Parse(expandHome(path))
	if err != nil {
		return err
	}
	return applyImport(src.Name, path, plan, groups, overwrite)
}

// importProtectedSkip is why an import with --overwrite leaves a protected
// server or conn as it is.
const importProtectedSkip = "protected: replacing it needs --yes after the user confirms"

type importSkip struct {
	Name   string `json:"name"`
	Reason string `json:"reason"`
}

type importResult struct {
	Action   string       `json:"action"` // added | would_add
	Source   string       `json:"source"`
	File     string       `json:"file"`
	Hosts    []string     `json:"hosts"`
	Conns    []string     `json:"conns"`
	Vpns     []string     `json:"vpns"`
	Recipes  []string     `json:"recipes"`
	Secrets  []string     `json:"secrets"` // vault names stored (never values)
	Skipped  []importSkip `json:"skipped"`
	NotFound []string     `json:"not_imported"` // in the source, but not something komando imports
	// DenyRules: deny rules added from the file; SettingsDiffer: settings
	// the file has otherwise, left as they are here, with the command
	DenyRules      []string         `json:"deny_rules_added,omitempty"`
	SettingsDiffer []settingDiffers `json:"settings_differ,omitempty"`
	// Notes are about what was added (how a conn logs in, why it got its
	// name); not_imported is only about what was left out.
	Notes []string `json:"notes,omitempty"`
	// Replaced are the names among those added that were there before
	// (--overwrite): their old settings are gone.
	Replaced []string `json:"replaced,omitempty"`
	// Next is the command that checks what came in (import -> test).
	Next string `json:"next,omitempty"`
	// aboutAdded are the notes in NotFound about a server that was added
	// (what was left out of it): the text output does not call them "not
	// imported". JSON keeps them in not_imported.
	aboutAdded []string
}

func applyImport(source, file string, plan *importPlan, groups []string, overwrite bool) error {
	res := importResult{Source: source, File: file, Hosts: []string{}, Conns: []string{}, Vpns: []string{}, Recipes: []string{},
		Secrets: []string{}, Skipped: []importSkip{}, NotFound: plan.Notes}
	if res.NotFound == nil {
		res.NotFound = []string{}
	}
	st, err := loadState()
	if err != nil {
		return err
	}
	existed := entryNames(st) // before this import puts anything in st
	// decide first, so secrets are stored only for what is really added
	skip := importSkipper(st, overwrite)
	var vpns []*store.Vpn
	for _, v := range plan.Vpns {
		if r := skip("vpn", v.Name); r != "" {
			res.Skipped = append(res.Skipped, importSkip{v.Name, r})
			continue
		}
		vpns = append(vpns, v)
		res.Vpns = append(res.Vpns, v.Name)
	}
	for _, v := range vpns { // so hosts and conns can use them with --via
		st.Vpns[v.Name] = v
	}
	// hosts are checked like host add; they land in st (not saved) so
	// conns can use them with --via
	prefetchTwinIPs(st, plan.Hosts)
	v, err := vetImportHosts(st, plan.Hosts, overwrite, plan.OwnRefs)
	if err != nil {
		return err
	}
	if plan.Strict && len(v.Invalid) > 0 {
		var bad []string
		for _, s := range v.Invalid {
			bad = append(bad, s.Name+": "+s.Reason)
		}
		return out.Errf(out.ExitUsage, "USAGE", "fix these rows and import again; nothing was imported",
			"%s cannot be added: %s", countOf(len(bad), "server"), strings.Join(bad, "; "))
	}
	hosts := v.Add
	for _, n := range v.Existing {
		res.Skipped = append(res.Skipped, importSkip{n, "a server with this name exists (use --overwrite to replace it)"})
	}
	for _, n := range v.Protected {
		res.Skipped = append(res.Skipped, importSkip{n, importProtectedSkip})
	}
	res.Skipped = append(res.Skipped, v.Invalid...)
	res.NotFound, res.aboutAdded = append(res.NotFound, v.Notes...), v.Notes // each note in v.Notes is about a server in v.Add
	conns, err := vetImportConns(st, plan, overwrite, skip, &res)
	if err != nil {
		return err
	}
	var recipes []*store.Snippet
	for _, r := range plan.Recipes {
		if _, ok := st.Snippets[r.Name]; (ok && !overwrite) || builtinRecipe(r.Name) != nil {
			res.Skipped = append(res.Skipped, importSkip{r.Name, "a recipe with this name exists"})
			continue
		}
		recipes = append(recipes, r)
	}
	for _, h := range hosts {
		res.Hosts = append(res.Hosts, h.Name)
	}
	for _, c := range conns {
		res.addConn(c, plan)
	}
	for _, r := range recipes {
		res.Recipes = append(res.Recipes, r.Name)
	}
	res.DenyRules, res.SettingsDiffer = importRulesAndSettings(st, plan)
	res.replacedAndNext(existed, groups)
	res.Action = "added"
	incomplete := importIncomplete(len(v.Invalid))
	if g.dryRun {
		res.Action = "would_add"
		out.P.Print("import", res, toErr(incomplete))
		if incomplete != nil {
			return exitCode(1)
		}
		return nil
	}
	for _, name := range res.Secrets {
		if err := vault.Set(name, plan.Secrets[name]); err != nil {
			return err
		}
	}
	now := time.Now().UTC()
	err = store.Update(func(s *store.State) error {
		for _, h := range hosts {
			h.Groups = dedupe(append(h.Groups, groups...))
			h.CreatedAt, h.UpdatedAt = now, now
			s.Hosts[h.Name] = h
		}
		for _, c := range conns {
			c.Groups = dedupe(append(c.Groups, groups...))
			c.CreatedAt, c.UpdatedAt = now, now
			s.Conns[c.Name] = c
		}
		for _, r := range recipes {
			s.Snippets[r.Name] = r
		}
		for _, v := range vpns {
			v.CreatedAt, v.UpdatedAt = now, now
			s.Vpns[v.Name] = v
		}
		for _, p := range res.DenyRules {
			if !slices.Contains(s.Settings.ExtraDenyPattern, p) {
				s.Settings.ExtraDenyPattern = append(s.Settings.ExtraDenyPattern, p)
			}
		}
		return nil
	})
	if err != nil {
		return err
	}
	audit(st, "import", append(append([]string{}, res.Hosts...), res.Conns...), "", true,
		map[string]any{"source": source, "file": file, "secrets": len(res.Secrets), "deny_rules": res.DenyRules})
	out.P.Print("import", res, toErr(incomplete))
	if incomplete != nil {
		return exitCode(1)
	}
	return nil
}

// vetImportConns picks the conns an import adds, as conn add would, and
// records the rest in res.Skipped. For an AI agent, a conn that sends a
// secret the import does not bring itself (one already in the vault, an
// env: or file: reference), or whose URL turns its network protection
// down, needs a person's yes; the import's own passwords go to the
// address they came with.
func vetImportConns(st *store.State, plan *importPlan, overwrite bool, skip func(kind, name string) string, res *importResult) ([]*store.Conn, error) {
	var conns []*store.Conn
	var sends, weak []string
	for _, c := range plan.Conns {
		c.URL = normConnURL(c.URL)
		// the TLS default conn add applies: verified TLS where the URL says
		// nothing, and no password in clear text over the network unless
		// the URL says ?insecure=1 (docs/features/import.md)
		var tls connResult
		if err := secureConnURL(c, &tls); err != nil {
			e := toErr(err)
			res.Skipped = append(res.Skipped, importSkip{c.Name, e.Message + "; " + e.Hint})
			continue
		}
		// the same database imported again is skipped; a different one that
		// happens to share the name gets the next free name (shop-2)
		name := c.Name
		if old, ok := st.Conns[c.Name]; ok && old.URL != c.URL && !overwrite {
			renameImported(st, plan, c)
		}
		for _, w := range tls.Warnings {
			w = strings.ReplaceAll(w, "`komando test "+name+"`", "`komando test "+c.Name+"`")
			plan.ConnNotes[c] = append(plan.ConnNotes[c], c.Name+": "+w)
		}
		if r := skip("conn", c.Name); r != "" {
			res.Skipped = append(res.Skipped, importSkip{c.Name, r})
			continue
		}
		if err := checkConn(st, c); err != nil {
			res.Skipped = append(res.Skipped, importSkip{c.Name, toErr(err).Message})
			continue
		}
		name, ok := strings.CutPrefix(c.PasswordRef, "secret:")
		if ok && !overwrite {
			if _, err := vault.Get(name); err == nil {
				res.Skipped = append(res.Skipped, importSkip{c.Name, "secret " + name + " already exists (use --overwrite to replace it)"})
				continue
			}
		}
		p := connPlace(c)
		if ok && plan.Secrets[name] != "" { // stored by this import, for this conn
			p.refs = slices.DeleteFunc(p.refs, func(r string) bool { return r == c.PasswordRef })
		}
		line, err := newSends("conn "+c.Name, nil, p)
		if err != nil {
			return nil, err
		}
		sends = append(sends, line)
		for _, w := range weakTLS("", c.URL) {
			weak = append(weak, c.Name+": "+w)
		}
		conns = append(conns, c)
	}
	return conns, guardSends(sends, weak)
}

// addConn records a conn the import adds: its name, the password stored
// for it, and how to set one when the source had none. That note uses the
// conn's final name, so its commands change this conn and no other.
func (r *importResult) addConn(c *store.Conn, plan *importPlan) {
	r.Conns = append(r.Conns, c.Name)
	r.Notes = append(r.Notes, plan.ConnNotes[c]...)
	if name, ok := strings.CutPrefix(c.PasswordRef, "secret:"); ok && plan.Secrets[name] != "" {
		r.Secrets = append(r.Secrets, name)
	}
	if plan.NoPassword[c] {
		note := c.Name + ": set its password with `komando secret set " + c.Name + "-pass` and `komando conn edit " + c.Name + " --password-ref secret:" + c.Name + "-pass`"
		r.NotFound, r.aboutAdded = append(r.NotFound, note), append(r.aboutAdded, note)
	}
}

// entryNames are the names of the servers, conns and VPNs in st.
func entryNames(st *store.State) map[string]bool {
	n := map[string]bool{}
	for k := range st.Hosts {
		n[k] = true
	}
	for k := range st.Conns {
		n[k] = true
	}
	for k := range st.Vpns {
		n[k] = true
	}
	return n
}

// importSkipper says why an entry of kind is not added (or "").
func importSkipper(st *store.State, overwrite bool) func(kind, name string) string {
	return func(kind, name string) string {
		if err := checkEntryName(kind, name); err != nil {
			return toErr(err).Message
		}
		// a protected conn is skipped like a protected server (vetImportHosts),
		// so a dry run lists it as skipped, as the real run does, and the
		// rest of the file still comes in
		if c, ok := st.Conns[name]; ok && kind == "conn" && overwrite && c.Protected && !yesOK() {
			return importProtectedSkip
		}
		if err := checkNewName(st, kind, name, overwrite); err != nil {
			return toErr(err).Message
		}
		return ""
	}
}

// replacedAndNext fills in what the import replaces (names that existed
// before it) and the command that tests what it adds.
func (r *importResult) replacedAndNext(existed map[string]bool, groups []string) {
	added := slices.Concat(r.Hosts, r.Conns, r.Vpns)
	for _, n := range added {
		if existed[n] {
			r.Replaced = append(r.Replaced, n)
		}
	}
	r.Next = importNext(added, groups)
	if r.Next != "" && !g.dryRun {
		sayNext(r.Next)
	}
}

// importNext is the test command for what an import brings in: its group
// when --group was given, the names when they are few, else everything.
func importNext(names, groups []string) string {
	switch {
	case len(names) == 0:
		return ""
	case len(groups) > 0:
		return "komando test @" + groups[0]
	case len(names) <= 5:
		return "komando test " + strings.Join(names, ",")
	}
	return "komando test all"
}

func (r importResult) Text() string {
	var sb strings.Builder
	line := func(label string, names []string) {
		if len(names) > 0 {
			fmt.Fprintf(&sb, "%s: %s\n", label, strings.Join(names, ", "))
		}
	}
	verb := "added"
	if g.dryRun {
		verb = "would add"
	}
	added := slices.Concat(r.Hosts, r.Conns, r.Vpns, r.Recipes)
	if len(added) == 0 { // first, so the notes below cannot read like a success
		fmt.Fprintf(&sb, "nothing to import from %s\n", r.File)
	}
	line("servers "+verb, r.Hosts)
	line("conns "+verb, r.Conns)
	line("VPNs "+verb, r.Vpns)
	line("recipes "+verb, r.Recipes)
	if g.dryRun {
		line("logins it would store in the vault", r.Secrets)
	} else {
		line("logins stored in the vault", r.Secrets)
	}
	if g.dryRun {
		line("of these it would replace", r.Replaced)
	} else {
		line("of these replaced (the old settings are gone)", r.Replaced)
	}
	line("deny rules "+verb, r.DenyRules)
	for _, d := range r.SettingsDiffer {
		fmt.Fprintf(&sb, "setting %s is %s in the file, %s here (not changed; `%s` sets it)\n", d.Key, dash(d.File), dash(d.Here), d.Command)
	}
	for _, s := range r.Skipped {
		fmt.Fprintf(&sb, "skipped %s: %s\n", s.Name, s.Reason)
	}
	for _, n := range r.Notes {
		fmt.Fprintln(&sb, n)
	}
	for _, n := range r.NotFound {
		if slices.Contains(r.aboutAdded, n) { // "bastion: its identity file ...": bastion is in
			fmt.Fprintln(&sb, n)
		} else {
			fmt.Fprintf(&sb, "not imported: %s\n", n)
		}
	}
	return sb.String()
}

// Import sources.

// renameImported gives c the first free name based on its own, moving its
// password to the matching vault name.
func renameImported(st *store.State, plan *importPlan, c *store.Conn) {
	base, name := c.Name, ""
	for i := 2; ; i++ {
		name = fmt.Sprintf("%s-%d", base, i)
		if _, _, taken := st.FindName(name); !taken {
			break
		}
	}
	for _, suffix := range []string{"-pass", "-kubeconfig"} {
		if pw, ok := plan.Secrets[base+suffix]; ok && c.PasswordRef == "secret:"+base+suffix {
			delete(plan.Secrets, base+suffix)
			plan.Secrets[name+suffix] = pw
			c.PasswordRef = "secret:" + name + suffix
		}
	}
	c.Name = name
}

func newPlan() *importPlan {
	return &importPlan{Secrets: map[string]string{}, NoPassword: map[*store.Conn]bool{}, ConnNotes: map[*store.Conn][]string{}}
}

var unsafeName = regexp.MustCompile(`[^A-Za-z0-9._-]+`)

// importName makes a valid, unused name from parts ("shop", "db.lan").
func (p *importPlan) name(parts ...string) string {
	var clean []string
	for _, s := range parts {
		if s = strings.Trim(unsafeName.ReplaceAllString(s, "-"), "-._"); s != "" {
			clean = append(clean, s)
		}
	}
	base := strings.ToLower(strings.Join(clean, "-"))
	if base == "" || base == "all" {
		base = "imported"
	}
	taken := func(n string) bool {
		for _, c := range p.Conns {
			if strings.EqualFold(c.Name, n) {
				return true
			}
		}
		for _, h := range p.Hosts {
			if strings.EqualFold(h.Name, n) {
				return true
			}
		}
		return false
	}
	n := base
	for i := 2; taken(n); i++ {
		n = fmt.Sprintf("%s-%d", base, i)
	}
	return n
}

// addConn adds a conn whose URL may still carry a password: the password
// moves to the plan's secrets and the URL is stored without it.
func (p *importPlan) addConn(name, raw, note string) {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme == "" {
		p.Notes = append(p.Notes, fmt.Sprintf("%s: not a URL", note))
		return
	}
	ref := ""
	if u.User != nil {
		if pw, ok := u.User.Password(); ok {
			ref = "secret:" + name + "-pass"
			p.Secrets[name+"-pass"] = pw
			u.User = url.User(u.User.Username())
		}
	}
	clean := u.String()
	if _, err := driver.Parse(clean); err != nil {
		p.Notes = append(p.Notes, fmt.Sprintf("%s: %s", note, toErr(err).Message))
		delete(p.Secrets, name+"-pass")
		return
	}
	p.Conns = append(p.Conns, &store.Conn{Name: name, URL: clean, PasswordRef: ref})
}

func readSource(path string) ([]byte, error) {
	b, err := readImportFile(path)
	if err != nil {
		return nil, localFileErr("FILE_NOT_FOUND", err, "give the file's path after the source name")
	}
	return b, nil
}

func importSSHConfig(path string) (*importPlan, error) {
	hosts, notes, err := parseSSHConfig(path)
	if err != nil {
		return nil, err
	}
	p := newPlan()
	p.Hosts = hosts
	p.Notes = append(p.Notes, notes...)
	return p, nil
}

// importPgpass reads host:port:database:user:password lines. Lines with a
// wildcard match many databases, so they cannot become one conn.
func importPgpass(path string) (*importPlan, error) {
	b, err := readSource(path)
	if err != nil {
		return nil, err
	}
	p := newPlan()
	for n, line := range strings.Split(string(b), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		f := splitPgpass(line)
		if len(f) != 5 {
			p.Notes = append(p.Notes, fmt.Sprintf("line %d: expected host:port:database:user:password", n+1))
			continue
		}
		host, port, db, user, pw := f[0], f[1], f[2], f[3], f[4]
		if host == "*" || db == "*" || user == "*" || port == "*" {
			p.Notes = append(p.Notes, fmt.Sprintf("line %d: wildcards (*) match many databases; add them one by one with `komando conn add`", n+1))
			continue
		}
		name := p.name(db)
		u := url.URL{Scheme: "postgres", User: url.UserPassword(user, pw), Host: host + ":" + port, Path: "/" + db}
		p.addConn(name, u.String(), fmt.Sprintf("line %d", n+1))
	}
	return p, nil
}

func splitPgpass(line string) []string {
	var f []string
	var cur strings.Builder
	for i := 0; i < len(line); i++ {
		switch c := line[i]; {
		case c == '\\' && i+1 < len(line):
			i++
			cur.WriteByte(line[i])
		case c == ':':
			f = append(f, cur.String())
			cur.Reset()
		default:
			cur.WriteByte(c)
		}
	}
	return append(f, cur.String())
}

// importMycnf reads [client] style sections of a MySQL option file.
func importMycnf(path string) (*importPlan, error) {
	b, err := readSource(path)
	if err != nil {
		return nil, err
	}
	p := newPlan()
	sections := map[string]map[string]string{}
	var order []string
	cur := ""
	sc := bufio.NewScanner(strings.NewReader(string(b)))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		switch {
		case line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";"):
		case strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]"):
			cur = strings.TrimSpace(line[1 : len(line)-1])
			if sections[cur] == nil {
				sections[cur] = map[string]string{}
				order = append(order, cur)
			}
		case cur != "":
			k, v, _ := strings.Cut(line, "=")
			k = strings.ReplaceAll(strings.ToLower(strings.TrimSpace(k)), "-", "_")
			sections[cur][k] = strings.Trim(strings.TrimSpace(v), `"'`)
		}
	}
	for _, sec := range order {
		kv := sections[sec]
		if !strings.HasPrefix(sec, "client") && sec != "mysql" {
			continue
		}
		if kv["user"] == "" && kv["host"] == "" {
			continue
		}
		host := kv["host"]
		if host == "" {
			host = "localhost"
		}
		port := kv["port"]
		if port == "" {
			port = "3306"
		}
		if kv["socket"] != "" && kv["host"] == "" {
			p.Notes = append(p.Notes, fmt.Sprintf("[%s]: unix sockets are not supported; set host= to import it", sec))
			continue
		}
		user := url.User(kv["user"])
		if kv["password"] != "" {
			user = url.UserPassword(kv["user"], kv["password"])
		}
		db := kv["database"]
		suffix := strings.TrimPrefix(strings.TrimPrefix(sec, "client"), "mysql")
		name := p.name(cmp.Or(strings.Trim(suffix, "-_"), db, "mysql"))
		u := url.URL{Scheme: "mysql", User: user, Host: host + ":" + port, Path: "/" + db}
		p.addConn(name, u.String(), "["+sec+"]")
	}
	return p, nil
}

// importEnv picks the values of a .env file that are conn URLs
// (postgres://, mysql://, redis://, s3://, ...). Other lines are ignored;
// *_URL values that are not conns are reported.
func importEnv(path string) (*importPlan, error) {
	b, err := readSource(path)
	if err != nil {
		return nil, err
	}
	p := newPlan()
	schemes := map[string]bool{}
	for _, k := range driver.Kinds() {
		for _, s := range k.Schemes {
			schemes[s] = true
		}
	}
	for _, line := range strings.Split(string(b), "\n") {
		line = strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(line), "export "))
		k, v, ok := strings.Cut(line, "=")
		if !ok || strings.HasPrefix(line, "#") {
			continue
		}
		k, v = strings.TrimSpace(k), strings.Trim(strings.TrimSpace(v), `"'`)
		scheme, _, _ := strings.Cut(v, "://")
		if !schemes[strings.ToLower(scheme)] {
			if (strings.HasSuffix(k, "_URL") || strings.HasSuffix(k, "_URI")) && strings.Contains(v, "://") {
				p.Notes = append(p.Notes, fmt.Sprintf("%s: %s:// is not a kind komando knows (see `komando conn kinds`)", k, scheme))
			}
			continue
		}
		base := strings.ToLower(k)
		for _, sfx := range []string{"_url", "_uri", "_dsn"} {
			base = strings.TrimSuffix(base, sfx)
		}
		p.addConn(p.name(strings.ReplaceAll(base, "_", "-")), v, k)
	}
	return p, nil
}

// settingDiffers is a setting an export file has otherwise than here.
type settingDiffers struct {
	Key     string `json:"key"`
	File    string `json:"file"`
	Here    string `json:"here"`
	Command string `json:"command"`
}

// importRulesAndSettings: the deny rules of a komando export that are new
// here (they only stop more, so they are added), and its settings that
// differ, with the command that sets each (they are never set by import).
func importRulesAndSettings(st *store.State, plan *importPlan) (rules []string, differ []settingDiffers) {
	for _, p := range plan.DenyRules {
		if strings.TrimSpace(p) != "" && checkRegex(p) == nil && !slices.Contains(st.Settings.ExtraDenyPattern, p) && !slices.Contains(rules, p) {
			rules = append(rules, p)
		}
	}
	for _, s := range settings {
		if v, ok := plan.Settings[s.Key]; ok && v != s.get(&st.Settings) {
			differ = append(differ, settingDiffers{s.Key, v, s.get(&st.Settings), "komando config set " + s.Key + " " + shellQuote(v)})
		}
	}
	return rules, differ
}

// importIncomplete: servers komando refused make the import fail (exit 1),
// not a quiet skip; a name that exists already does not (importing again
// is safe).
func importIncomplete(refused int) error {
	if refused == 0 {
		return nil
	}
	if !g.dryRun {
		return out.Errf(out.ExitError, "IMPORT_INCOMPLETE", "fix them in the source and import again: the rest is in, and importing again skips it",
			"%s not imported (see skipped)", map[bool]string{true: "1 server was", false: strconv.Itoa(refused) + " servers were"}[refused == 1])
	}
	// a preview: nothing is in yet
	return out.Errf(out.ExitError, "IMPORT_INCOMPLETE", "each skipped entry says why; without --dry-run the rest comes in, and importing again later skips it",
		"%s would not be imported (see skipped)", countOf(refused, "server"))
}
