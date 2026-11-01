package cli

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
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
	{"komando", "", "a file made by `komando export` (moving to another computer)", importKomando},
}

func importCmd() *cobra.Command {
	var groups []string
	var overwrite bool
	var names []string
	for _, s := range importSources {
		names = append(names, fmt.Sprintf("  %-11s %s (default %s)", s.Name, s.Desc, dash(s.Default)))
	}
	c := &cobra.Command{
		Use:   "import SOURCE [FILE]",
		Short: "Bring in servers and databases you already have (ssh config, .pgpass, my.cnf, .env, exports)",
		Long: "Sources:\n" + strings.Join(names, "\n") + `

Passwords go to the vault (as <name>-pass) and are referenced from the
conn; they are never printed. Existing names are skipped unless
--overwrite. Try --dry-run first to see what would be added.`,
		Example: `  komando import ssh-config --dry-run
  komando import pgpass
  komando import env ./app/.env --group shop
  komando import komando backup.json`,
		Args: cobra.RangeArgs(1, 2),
		RunE: func(cmd *cobra.Command, args []string) error {
			var src *importSource
			for i := range importSources {
				if importSources[i].Name == args[0] {
					src = &importSources[i]
				}
			}
			if src == nil {
				return out.Usage("unknown source %q (see `komando import --help`)", args[0])
			}
			path := src.Default
			if len(args) == 2 {
				path = args[1]
			}
			if path == "" {
				return out.Usage("give the file to import")
			}
			plan, err := src.Parse(expandHome(path))
			if err != nil {
				return err
			}
			return applyImport(src.Name, path, plan, groups, overwrite)
		},
	}
	c.Flags().StringSliceVarP(&groups, "group", "g", nil, "add everything imported to these groups")
	c.Flags().BoolVar(&overwrite, "overwrite", false, "replace servers, conns and recipes with the same name")
	return c
}

type importSkip struct {
	Name   string `json:"name"`
	Reason string `json:"reason"`
}

type importResult struct {
	Source   string       `json:"source"`
	File     string       `json:"file"`
	Hosts    []string     `json:"hosts"`
	Conns    []string     `json:"conns"`
	Vpns     []string     `json:"vpns"`
	Recipes  []string     `json:"recipes"`
	Secrets  []string     `json:"secrets"` // vault names stored (never values)
	Skipped  []importSkip `json:"skipped"`
	NotFound []string     `json:"not_imported"` // in the source, but not something komando imports
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
	// decide first, so secrets are stored only for what is really added
	skip := func(kind, name string) string {
		if err := validName(kind, name); err != nil {
			return toErr(err).Message
		}
		if err := checkNewName(st, kind, name, overwrite); err != nil {
			return toErr(err).Message
		}
		return ""
	}
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
	var hosts []*store.Host
	for _, h := range plan.Hosts {
		if r := skip("host", h.Name); r != "" {
			res.Skipped = append(res.Skipped, importSkip{h.Name, r})
			continue
		}
		hosts = append(hosts, h)
	}
	for _, h := range hosts { // so conns can use them with --via (st is not saved)
		st.Hosts[h.Name] = h
	}
	var conns []*store.Conn
	for _, c := range plan.Conns {
		// the same database imported again is skipped; a different one that
		// happens to share the name gets the next free name (shop-2)
		if old, ok := st.Conns[c.Name]; ok && old.URL != c.URL && !overwrite {
			renameImported(st, plan, c)
		}
		if r := skip("conn", c.Name); r != "" {
			res.Skipped = append(res.Skipped, importSkip{c.Name, r})
			continue
		}
		if _, err := checkConn(st, c); err != nil {
			res.Skipped = append(res.Skipped, importSkip{c.Name, toErr(err).Message})
			continue
		}
		if name, ok := strings.CutPrefix(c.PasswordRef, "secret:"); ok && !overwrite {
			if _, err := vault.Get(name); err == nil {
				res.Skipped = append(res.Skipped, importSkip{c.Name, "secret " + name + " already exists (use --overwrite to replace it)"})
				continue
			}
		}
		conns = append(conns, c)
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
		res.Conns = append(res.Conns, c.Name)
		if name, ok := strings.CutPrefix(c.PasswordRef, "secret:"); ok && plan.Secrets[name] != "" {
			res.Secrets = append(res.Secrets, name)
		}
	}
	for _, r := range recipes {
		res.Recipes = append(res.Recipes, r.Name)
	}
	if g.dryRun {
		out.P.Print("import", res, nil)
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
		return nil
	})
	if err != nil {
		return err
	}
	audit(st, "import", append(append([]string{}, res.Hosts...), res.Conns...), "", true,
		map[string]any{"source": source, "file": file, "secrets": len(res.Secrets)})
	out.P.Print("import", res, nil)
	return nil
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
	line("servers "+verb, r.Hosts)
	line("conns "+verb, r.Conns)
	line("VPNs "+verb, r.Vpns)
	line("recipes "+verb, r.Recipes)
	line("passwords stored in the vault", r.Secrets)
	for _, s := range r.Skipped {
		fmt.Fprintf(&sb, "skipped %s: %s\n", s.Name, s.Reason)
	}
	for _, n := range r.NotFound {
		fmt.Fprintf(&sb, "not imported: %s\n", n)
	}
	if sb.Len() == 0 {
		sb.WriteString("nothing to import\n")
	}
	return sb.String()
}

// --- sources ---------------------------------------------------------------

// renameImported gives c the first free name based on its own, moving its
// password to the matching vault name.
func renameImported(st *store.State, plan *importPlan, c *store.Conn) {
	base, name := c.Name, c.Name
	for i := 2; ; i++ {
		name = fmt.Sprintf("%s-%d", base, i)
		if _, _, taken := st.FindName(name); !taken {
			break
		}
	}
	if pw, ok := plan.Secrets[base+"-pass"]; ok && c.PasswordRef == "secret:"+base+"-pass" {
		delete(plan.Secrets, base+"-pass")
		plan.Secrets[name+"-pass"] = pw
		c.PasswordRef = "secret:" + name + "-pass"
	}
	c.Name = name
}

func newPlan() *importPlan { return &importPlan{Secrets: map[string]string{}} }

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
	b, err := readFileOrStdin(path)
	if err != nil {
		return nil, out.Errf(out.ExitNotFound, "FILE_NOT_FOUND", "give the file's path after the source name", "%v", err)
	}
	return b, nil
}

func importSSHConfig(path string) (*importPlan, error) {
	hosts, err := parseSSHConfig(path)
	if err != nil {
		return nil, err
	}
	p := newPlan()
	p.Hosts = hosts
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
		name := p.name(firstNonEmpty(strings.Trim(suffix, "-_"), db, "mysql"))
		u := url.URL{Scheme: "mysql", User: user, Host: host + ":" + port, Path: "/" + db}
		p.addConn(name, u.String(), "["+sec+"]")
	}
	return p, nil
}

func firstNonEmpty(v ...string) string {
	for _, s := range v {
		if s != "" {
			return s
		}
	}
	return ""
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
			if strings.HasSuffix(k, "_URL") && strings.Contains(v, "://") {
				p.Notes = append(p.Notes, fmt.Sprintf("%s: %s:// is not a kind komando knows (see `komando conn kinds`)", k, scheme))
			}
			continue
		}
		base := strings.TrimSuffix(strings.TrimSuffix(strings.ToLower(k), "_url"), "_dsn")
		p.addConn(p.name(strings.ReplaceAll(base, "_", "-")), v, k)
	}
	return p, nil
}

// --- export ----------------------------------------------------------------

// exportFile is what `komando export` writes and `komando import komando`
// reads. Secrets stay in the vault; refs are kept, so on a new computer
// the same `komando secret set NAME` makes them work again.
type exportFile struct {
	Format  string           `json:"format"` // komando-export/1
	Hosts   []*store.Host    `json:"hosts"`
	Conns   []*store.Conn    `json:"conns"`
	Vpns    []*store.Vpn     `json:"vpns"`
	Recipes []*store.Snippet `json:"recipes"`
	Secrets []string         `json:"secrets_needed"` // vault names the refs use
}

const exportFormat = "komando-export/1"

func importKomando(path string) (*importPlan, error) {
	b, err := readSource(path)
	if err != nil {
		return nil, err
	}
	var f exportFile
	if err := json.Unmarshal(b, &f); err != nil || f.Format == "" {
		var env struct {
			Data exportFile `json:"data"`
		}
		if err2 := json.Unmarshal(b, &env); err2 != nil || env.Data.Format == "" {
			return nil, out.Usage("%s is not a `komando export` file", path)
		}
		f = env.Data
	}
	if f.Format != exportFormat {
		return nil, out.Usage("%s has format %q; this komando reads %s", path, f.Format, exportFormat)
	}
	p := newPlan()
	p.Hosts, p.Conns, p.Recipes, p.Vpns = f.Hosts, f.Conns, f.Recipes, f.Vpns
	if len(f.Secrets) > 0 {
		p.Notes = append(p.Notes, "passwords are not in export files; set them with `komando secret set NAME` for: "+strings.Join(f.Secrets, ", "))
	}
	return p, nil
}

func exportCmd() *cobra.Command {
	var to string
	var overwrite bool
	c := &cobra.Command{
		Use:   "export [TARGET]",
		Short: "Save servers, conns and recipes to a file, to move them to another computer (no passwords)",
		Example: `  komando export --to komando-backup.json
  komando export @prod --to prod.json
  komando import komando komando-backup.json      # on the other computer`,
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			st, err := loadState()
			if err != nil {
				return err
			}
			sel := selection{Hosts: st.SortedHosts(), Conns: st.SortedConns(), Vpns: st.SortedVpns()}
			if len(args) == 1 {
				if sel, err = resolveSelection(st, args[0]); err != nil {
					return err
				}
			}
			need := map[string]bool{}
			f := exportFile{Format: exportFormat, Hosts: sel.Hosts, Conns: sel.Conns, Vpns: sel.Vpns, Recipes: []*store.Snippet{}, Secrets: []string{}}
			for _, v := range sel.Vpns {
				for _, r := range []string{v.KeyRef, v.PSKRef} {
					if n, ok := strings.CutPrefix(r, "secret:"); ok {
						need[n] = true
					}
				}
			}
			for _, h := range sel.Hosts {
				for _, r := range []string{h.PasswordRef, h.SudoRef} {
					if n, ok := strings.CutPrefix(r, "secret:"); ok {
						need[n] = true
					}
				}
			}
			for _, c := range sel.Conns {
				if n, ok := strings.CutPrefix(c.PasswordRef, "secret:"); ok {
					need[n] = true
				}
			}
			for n := range need {
				f.Secrets = append(f.Secrets, n)
			}
			sort.Strings(f.Secrets)
			if len(args) == 0 {
				for _, s := range st.Snippets {
					f.Recipes = append(f.Recipes, s)
				}
				sort.Slice(f.Recipes, func(i, j int) bool { return f.Recipes[i].Name < f.Recipes[j].Name })
			}
			if to == "" {
				out.P.Print("export", f, nil)
				return nil
			}
			if _, err := os.Stat(to); err == nil && !overwrite {
				return out.Errf(out.ExitConflict, "FILE_EXISTS", "pick another file or pass --overwrite", "%s already exists", to)
			}
			b, _ := json.MarshalIndent(f, "", "  ")
			if err := os.MkdirAll(filepath.Dir(to), 0o700); err != nil {
				return err
			}
			if err := writeAtomic(to, func(tmp string) error { return os.WriteFile(tmp, append(b, '\n'), 0o600) }); err != nil {
				return err
			}
			out.P.Print("export", map[string]any{"file": to, "hosts": len(f.Hosts), "conns": len(f.Conns), "vpns": len(f.Vpns), "recipes": len(f.Recipes), "secrets_needed": f.Secrets}, nil)
			return nil
		},
	}
	c.Flags().StringVar(&to, "to", "", "write to this file (0600) instead of printing")
	c.Flags().BoolVar(&overwrite, "overwrite", false, "replace the file if it exists")
	return c
}
