package cli

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"golang.org/x/term"

	"github.com/sgnd/komando/internal/driver"
	"github.com/sgnd/komando/internal/out"
	"github.com/sgnd/komando/internal/policy"
	"github.com/sgnd/komando/internal/sshx"
	"github.com/sgnd/komando/internal/store"
)

func loadState() (*store.State, error) { return store.Load() }

// rmAliases are the other words people type for rm. Every rm command
// accepts them (docs/design/ux.md, section 1).
var rmAliases = []string{"remove", "delete", "del"}

// applyConventions applies the rules every command shares, so a new command
// cannot forget them. TestConventions checks the rest.
func applyConventions(c *cobra.Command) {
	if c.Name() == "rm" {
		c.Aliases = rmAliases
	}
	if c.HasParent() && c.HasSubCommands() && c.Run == nil && c.RunE == nil {
		// `komando host lst`: a typo must fail (exit 2) with a suggestion,
		// not print the help and exit 0 as if it had worked
		c.Args = cobra.ArbitraryArgs
		c.RunE = func(cmd *cobra.Command, args []string) error {
			if len(args) == 0 {
				return cmd.Help()
			}
			e := out.Usage("unknown command %q for %q", args[0], cmd.CommandPath())
			cmd.SuggestionsMinimumDistance = 2
			if s := cmd.SuggestionsFor(args[0]); len(s) > 0 {
				e.Message += "; did you mean " + strings.Join(s, " or ") + "?"
			}
			names := []string{}
			for _, sub := range cmd.Commands() {
				if sub.IsAvailableCommand() {
					names = append(names, sub.Name())
				}
			}
			e.Hint = "`" + cmd.CommandPath() + "` has: " + strings.Join(names, ", ")
			return e
		}
	}
	for _, sub := range c.Commands() {
		applyConventions(sub)
	}
}

func dash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

// alias marks c as the per-area spelling of a shared command (`host list`
// for `list kind:host`). It keeps working and says so in its help, so there
// is one implementation and one name to learn (docs/design/ux.md, section 11).
func alias(c *cobra.Command, shared string) *cobra.Command {
	c.Short = "Same as `komando " + shared + "`"
	c.Long = ""
	c.Example = ""
	return c
}

// aliasFlag keeps an old flag name working after a rename: old is hidden,
// shares the value of now, and prints a note on stderr when used. Old names
// stay for one minor release (docs/design/ux.md, section 10).
func aliasFlag(fs *pflag.FlagSet, old, now string) {
	f := fs.Lookup(now)
	fs.AddFlag(&pflag.Flag{Name: old, Value: f.Value, DefValue: f.DefValue, NoOptDefVal: f.NoOptDefVal, Usage: f.Usage})
	_ = fs.MarkDeprecated(old, "use --"+now)
}

func dur(flag time.Duration, setting string, def time.Duration) time.Duration {
	if flag > 0 {
		return flag
	}
	if d, err := time.ParseDuration(setting); err == nil && d > 0 {
		return d
	}
	return def
}

func cmdTimeout(st *store.State) time.Duration {
	return dur(g.timeout, st.Settings.DefaultTimeout, 5*time.Minute)
}

func sshOpts(st *store.State) sshx.Options {
	p := g.hostKeyPolicy
	if p == "" {
		p = st.Settings.HostKeyPolicy
	}
	return sshx.Options{ConnectTimeout: dur(g.connectTimeout, st.Settings.ConnectTimeout, 15*time.Second), HostKeyPolicy: p}
}

func maxOutput(st *store.State) int {
	if g.maxOutput > 0 {
		return g.maxOutput
	}
	return st.Settings.MaxOutputBytes
}

func parallelism(st *store.State) int {
	if g.parallel > 0 {
		return g.parallel
	}
	return st.Settings.Parallel
}

func toErr(err error) *out.Error {
	if err == nil {
		return nil
	}
	var e *out.Error
	if errors.As(err, &e) {
		return e
	}
	if errors.Is(err, store.ErrDryRun) {
		return &out.Error{Code: "DRY_RUN_UNSUPPORTED", Message: err.Error(), Hint: "run it again without --dry-run to make the change", Exit: out.ExitUsage}
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return &out.Error{Code: "TIMEOUT", Message: err.Error(), Exit: out.ExitTimeout}
	}
	if errors.Is(err, context.Canceled) {
		return &out.Error{Code: "CANCELLED", Message: "interrupted", Exit: out.ExitError}
	}
	return &out.Error{Code: "REMOTE_ERROR", Message: err.Error(), Exit: out.ExitError}
}

type outcome struct {
	Host  *store.Host
	Value any
	Err   error
}

// fanout dials each host (parallel, bounded) and runs fn on it.
func fanout(ctx context.Context, st *store.State, hosts []*store.Host, fn func(ctx context.Context, c *sshx.Client) (any, error)) []outcome {
	res := make([]outcome, len(hosts))
	sem := make(chan struct{}, max(1, parallelism(st)))
	var wg sync.WaitGroup
	opts := sshOpts(st)
	for i, h := range hosts {
		wg.Add(1)
		go func(i int, h *store.Host) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			res[i].Host = h
			c, err := sshx.Dial(ctx, st, h, opts)
			if err != nil {
				res[i].Err = err
				return
			}
			defer c.Close()
			res[i].Value, res[i].Err = fn(ctx, c)
		}(i, h)
	}
	wg.Wait()
	return res
}

func withClient(ctx context.Context, st *store.State, h *store.Host, fn func(c *sshx.Client) error) error {
	c, err := sshx.Dial(ctx, st, h, sshOpts(st))
	if err != nil {
		return err
	}
	defer c.Close()
	return fn(c)
}

// guard enforces the safety policy before anything mutating runs.
func guard(st *store.State, hosts []*store.Host, command string, mutating bool) error {
	names := hostNames(hosts)
	if command != "" {
		if hits := policy.Check(command, st.Settings.ExtraDenyPattern); len(hits) > 0 && !dangerOK() && !confirmDangerous(names, hits[0].Reason) {
			ids := make([]string, len(hits))
			reasons := make([]string, len(hits))
			for i, h := range hits {
				ids[i], reasons[i] = h.ID, h.Reason
			}
			return policyStop(out.Errf(out.ExitPolicy, "POLICY_BLOCKED",
				"if this is truly intended, confirm with the user and re-run with --allow-dangerous (try --dry-run first)",
				"command matches destructive rules [%s]: %s", strings.Join(ids, ","), strings.Join(reasons, "; ")))
		}
	}
	if mutating {
		var prot []string
		for _, h := range hosts {
			if protectedHost(st, h) {
				prot = append(prot, h.Name)
			}
		}
		if len(prot) > 0 && !yesOK() && !confirmProtected(prot) {
			return policyStop(out.Errf(out.ExitPolicy, "PROTECTED_HOST",
				"protected hosts require explicit confirmation: re-run with --yes after verifying intent",
				"mutating action targets protected host(s): %s", strings.Join(prot, ", ")))
		}
	}
	return nil
}

// guardConns is guard for conns. The driver classifies the operation first;
// destructive needs --allow-dangerous, and any change to a protected conn
// needs --yes. Exit code and codes match guard so agents handle both alike.
func guardConns(st *store.State, conns []*store.Conn, v driver.Verdict) error {
	names := make([]string, len(conns))
	for i, c := range conns {
		names[i] = c.Name
	}
	if v.Risk >= driver.RiskDestructive && !dangerOK() && !confirmDangerous(names, strings.Join(v.Reasons, "; ")) {
		return policyStop(out.Errf(out.ExitPolicy, "POLICY_BLOCKED",
			"if this is truly intended, confirm with the user and re-run with --allow-dangerous (try --dry-run first)",
			"operation matches destructive rules [%s]: %s", strings.Join(v.RuleIDs, ","), strings.Join(v.Reasons, "; ")))
	}
	if v.Risk >= driver.RiskWrite {
		var prot []string
		for _, c := range conns {
			if protectedConn(st, c) {
				prot = append(prot, c.Name)
			}
		}
		if len(prot) > 0 && !yesOK() && !confirmProtected(prot) {
			return policyStop(out.Errf(out.ExitPolicy, "PROTECTED_TARGET",
				"protected conns require explicit confirmation: re-run with --yes after verifying intent",
				"%s action targets protected conn(s): %s", v.Risk, strings.Join(prot, ", ")))
		}
	}
	return nil
}

// protectedHost is true when h is marked protected, or when a protected
// inventory host has the same address and port: otherwise an ad-hoc
// user@address or a second name for the same server would get around
// protection. Names are compared as written; komando does not resolve DNS.
func protectedHost(st *store.State, h *store.Host) bool {
	if h.Protected {
		return true
	}
	for _, o := range st.Hosts {
		if o.Protected && sameHostName(o.Address, h.Address) && o.EffectivePort() == h.EffectivePort() {
			return true
		}
	}
	return false
}

// sameHostName compares host names the way DNS does: case does not matter,
// and "db.example." (the fully qualified form) is "db.example".
func sameHostName(a, b string) bool {
	return normHost(a) == normHost(b)
}

func normHost(h string) string {
	return strings.TrimSuffix(strings.ToLower(strings.Trim(h, "[]")), ".")
}

// normHostPort is host:port with the host normalised.
func normHostPort(addr string) string {
	h, p, err := net.SplitHostPort(addr)
	if err != nil {
		return normHost(addr)
	}
	return net.JoinHostPort(normHost(h), p)
}

// protectedConn is protectedHost for conns: a conn pointing at the same
// server, file or bucket as a protected conn is protected too.
func protectedConn(st *store.State, c *store.Conn) bool {
	if c.Protected {
		return true
	}
	if st == nil {
		return false
	}
	key := func(c *store.Conn) string {
		t, err := driver.Parse(c.URL)
		if err != nil {
			return ""
		}
		switch {
		case t.Kind.File:
			return "file " + t.Path
		case t.Bucket != "":
			return "bucket " + normHostPort(t.Address) + "/" + t.Bucket
		}
		return t.Kind.Family + " " + normHostPort(t.Address)
	}
	k := key(c)
	for _, o := range st.Conns {
		if o.Protected && k != "" && key(o) == k {
			return true
		}
	}
	// an SFTP conn is an SSH server: protected when a protected host is it
	if h := sftpHost(c); h != nil && protectedHost(st, h) {
		return true
	}
	return false
}

// sftpHost is the SSH host an sftp:// conn points at, or nil for other kinds.
func sftpHost(c *store.Conn) *store.Host {
	t, err := driver.Parse(c.URL)
	if err != nil || t.Kind.Name != "sftp" {
		return nil
	}
	hostname, port, _ := net.SplitHostPort(t.Address)
	p, _ := strconv.Atoi(port)
	return &store.Host{Name: c.Name, Address: hostname, Port: p, User: t.User, PasswordRef: c.PasswordRef, Via: c.Via}
}

// interactive is true when a human sits at a terminal: stdin and stderr are
// both terminals and no AI agent runs komando. Agents and scripts never are, so they still need --yes and
// --allow-dangerous (docs/design/ux.md, section 6).
var interactive = func() bool {
	return term.IsTerminal(int(os.Stdin.Fd())) && term.IsTerminal(int(os.Stderr.Fd())) && !isAgent()
}

// ask prints question on stderr and reads one line from the terminal.
func ask(question string) string {
	fmt.Fprint(os.Stderr, question)
	line, _ := bufio.NewReader(os.Stdin).ReadString('\n')
	return strings.TrimSpace(line)
}

// confirmProtected asks a human at the terminal to confirm a change to
// protected targets. A yes counts as --yes for the rest of this command.
func confirmProtected(names []string) bool {
	return confirmYes(fmt.Sprintf("%s %s protected. Change it anyway?", strings.Join(names, ", "), map[bool]string{true: "is", false: "are"}[len(names) == 1]))
}

// confirmYes asks a [y/N] question at the terminal. The answer covers this
// question only; it does not turn on --yes for later checks.
func confirmYes(question string) bool {
	if g.dryRun || !interactive() {
		return false
	}
	a := strings.ToLower(ask(question + " [y/N] "))
	ok := a == "y" || a == "yes"
	personSaidNo = personSaidNo || !ok
	return ok
}

// personSaidNo: a person at the terminal answered no, so the stop that
// follows is their decision, not something to retry (Execute words it so).
var personSaidNo bool

// guardSafety: changes that weaken komando's own safety checks (no audit
// log, no host key check, fewer deny rules) need --yes, so an agent cannot
// switch them off by itself.
func guardSafety(what string) error {
	if yesOK() || confirmYes("This weakens komando's safety checks: "+what+". Continue?") {
		return nil
	}
	return policyStop(out.Errf(out.ExitPolicy, "SAFETY_SETTING", "re-run with --yes after the user confirms", "%s weakens komando's safety checks", what))
}

// confirmDangerous asks a human at the terminal to confirm a destructive
// action by typing the target's name (or how many targets there are), so a
// reflex "y" is not enough.
func confirmDangerous(names []string, reason string) bool {
	if g.dryRun || !interactive() {
		return false
	}
	want, what := "yes", "yes"
	switch {
	case len(names) == 1:
		want, what = names[0], "the name "+names[0]
	case len(names) > 1:
		want, what = fmt.Sprint(len(names)), fmt.Sprintf("%d (the number of targets)", len(names))
	}
	fmt.Fprintf(os.Stderr, "Dangerous: %s.\n", reason)
	ok := ask("Type "+what+" to continue: ") == want
	personSaidNo = personSaidNo || !ok
	return ok
}

// guardProtection stops a way around protection: removing a protected
// target from the inventory, or turning its protection off, would let the
// next command skip --yes, so it needs --yes itself. kind is host or conn.
func guardProtection(kind, action string, names []string) error {
	if len(names) == 0 || yesOK() || confirmProtected(names) {
		return nil
	}
	code := map[string]string{"host": "PROTECTED_HOST", "conn": "PROTECTED_TARGET"}[kind]
	return policyStop(out.Errf(out.ExitPolicy, code, "re-run with --yes after the user confirms",
		"%s protected %s(s): %s", action, kind, strings.Join(names, ", ")))
}

func hostNames(hs []*store.Host) []string {
	n := make([]string, len(hs))
	for i, h := range hs {
		n[i] = h.Name
	}
	return n
}

// audit appends one JSON line per action to $KOMANDO_HOME/audit.jsonl.
func audit(st *store.State, command string, hosts []string, remote string, ok bool, extra map[string]any) {
	if st != nil && !st.Settings.Audit {
		return
	}
	rec := map[string]any{
		"ts":      time.Now().UTC().Format(time.RFC3339Nano),
		"command": command,
		"ok":      ok,
		"dry_run": g.dryRun,
		"actor":   actor(),
	}
	if hosts != nil {
		rec["hosts"] = hosts
	}
	if remote != "" {
		rec["remote"] = remote
	}
	if a := agentName(); a != "" {
		rec["agent"] = a // who typed it: an AI agent
		if allowedByPerson() {
			rec["allowed_by_person"] = true // in komando's window
		}
	}
	for k, v := range extra {
		rec[k] = v
	}
	_ = appendAudit(rec)
}

func actor() string {
	if a := os.Getenv("KOMANDO_ACTOR"); a != "" {
		return a
	}
	return os.Getenv("USER")
}

// fleetSummary is attached to every multi-host result.
type fleetSummary struct {
	Total       int      `json:"total"`
	OK          int      `json:"ok"`
	Failed      int      `json:"failed"`
	FailedHosts []string `json:"failed_hosts,omitempty"`
}

// finish prints a multi-host result and converts failures into an exit code.
func finish(command string, data any, sum fleetSummary, worstExit int) error {
	var soft *out.Error
	if sum.Failed > 0 {
		soft = &out.Error{Code: "PARTIAL_FAILURE", Message: fmt.Sprintf("%d of %d host(s) failed: %s", sum.Failed, sum.Total, strings.Join(sum.FailedHosts, ", ")),
			Hint: "see the per-host results (data.results) for exit codes and stderr", Exit: worstExit}
		if sum.Total == 1 {
			soft.Code = "FAILED"
			soft.Message = "host " + sum.FailedHosts[0] + " failed"
		}
	}
	out.P.Print(command, data, soft)
	if soft != nil {
		return exitCode(worstExit)
	}
	return nil
}

func worse(a, b int) int {
	rank := func(x int) int {
		switch x {
		case out.ExitConnect:
			return 5
		case out.ExitTimeout:
			return 4
		case out.ExitRemote:
			return 3
		case 0:
			return 0
		}
		return 2
	}
	if rank(b) > rank(a) {
		return b
	}
	return a
}

func readStdinIfPiped() ([]byte, error) {
	fi, err := os.Stdin.Stat()
	if err != nil || fi.Mode()&os.ModeCharDevice != 0 {
		return nil, nil
	}
	b, err := io.ReadAll(os.Stdin)
	return b, err
}

func parseKV(pairs []string) (map[string]string, error) {
	m := map[string]string{}
	for _, p := range pairs {
		k, v, ok := strings.Cut(p, "=")
		if !ok || k == "" {
			return nil, out.Usage("expected KEY=VALUE, got %q", p)
		}
		m[k] = v
	}
	return m, nil
}

// parseEnv is parseKV for environment variables: keys must be shell names,
// because they are exported on the remote side unquoted.
func parseEnv(pairs []string) (map[string]string, error) {
	m, err := parseKV(pairs)
	if err != nil {
		return nil, err
	}
	return m, checkEnvKeys(m)
}

func checkEnvKeys(m map[string]string) error {
	for k := range m {
		if !sshx.ValidEnvKey(k) {
			return out.Usage("environment variable name %q is not valid: use letters, digits and _, not starting with a digit", k)
		}
	}
	return nil
}

func parseDur(s string) (time.Duration, error) { return time.ParseDuration(s) }

func checkRegex(s string) error {
	_, err := regexp.Compile(s)
	return err
}
