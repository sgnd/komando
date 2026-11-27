package cli

import (
	"context"
	"fmt"
	"maps"
	"net"
	"slices"
	"strconv"
	"strings"
	"sync"

	"golang.org/x/crypto/ssh"

	"github.com/sgnd/komando/internal/capability"
	"github.com/sgnd/komando/internal/out"
	"github.com/sgnd/komando/internal/sshx"
	"github.com/sgnd/komando/internal/store"
	"github.com/spf13/cobra"
)

// `host trust TARGET` pins the host keys of one server or many, with one
// answer shape: data.results, one row per server, and data.summary. After
// a rebuild of a group of servers (same addresses, new keys) every one of
// them is a HOSTKEY_MISMATCH; --reset replaces them all after one yes that
// names every server with its new key, instead of one yes per server.

// trustRow is one server's answer.
type trustRow struct {
	Host           string     `json:"host"`
	OK             bool       `json:"ok"`
	Address        string     `json:"address"`
	KeyType        string     `json:"key_type,omitempty"`
	Fingerprint    string     `json:"fingerprint,omitempty"`
	OldFingerprint []string   `json:"old_fingerprints,omitempty"`     // pinned keys that are not the server's
	Expected       string     `json:"expected_fingerprint,omitempty"` // --fingerprint: pinned only if the server shows it
	RemovedEntries int        `json:"removed_entries"`
	AlreadyPinned  bool       `json:"already_pinned,omitempty"`
	Error          *out.Error `json:"error,omitempty"`
	h              *store.Host
	key            ssh.PublicKey
	same           bool // the server's key is pinned already
}

func (r *trustRow) mismatch() bool { return len(r.OldFingerprint) > 0 && !r.same }

// trustAddr is the known_hosts address of h.
func trustAddr(h *store.Host) string {
	return net.JoinHostPort(h.Address, strconv.Itoa(h.EffectivePort()))
}

// fetchTrustRows fetches every server's key, a few at a time, and compares
// it with what is pinned. Nothing is written.
func fetchTrustRows(cl *call, ctx context.Context, st *store.State, hosts []*store.Host) []*trustRow {
	rows := make([]*trustRow, len(hosts))
	sem := make(chan struct{}, max(1, parallelism(cl, st)))
	var wg sync.WaitGroup
	opts := sshOpts(cl, st)
	for i, h := range hosts {
		rows[i] = &trustRow{Host: h.Name, Address: trustAddr(h), h: h}
		wg.Add(1)
		go func(r *trustRow) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			key, err := sshx.FetchHostKey(ctx, st, r.h, opts)
			if err != nil {
				r.Error = keyscanError(r.h, r.Address, err)
				return
			}
			r.key, r.KeyType, r.Fingerprint = key, key.Type(), ssh.FingerprintSHA256(key)
			pins, err := sshx.PinnedKeys(r.Address)
			if err != nil {
				r.Error = toErr(err)
				return
			}
			for _, k := range pins {
				if sshx.SameKey(k, key) {
					r.same = true
				} else {
					r.OldFingerprint = append(r.OldFingerprint, ssh.FingerprintSHA256(k))
				}
			}
		}(rows[i])
	}
	wg.Wait()
	return rows
}

func keyscanError(h *store.Host, addr string, err error) *out.Error {
	if oe, ok := err.(*out.Error); ok && oe.Code != "CONN_UNREACHABLE" {
		return oe // a jump host's key or login, a timeout, a VPN: its own words
	}
	return out.Errf(out.ExitConnect, "KEYSCAN_FAILED", "check the address and port with `komando host ssh show "+h.Name+"`", "cannot fetch host key from %s: %v", addr, err)
}

// shortFP is a fingerprint short enough for the approval window's one
// line: SHA256: and its first 8 characters. The full ones are in the
// output and on the terminal.
func shortFP(fp string) string {
	if len(fp) > len("SHA256:")+8 {
		return fp[:len("SHA256:")+8] + "…"
	}
	return fp
}

// approveReplacements asks once for every server whose pinned key would be
// replaced: a person at the terminal sees the full table first; an AI
// agent's person sees each server with its new key in the window.
func approveReplacements(cl *call, st *store.State, rows []*trustRow) error {
	var names, parts []string
	var prot []string
	for _, r := range rows {
		if r.Error != nil || !r.mismatch() {
			continue
		}
		names = append(names, r.Host)
		parts = append(parts, r.Host+" "+shortFP(r.Fingerprint))
		if protectedHost(st, r.h) {
			prot = append(prot, r.Host)
		}
	}
	if len(names) == 0 {
		return nil
	}
	if cl.interactive() && !cl.dryRun() {
		fmt.Fprintln(cl.out.Err, "These servers show a different host key than the one pinned:")
		for _, r := range rows {
			if r.Error == nil && r.mismatch() {
				fmt.Fprintf(cl.out.Err, "  %-24s old %s\n  %-24s new %s\n", r.Host, strings.Join(r.OldFingerprint, ", "), "", r.Fingerprint)
			}
		}
	}
	what := fmt.Sprintf("replacing the pinned host keys of %s: %s", countOf(len(names), "server"), strings.Join(parts, ", "))
	if len(names) == 1 {
		for _, r := range rows {
			if r.Host == names[0] {
				what = "replacing the pinned host key of " + r.Host + " (old " + strings.Join(r.OldFingerprint, ", ") + ", new " + r.Fingerprint + ")"
			}
		}
	}
	if len([]rune(what)) > approvalMaxLen {
		what = fmt.Sprintf("replacing the pinned host keys of %s: %s", countOf(len(names), "server"), strings.Join(names, ", "))
	}
	return replacePin(cl, names, prot, what)
}

// pinTrustRows writes the pins: new keys are added, mismatches without
// --reset are refused (never two keys for one address: both would be
// accepted), and with --reset the old ones go.
func pinTrustRows(rows []*trustRow, reset bool) {
	for _, r := range rows {
		if r.Error != nil {
			continue
		}
		if r.mismatch() && !reset {
			r.Error = sshx.HostKeyMismatch(r.Host, r.Fingerprint, r.OldFingerprint)
			continue
		}
		removed, err := sshx.PinHostKey(r.Address, r.key, reset)
		if err != nil {
			r.Error = toErr(err)
			continue
		}
		r.RemovedEntries, r.AlreadyPinned, r.OK = removed, r.same && removed == 0, true
	}
}

type trustData struct {
	Results []*trustRow  `json:"results"`
	Summary fleetSummary `json:"summary"`
}

// Text is host trust's answer for a person: one line per server.
func (d trustData) Text() string {
	var b strings.Builder
	for _, r := range d.Results {
		switch {
		case r.Error != nil:
			fmt.Fprintf(&b, "%s: %s\n", r.Host, r.Error.Message)
		case r.AlreadyPinned:
			fmt.Fprintf(&b, "%s: its host key is pinned already (%s %s)\n", r.Host, r.KeyType, r.Fingerprint)
		default:
			fmt.Fprintf(&b, "pinned the host key of %s (%s %s)\n", r.Host, r.KeyType, r.Fingerprint)
		}
	}
	return b.String()
}

// trustHosts is `host trust TARGET`.
func trustHosts(cl *call, ctx context.Context, st *store.State, hosts []*store.Host, reset bool, want string) error {
	if cl.dryRun() {
		return trustDryRun(cl, st, hosts, reset, want)
	}
	rows := fetchTrustRows(cl, ctx, st, hosts)
	if want != "" {
		for _, r := range rows {
			r.Expected = want
			if r.Error == nil && r.Fingerprint != want {
				r.Error = sshx.FingerprintMismatch(r.Host, want, r.Fingerprint)
			}
		}
	}
	var first []string
	for _, r := range rows {
		if r.Error == nil && !r.same && len(r.OldFingerprint) == 0 {
			first = append(first, r.Host+" "+r.Fingerprint)
		}
	}
	if err := guardFirstPin(cl, st, first); err != nil {
		return err
	}
	if reset {
		if err := approveReplacements(cl, st, rows); err != nil {
			return err
		}
	}
	pinTrustRows(rows, reset)
	data := trustData{Results: rows}
	worst := 0
	var fails []hostFail
	for _, r := range rows {
		if r.Error != nil {
			data.Summary.Failed++
			data.Summary.FailedHosts = append(data.Summary.FailedHosts, r.Host)
			worst = worse(worst, max(r.Error.Exit, 1))
			fails = append(fails, hostFail{host: r.Host, reason: failReason(0, r.Error), err: r.Error})
			continue
		}
		data.Summary.OK++
		rec := map[string]any{"reset": reset, "removed_entries": r.RemovedEntries, "fingerprint": r.Fingerprint}
		if want != "" {
			rec["fingerprint_checked"] = true
		}
		audit(cl, st, "host.trust", []string{r.Host}, "", true, rec)
	}
	data.Summary.Total = len(rows)
	return finishFleet(cl, "host.trust", data, runSummary{fleetSummary: data.Summary}, worst, fails)
}

// trustDryRun fetches nothing and changes nothing: it says how each key
// would be fetched and, with --reset, how many pinned entries would go.
func trustDryRun(cl *call, st *store.State, hosts []*store.Host, reset bool, want string) error {
	var res []map[string]any
	pinned := 0
	for _, h := range hosts {
		r := map[string]any{"host": h.Name, "address": trustAddr(h), "would_fetch_from": keyFetchPath(st, h)}
		if want != "" {
			r["expected_fingerprint"] = want
		}
		if reset {
			n := countPinned(trustAddr(h))
			r["would_remove_entries"] = n
			pinned += n
		}
		res = append(res, r)
	}
	// the stops the real run hits, in its order: a first pin (no key is
	// pinned for the address yet; the real run fetches it), then replacing
	// pinned keys
	var first []string
	for _, h := range hosts {
		if countPinned(trustAddr(h)) == 0 {
			first = append(first, h.Name+" (its key is fetched by the real run)")
		}
	}
	if err := guardFirstPin(cl, st, first); err != nil {
		return err
	}
	if reset && pinned > 0 {
		var prot []string
		for _, h := range hosts {
			if protectedHost(st, h) {
				prot = append(prot, h.Name)
			}
		}
		what := fmt.Sprintf("replacing the pinned host keys of %s (keys may be replaced)", countOf(len(hosts), "server"))
		if len(hosts) == 1 {
			what = "replacing the pinned host key of " + hosts[0].Name + " (a key may be replaced)"
		}
		if err := replacePin(cl, hostNames(hosts), prot, what); err != nil {
			return err
		}
	}
	cl.out.Print("host.trust", textAs{map[string]any{"results": res}, trustDryText(res)}, nil)
	return nil
}

// trustDryText is a dry run's text: where each key would come from.
func trustDryText(rows []map[string]any) out.Texter {
	return textFn(func() string {
		var b strings.Builder
		for _, r := range rows {
			fmt.Fprintf(&b, "would fetch the host key of %v (%v) from %v", r["host"], r["address"], r["would_fetch_from"])
			if n, ok := r["would_remove_entries"].(int); ok && n > 0 {
				fmt.Fprintf(&b, ", and remove %d pinned %s", n, map[bool]string{true: "key", false: "keys"}[n == 1])
			}
			b.WriteString("\n")
		}
		return b.String()
	})
}

// The host type of the table: komando host ssh|winrm VERB. The verbs are
// today's commands run through runBody (add, edit, list, show, rename,
// remove, test, exec, shell, trust and the tunnel verbs), each on the
// servers of its provider only: the provider in the path must be the one the
// server was saved with (WRONG_KIND). The provider groups, their texts and
// their options come from the table when the tree is mounted.

func init() {
	for _, p := range []string{"ssh", "winrm"} {
		key := func(verb string) capability.Key { return capability.Key{Type: "host", Provider: p, Verb: verb} }
		on := func(verb string, body func() *cobra.Command, targets func(leafInput) []string) {
			handlers[key(verb)] = func(cl *call, ctx context.Context, in leafInput) error {
				if err := withHostTargets(cl, targets(in), p, verb); err != nil {
					return err
				}
				return runBody(cl, ctx, body(), hostBodyInput(in), nil)
			}
		}
		first := func(in leafInput) []string { return in.Args[:min(1, len(in.Args))] }
		all := func(in leafInput) []string { return in.Args }
		handlers[key("add")] = func(cl *call, ctx context.Context, in leafInput) error {
			if err := hostAddressOfProvider(&in, p); err != nil {
				return err
			}
			return runBody(cl, ctx, hostAddCmd(), hostBodyInput(in), nil)
		}
		on("edit", hostEditCmd, all)
		on("show", hostShowCmd, first)
		on("rename", hostMvCmd, first)
		on("remove", hostRmCmd, all)
		handlers[key("list")] = func(cl *call, ctx context.Context, in leafInput) error {
			return runBody(cl, ctx, listCmdKind("host", p), in, nil)
		}
		handlers[key("test")] = func(cl *call, ctx context.Context, in leafInput) error {
			if !in.Changed("end") || len(in.Args) > 0 {
				if err := withHostTargets(cl, in.Args, p, "test"); err != nil {
					return err
				}
			}
			return runBody(cl, ctx, testCmdFor("host"), in, nil)
		}
		on("exec", execCmd, first)
		handlers[key("shell")] = func(cl *call, ctx context.Context, in leafInput) error {
			if in.Changed("attach") {
				return out.Usage("--attach comes with shell sessions, which this build does not have yet")
			}
			if err := withHostTargets(cl, in.Args, p, "shell"); err != nil {
				return err
			}
			return runBody(cl, ctx, shellCmd(), in, nil)
		}
	}
	on := func(verb string, body func() *cobra.Command) {
		handlers[capability.Key{Type: "host", Provider: "ssh", Verb: verb}] = func(cl *call, ctx context.Context, in leafInput) error {
			if err := withHostTargets(cl, in.Args, "ssh", verb); err != nil {
				return err
			}
			return runBody(cl, ctx, body(), in, nil)
		}
	}
	on("trust", hostTrustCmd)
	for verb, body := range map[string]func() *cobra.Command{"start": tunnelStartCmd, "list": tunnelListCmd, "stop": tunnelStopCmd} {
		handlers[capability.Key{Type: "host", Provider: "ssh", Area: "tunnel", Verb: verb}] = func(cl *call, ctx context.Context, in leafInput) error {
			return runBody(cl, ctx, body(), in, nil)
		}
	}
	moveType("host")
	providerIDs["tunnel"] = true // the hidden group of tunnel serve keeps its old key, which host ssh tunnel has too
	groupShorts["host ssh"] = "SSH servers: save them, run commands on them, tunnel through them"
	groupShorts["host winrm"] = "Windows servers over WinRM: save them and run commands on them"
	groupShorts["host ssh tunnel"] = "Background tunnels through a server: start, list, stop"
}

// hostProvider is the word of the provider a server was saved with.
func hostProvider(h *store.Host) string {
	if h.WinRM() {
		return "winrm"
	}
	return "ssh"
}

// hostIsOf is nil when h is a server of this provider; another provider is
// WRONG_KIND with the path that fits it.
func hostIsOf(h *store.Host, provider, verb string) error {
	if p := hostProvider(h); p != provider {
		return out.Errf(out.ExitUsage, "WRONG_KIND", "use `komando host "+p+" "+verb+" "+h.Name+"`",
			"%s is a %s server, not a %s one", h.Name, p, provider)
	}
	return nil
}

// withHostTargets is nil when every server the targets name or pick is of
// this provider. A name that is no server, or a selector that picks none, is
// left to the command to say.
func withHostTargets(cl *call, targets []string, provider, verb string) error {
	if len(targets) == 0 {
		return nil
	}
	st, err := loadState()
	if err != nil {
		return err
	}
	for _, t := range targets {
		if h := st.Hosts[t]; h != nil {
			if err := hostIsOf(h, provider, verb); err != nil {
				return err
			}
			continue
		}
		if !isSelector(t) {
			continue
		}
		sel, err := resolveSelection(cl, st, t)
		if err != nil {
			return err
		}
		for _, h := range sel.Hosts {
			if err := hostIsOf(h, provider, verb); err != nil {
				return err
			}
		}
	}
	return nil
}

// hostAddressOfProvider makes the address of add what today's add reads: a
// WinRM server is written winrm://USER@ADDRESS, which `host winrm add` puts
// before the address it is given; an SSH server is not written that way.
func hostAddressOfProvider(in *leafInput, provider string) error {
	fix := func(a string) (string, error) {
		switch {
		case a == "":
			return a, nil
		case provider == "winrm" && !isWinRMAddress(a):
			return "winrm://" + a, nil
		case provider == "ssh" && isWinRMAddress(a):
			return "", out.Errf(out.ExitUsage, "WRONG_KIND", "use `komando host winrm add`", "%s is a WinRM address, not an SSH one", a)
		}
		return a, nil
	}
	if len(in.Args) == 2 {
		a, err := fix(in.Args[1])
		if err != nil {
			return err
		}
		in.Args = []string{in.Args[0], a}
	}
	if p, ok := in.vals["address"].(*string); ok && *p != "" {
		a, err := fix(*p)
		if err != nil {
			return err
		}
		*p = a
	}
	return nil
}

// hostBodyInput is the input as today's host commands read it: the sudo
// credential is their --sudo-ref, a reference to a credential.
func hostBodyInput(in leafInput) leafInput {
	if p, ok := in.vals["sudo-credential"].(*string); ok {
		in.vals = maps.Clone(in.vals)
		in.vals["sudo-ref"] = &[]string{credentialRef(*p)}[0]
		delete(in.vals, "sudo-credential")
		changed := in.changed
		in.changed = func(n string) bool {
			if n == "sudo-ref" {
				n = "sudo-credential"
			}
			return changed(n)
		}
	}
	if p, ok := in.vals["unset"].(*[]string); ok {
		words := slices.Clone(*p)
		for i, w := range words {
			if w == "sudo-credential" {
				words[i] = "sudo-ref"
			}
		}
		in.vals = maps.Clone(in.vals)
		in.vals["unset"] = &words
	}
	return in
}
