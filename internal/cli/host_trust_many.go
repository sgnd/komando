package cli

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"

	"golang.org/x/crypto/ssh"

	"github.com/sgnd/komando/internal/out"
	"github.com/sgnd/komando/internal/sshx"
	"github.com/sgnd/komando/internal/store"
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
	OldFingerprint []string   `json:"old_fingerprints,omitempty"` // pinned keys that are not the server's
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
	if oe, ok := err.(*out.Error); ok && oe.Code != "CONNECT_FAILED" {
		return oe // a jump host's key or login, a timeout, a VPN: its own words
	}
	return out.Errf(out.ExitConnect, "KEYSCAN_FAILED", "check the address and port with `komando host show "+h.Name+"`", "cannot fetch host key from %s: %v", addr, err)
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
	if cl.interactive() && !cl.flags.dryRun {
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
func trustHosts(cl *call, ctx context.Context, st *store.State, hosts []*store.Host, reset bool) error {
	if cl.flags.dryRun {
		return trustDryRun(cl, st, hosts, reset)
	}
	rows := fetchTrustRows(cl, ctx, st, hosts)
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
		audit(cl, st, "host.trust", []string{r.Host}, "", true, map[string]any{"reset": reset, "removed_entries": r.RemovedEntries, "fingerprint": r.Fingerprint})
	}
	data.Summary.Total = len(rows)
	return finishFleet(cl, "host.trust", data, runSummary{fleetSummary: data.Summary}, worst, fails)
}

// trustDryRun fetches nothing and changes nothing: it says how each key
// would be fetched and, with --reset, how many pinned entries would go.
func trustDryRun(cl *call, st *store.State, hosts []*store.Host, reset bool) error {
	var res []map[string]any
	pinned := 0
	for _, h := range hosts {
		r := map[string]any{"host": h.Name, "address": trustAddr(h), "would_fetch_from": keyFetchPath(st, h)}
		if reset {
			n := countPinned(trustAddr(h))
			r["would_remove_entries"] = n
			pinned += n
		}
		res = append(res, r)
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
