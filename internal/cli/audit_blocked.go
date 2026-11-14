package cli

import (
	"github.com/spf13/cobra"

	"github.com/sgnd/komando/internal/out"
	"github.com/sgnd/komando/internal/store"
)

// auditBlocked records a safety stop (exit 6) that the command itself did
// not record, so `audit --failed` shows every blocked attempt: a protected
// host rm, a deny rule removal, a secret sent somewhere.
func auditBlocked(cl *call, cmd *cobra.Command, e *out.Error) {
	if e.Exit != out.ExitPolicy || cl.blockAudited || cl.flags.dryRun || cmd == nil || leavesHomeNow(cmd) {
		return
	}
	st, err := loadState()
	if err != nil {
		st = nil // recorded anyway: a broken state file is no reason to lose it
	}
	var hosts, conns []string
	if st != nil { // what it was stopped on, for `audit --target`
		hosts, conns = blockedTargets(cl, st, cmd)
	}
	extra := map[string]any{"blocked": e.Code, "message": e.Message}
	if conns != nil {
		extra["conns"] = conns
	}
	audit(cl, st, commandName(cmd), hosts, "", false, extra)
}

// blockedTargets are the servers and conns a stopped command named: a name,
// or what a selector picked (@prod, tag:edge, web-*), so the audit line
// says web2 rather than "-". Only arguments before "--" count (after it
// comes the remote command), and only what is in the inventory: an
// ad-hoc address or a word that picks nothing is left out.
func blockedTargets(cl *call, st *store.State, cmd *cobra.Command) (hosts, conns []string) {
	args := cmd.Flags().Args()
	if n := cmd.ArgsLenAtDash(); n >= 0 && n <= len(args) {
		args = args[:n]
	}
	seen := map[string]bool{}
	add := func(kind, name string) {
		if seen[kind+" "+name] {
			return
		}
		seen[kind+" "+name] = true
		if kind == "host" {
			hosts = append(hosts, name)
		} else {
			conns = append(conns, name)
		}
	}
	for _, a := range args {
		if kind, name, ok := st.FindName(a); ok {
			if kind == "host" || kind == "conn" {
				add(kind, name)
			}
			continue
		}
		sel, err := pickedBy(cl, st, a)
		if err != nil {
			continue
		}
		for _, h := range sel.Hosts {
			if st.Hosts[h.Name] == h {
				add("host", h.Name)
			}
		}
		for _, c := range sel.Conns {
			add("conn", c.Name)
		}
	}
	return hosts, conns
}

// pickedBy is what a selector expression picks, like resolveSelection but
// with no side effect: recording a stop must not change how the rest of
// the output is masked.
func pickedBy(cl *call, st *store.State, expr string) (selection, error) {
	type item struct {
		h *store.Host
		c *store.Conn
	}
	items, err := resolveExpr(expr, func(one string) ([]item, error) {
		m, err := matchSelector(cl, st, one)
		var res []item
		for _, h := range m.Hosts {
			res = append(res, item{h: h})
		}
		for _, c := range m.Conns {
			res = append(res, item{c: c})
		}
		return res, err
	}, func(it item) string {
		if it.h != nil {
			return "host " + it.h.Name
		}
		return "conn " + it.c.Name
	})
	var sel selection
	for _, it := range items {
		if it.h != nil {
			sel.Hosts = append(sel.Hosts, it.h)
		} else {
			sel.Conns = append(sel.Conns, it.c)
		}
	}
	return sel, err
}
