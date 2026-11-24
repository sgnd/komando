package cli

import (
	"fmt"
	"strings"

	"github.com/sgnd/komando/internal/driver"
	"github.com/sgnd/komando/internal/store"
)

// GuardConns is Guard for conns. The driver classifies the operation first;
// destructive needs --allow-dangerous, and any change to a protected conn
// needs --yes. Exit code and codes match Guard so agents handle both alike.
func GuardConns(cl *call, st *store.State, conns []*store.Conn, v driver.Verdict) error {
	names := make([]string, len(conns))
	for i, c := range conns {
		names[i] = c.Name
	}
	var prot []string
	if v.Risk >= driver.RiskWrite {
		for _, c := range conns {
			if protectedConn(st, c) {
				prot = append(prot, c.Name)
			}
		}
	}
	if v.Risk >= driver.RiskDestructive && !cl.dangerAndYesOK(connProtWhy(prot), fmt.Sprintf("[%s] %s", strings.Join(v.RuleIDs, ","), strings.Join(v.Reasons, "; ")), connsWhy(names)) && !confirmDangerousOn(cl, names, prot, strings.Join(v.Reasons, "; ")) {
		if err := cl.policyStop(approvalErr(cl, "POLICY_BLOCKED",
			fmt.Sprintf("the operation matches destructive rules [%s]: %s", strings.Join(v.RuleIDs, ","), strings.Join(v.Reasons, "; ")), protNeed(prot)...).Say(dangerSay(v.Reasons), dangerHint)); err != nil {
			return err
		}
	}
	if len(prot) > 0 && !cl.yesOK(connProtWhy(prot)) && !confirmProtected(cl, prot) {
		return cl.policyStop(approvalErr(cl, "PROTECTED_TARGET",
			fmt.Sprintf("a %s action on protected %s: %s", v.Risk, nouns(len(prot), "conn"), strings.Join(prot, ", "))).Say(protectedSay(prot, connWord(conns, prot)), protectedHint))
	}
	return nil
}

// protectedHost is true when h is marked protected, or when a protected
// inventory host has the same address and port: otherwise an ad-hoc
// user@address or a second name for the same server would get around
// protection. Addresses are compared as sameServer does: by name, and by
// the IP addresses they lead to (each IP in its one canonical form, so
// ::ffff:10.0.0.5 is 10.0.0.5). A name this computer cannot look up (one
// only a jump host knows) is compared by its text only: failing closed on
// it would put every change behind --yes and teach people to say yes.
func protectedHost(st *store.State, h *store.Host) bool {
	if h.Protected {
		return true
	}
	for _, o := range st.Hosts {
		if o.Protected && o.EffectivePort() == h.EffectivePort() && sameServer(o.Address, h.Address) {
			return true
		}
	}
	// a protected sftp:// conn is an SSH server too (protectedConn reads
	// the link the other way)
	for _, c := range st.Conns {
		if !c.Protected {
			continue
		}
		if o := sftpHost(c); o != nil && o.EffectivePort() == h.EffectivePort() && sameServer(o.Address, h.Address) {
			return true
		}
	}
	return false
}

// protectedMark follows a protected target in targetsWhy, and
// protChangePrefix starts protWhy; the approval window reads both
// (newApprovalView) to show the protected fact once.
const (
	protectedMark    = " (protected)"
	protChangePrefix = "a change on protected "
)

// protWhy is the approval window's line for the protected servers a
// command changes, or "" for none.
func protWhy(prot []string) string {
	if len(prot) == 0 {
		return ""
	}
	return protChangePrefix + nouns(len(prot), "host") + " " + strings.Join(prot, ", ")
}

// connProtWhy is protWhy for conns.
func connProtWhy(prot []string) string {
	if len(prot) == 0 {
		return ""
	}
	return protChangePrefix + nouns(len(prot), "conn") + " " + strings.Join(prot, ", ")
}
