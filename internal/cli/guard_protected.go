package cli

import (
	"fmt"
	"path"
	"strings"

	"github.com/sgnd/komando/internal/driver"
	"github.com/sgnd/komando/internal/out"
	"github.com/sgnd/komando/internal/store"
)

// guardConns is guard for conns. The driver classifies the operation first;
// destructive needs --allow-dangerous, and any change to a protected conn
// needs --yes. Exit code and codes match guard so agents handle both alike.
func guardConns(cl *call, st *store.State, conns []*store.Conn, v driver.Verdict) error {
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

// Deletes that leave no copy behind are T3 (S-7.2, OD-7): a secret, the
// key files komando made, a file on a server. An AI agent or a script
// needs --allow-dangerous (an agent then gets the person's window); a
// person at the terminal types the name of what goes (S-7.3). cron rm and
// pkg rm stay T1: what they remove is easy to put back.

// guardLocalDelete stops a delete of komando's own things on this computer
// (secrets, key files) until it is allowed. Under --dry-run it records the
// stop and goes on. Call it before the state is locked: it may ask.
func guardLocalDelete(cl *call, items []string, of, reason string) error {
	askTypes(cl, items, of)
	if cl.dangerOK(reason) || confirmDangerous(cl, items, reason) {
		return nil
	}
	return cl.policyStop(approvalErr(cl, "POLICY_BLOCKED", reason).Say(dangerSay([]string{reason}), dangerHint))
}

// guardFsRm is fs rm's stop: every rm deletes for good. A folder with
// --recursive and a top-level path keep their own words; on a protected
// server the one typed question covers the protection too (S-7.4), and the
// stop's hint names --yes as well.
func guardFsRm(cl *call, target string, paths []string, recursive bool) error {
	askTypes(cl, paths, "paths on "+target)
	names := []string{target}
	prot, win := protectedTargets(cl, target)
	if len(win) > 0 { // fs rm does not run there: say so before asking anything
		return notOnWindows("fs rm", win)
	}
	// flags is what the real run needs: --allow-dangerous, and --yes as
	// well on a protected server (S-7.5)
	flags, dry := "--allow-dangerous", " (try --dry-run first)"
	if len(prot) > 0 && !cl.flags.yes {
		flags, dry = "--allow-dangerous and --yes (a protected server)", " and --yes (a protected server; try --dry-run first)"
	}
	stop := func(hint, reason, msg string, a ...any) error {
		if cl.dangerOK(reason) || confirmDangerousOn(cl, names, prot, reason) {
			return nil
		}
		return cl.policyStop(out.Errf(out.ExitPolicy, "POLICY_BLOCKED", hint, msg, a...).
			Say(dangerSay([]string{reason}), dangerHint).Need(protNeed(prot)...))
	}
	if recursive {
		return stop("a folder and everything in it would be gone; confirm with the user, then add "+flags,
			"deletes whole folders and everything in them (rm --recursive)", "rm --recursive deletes whole folders")
	}
	for _, p := range paths {
		if cp := path.Clean(p); cp == "/" || cp == "." || cp == "~" || strings.Count(cp, "/") <= 1 && strings.HasPrefix(cp, "/") {
			return stop("only if this is intended: confirm with the user, then add "+flags,
				fmt.Sprintf("removes the top-level path %s", p), "%q is a top-level path; komando does not remove it without --allow-dangerous", p)
		}
	}
	return stop("a deleted file has no copy; confirm with the user, then add --allow-dangerous"+dry,
		fmt.Sprintf("deletes %s on %s for good", joinAnd(paths), target), "fs rm deletes %s on %s for good", joinAnd(paths), target)
}

// protectedTargets are the protected servers target picks, and its
// Windows servers (none when it picks nothing: the command's own lookup
// says what is wrong).
func protectedTargets(cl *call, target string) (prot, windows []string) {
	st, err := loadState()
	if err != nil {
		return nil, nil
	}
	hosts, err := resolveTargets(cl, st, target)
	if err != nil {
		return nil, nil
	}
	for _, h := range hosts {
		if protectedHost(st, h) {
			prot = append(prot, h.Name)
		}
	}
	return prot, windowsNames(hosts)
}
