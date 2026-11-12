package cli

import (
	"fmt"
	"path"
	"strings"

	"github.com/sgnd/komando/internal/out"
)

// Deletes that leave no copy behind are T3 (S-7.2, OD-7): a secret, the
// key files komando made, a file on a server. An AI agent or a script
// needs --allow-dangerous (an agent then gets the person's window); a
// person at the terminal types the name of what goes (S-7.3). cron rm and
// pkg rm stay T1: what they remove is easy to put back.

// guardLocalDelete stops a delete of komando's own things on this computer
// (secrets, key files) until it is allowed. Under --dry-run it records the
// stop and goes on. Call it before the state is locked: it may ask.
func guardLocalDelete(items []string, of, reason string) error {
	askTypes(items, of)
	if dangerOK(reason) || confirmDangerous(items, reason) {
		return nil
	}
	return policyStop(out.Errf(out.ExitPolicy, "POLICY_BLOCKED",
		"only if this is intended: confirm with the user, then re-run with --allow-dangerous (try --dry-run first)",
		"%s", reason).Say(dangerSay([]string{reason}), dangerHint))
}

// guardFsRm is fs rm's stop: every rm deletes for good. A folder with
// --recursive and a top-level path keep their own words; on a protected
// server the one typed question covers the protection too (S-7.4), and the
// stop's hint names --yes as well.
func guardFsRm(target string, paths []string, recursive bool) error {
	askTypes(paths, "paths on "+target)
	names := []string{target}
	prot, win := protectedTargets(target)
	if len(win) > 0 { // fs rm does not run there: say so before asking anything
		return notOnWindows("fs rm", win)
	}
	// flags is what the real run needs: --allow-dangerous, and --yes as
	// well on a protected server (S-7.5)
	flags, dry := "--allow-dangerous", " (try --dry-run first)"
	if len(prot) > 0 && !g.yes {
		flags, dry = "--allow-dangerous and --yes (a protected server)", " and --yes (a protected server; try --dry-run first)"
	}
	stop := func(hint, reason, msg string, a ...any) error {
		if dangerOK(reason) || confirmDangerousOn(names, prot, reason) {
			return nil
		}
		return policyStop(out.Errf(out.ExitPolicy, "POLICY_BLOCKED", hint, msg, a...).
			Say(dangerSay([]string{reason}), dangerHint).Need(protNeed(prot)...))
	}
	if recursive {
		return stop("a folder and everything in it would be gone; confirm with the user, then add "+flags,
			"rm --recursive deletes whole folders and everything in them", "rm --recursive deletes whole folders")
	}
	for _, p := range paths {
		if cp := path.Clean(p); cp == "/" || cp == "." || cp == "~" || strings.Count(cp, "/") <= 1 && strings.HasPrefix(cp, "/") {
			return stop("only if this is intended: confirm with the user, then add "+flags,
				fmt.Sprintf("removing the top-level path %s", p), "%q is a top-level path; komando does not remove it without --allow-dangerous", p)
		}
	}
	return stop("a deleted file has no copy; confirm with the user, then add --allow-dangerous"+dry,
		fmt.Sprintf("deletes %s on %s for good", joinAnd(paths), target), "fs rm deletes %s on %s for good", joinAnd(paths), target)
}

// protectedTargets are the protected servers target picks, and its
// Windows servers (none when it picks nothing: the command's own lookup
// says what is wrong).
func protectedTargets(target string) (prot, windows []string) {
	st, err := loadState()
	if err != nil {
		return nil, nil
	}
	hosts, err := resolveTargets(st, target)
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
