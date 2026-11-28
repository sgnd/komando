package cli

import (
	"fmt"
	"strings"

	"github.com/sgnd/komando/internal/cli/kit/term"
)

// What a rename prints and the stop before it changes protected entries.
// The engine is in rename_engine.go; each noun's own rename command calls it.

// renameSkip is a name that matched but is left alone, and why.
type renameSkip struct {
	Kind   string `json:"kind"`
	Name   string `json:"name"`
	Reason string `json:"reason"`
}

// renameResult is what a rename prints.
type renameResult struct {
	Prefix    *renamePair             `json:"prefix,omitempty"` // OLD and NEW
	Action    string                  `json:"action"`           // renamed | would_rename | unchanged
	Count     int                     `json:"count"`            // entries renamed
	Renamed   map[string][]renamePair `json:"renamed"`          // by kind
	Protected []string                `json:"protected"`        // protected servers and conns it changes ("host NAME", old names)
	Updated   []renameRef             `json:"updated"`          // references that follow
	Moved     []renamePair            `json:"moved"`            // key files and VPN state folders
	Skipped   []renameSkip            `json:"skipped,omitempty"`
	Kept      []renameKept            `json:"kept,omitempty"` // old names left in notes and labels, and why
	Warnings  []string                `json:"warnings,omitempty"`
}

func (r renameResult) Text() string {
	var sb strings.Builder
	verb := map[string]string{"renamed": "renamed", "would_rename": "would rename", "unchanged": "nothing to rename"}[r.Action]
	if r.Action == "unchanged" {
		sb.WriteString(verb)
	} else {
		fmt.Fprintf(&sb, "%s %d %s", verb, r.Count, renameNoun(r.Count, "entry"))
	}
	if r.Prefix != nil {
		fmt.Fprintf(&sb, " (prefix %s -> %s)", r.Prefix.From, r.Prefix.To)
	}
	sb.WriteString("\n")
	var rows [][]string
	head := []string{"KIND", "FROM", "TO"}
	if len(r.Protected) > 0 {
		head = append(head, "PROTECTED")
	}
	for _, k := range renameKinds {
		for _, p := range r.Renamed[k] {
			row := []string{k, p.From, p.To}
			if len(r.Protected) > 0 {
				row = append(row, term.YesCell(p.Protected))
			}
			rows = append(rows, row)
		}
	}
	if len(rows) > 0 {
		sb.WriteString(textTable(head, rows))
	}
	if len(r.Updated) > 0 {
		fmt.Fprintf(&sb, "references that follow (%d):\n", len(r.Updated))
		for _, u := range r.Updated {
			fmt.Fprintf(&sb, "  %s: %s -> %s\n", u, u.From, u.To)
		}
	}
	for _, m := range r.Moved {
		fmt.Fprintf(&sb, "moves %s -> %s\n", m.From, m.To)
	}
	for _, s := range r.Skipped {
		fmt.Fprintf(&sb, "left alone: %s %s (%s)\n", s.Kind, s.Name, s.Reason)
	}
	if len(r.Kept) > 0 {
		fmt.Fprintf(&sb, "old names kept in notes and labels (%d):\n", len(r.Kept))
		for _, k := range r.Kept {
			why := k.Reason
			if k.To != "" {
				why += "; it would become " + k.To
			}
			fmt.Fprintf(&sb, "  %s %s: %s (%s)\n", k.Entry, k.Field, k.Name, why)
		}
	}
	for _, w := range r.Warnings {
		fmt.Fprintf(&sb, "warning: %s\n", w)
	}
	return sb.String()
}

// nouns gives "entrys" for entry; renameNoun is the plural that reads.
func renameNoun(n int, noun string) string {
	if noun == "entry" && n != 1 {
		return "entries"
	}
	return nouns(n, noun)
}

// guardRenameProtected asks once for every protected server and conn a
// rename changes: --yes (for an AI agent, a person's "Allow once" in
// komando's window), or a yes at the terminal.
func guardRenameProtected(cl *call, what string, prot []string) error {
	hosts := 0
	names := make([]string, len(prot))
	for i, p := range prot {
		kind, name, _ := strings.Cut(p, " ")
		if kind == "host" {
			hosts++
		}
		names[i] = name
	}
	conns := len(prot) - hosts
	var count string
	switch {
	case hosts == 1 && conns == 0:
		count = "1 protected server"
	case hosts == 0 && conns == 1:
		count = "1 protected conn"
	case conns == 0:
		count = fmt.Sprintf("%d protected servers", hosts)
	case hosts == 0:
		count = fmt.Sprintf("%d protected conns", conns)
	default:
		count = fmt.Sprintf("%d protected entries (%d %s, %d %s)", len(prot), hosts, nouns(hosts, "server"), conns, nouns(conns, "conn"))
	}
	shown := names
	more := ""
	if len(shown) > 8 { // the window stays short; --dry-run lists them all
		shown, more = shown[:8], fmt.Sprintf(" and %d more", len(names)-8)
	}
	why := fmt.Sprintf("%s changes %s in one step: %s%s", what, count, strings.Join(shown, ", "), more)
	if cl.yesOK(why) || confirmYes(cl, why+". Continue?") {
		return nil
	}
	return cl.policyStop(approvalErr(cl, "PROTECTED_TARGET", fmt.Sprintf("%s changes %s (one yes covers all of them): %s", what, count, strings.Join(names, ", "))))
}
