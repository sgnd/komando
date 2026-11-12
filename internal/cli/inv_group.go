package cli

import (
	"cmp"
	"fmt"
	"sort"
	"strings"

	"github.com/spf13/cobra"

	"github.com/sgnd/komando/internal/out"
	"github.com/sgnd/komando/internal/store"
)

// Groups are names on servers, conns and VPNs (@web picks them all). They
// exist while something is in them, like labels in kubectl.

type groupList struct {
	Groups map[string][]string `json:"groups"`
	Tags   map[string][]string `json:"tags"`
}

func (l groupList) Text() string {
	var rows [][]string
	for _, n := range mapKeys(l.Groups) {
		rows = append(rows, []string{"@" + n, "group", strings.Join(l.Groups[n], ", ")})
	}
	for _, n := range mapKeys(l.Tags) {
		rows = append(rows, []string{"tag:" + n, "tag", strings.Join(l.Tags[n], ", ")})
	}
	// groups and tags in one list by name (a group before a tag of the
	// same name); the TYPE column tells them apart
	name := func(sel string) string { return strings.TrimPrefix(strings.TrimPrefix(sel, "@"), "tag:") }
	sort.SliceStable(rows, func(i, j int) bool { return name(rows[i][0]) < name(rows[j][0]) })
	if len(rows) == 0 {
		return "no groups or tags yet: komando group add GROUP TARGET\n"
	}
	return textTable([]string{"SELECTOR", "TYPE", "MEMBERS"}, rows)
}

type groupMembers struct {
	Group   string   `json:"group"`
	Members []string `json:"members"`
}

func (m groupMembers) Text() string { return strings.Join(m.Members, "\n") + "\n" }

// allGroups lists every group with its members (servers, conns, VPNs),
// and every tag.
func allGroups(st *store.State) groupList {
	l := groupList{Groups: map[string][]string{}, Tags: map[string][]string{}}
	add := func(name string, gs, ts []string) {
		for _, gr := range gs {
			l.Groups[gr] = append(l.Groups[gr], name)
		}
		for _, t := range ts {
			l.Tags[t] = append(l.Tags[t], name)
		}
	}
	for _, h := range st.SortedHosts() {
		add(h.Name, h.Groups, h.Tags)
	}
	for _, c := range st.SortedConns() {
		add(c.Name, c.Groups, c.Tags)
	}
	for _, v := range st.SortedVpns() {
		add(v.Name, v.Groups, v.Tags)
	}
	for _, m := range []map[string][]string{l.Groups, l.Tags} {
		for k := range m {
			sort.Strings(m[k])
		}
	}
	return l
}

// groupMembersOf is the members of a group, matched like @GROUP (any case).
func groupMembersOf(st *store.State, group string) []string {
	var names []string
	for gr, m := range allGroups(st).Groups {
		if strings.EqualFold(gr, group) {
			names = append(names, m...)
		}
	}
	sort.Strings(names)
	return dedupe(names)
}

func groupNotFound(st *store.State, group string) error {
	hint := "run `komando group list` to see groups"
	if s := closest(group, mapKeys(allGroups(st).Groups)); s != "" {
		hint = fmt.Sprintf("did you mean %q? (%s)", s, hint)
	}
	return out.Errf(out.ExitNotFound, "GROUP_NOT_FOUND", hint, "no group named %q", group)
}

// manyMembers: removing a whole group from more than this many entries
// asks for --yes first.
const manyMembers = 3

func groupCmd() *cobra.Command {
	c := &cobra.Command{
		Use:     "group",
		Aliases: []string{"groups"},
		Short:   "List groups and manage membership",
		Long: `A group is a name on servers, conns and VPNs; @GROUP picks all of them in any
command. Group names use letters, digits and . _ - and match in any case.
A group exists while something is in it.`,
	}
	var limit int
	list := &cobra.Command{
		Use:   "list [GROUP]",
		Short: "List groups and tags with their members, or the members of one group",
		Example: `  komando group list
  komando group list web`,
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			st, err := loadState()
			if err != nil {
				return err
			}
			if len(args) == 1 {
				group := strings.TrimPrefix(args[0], "@")
				m := groupMembersOf(st, group)
				if len(m) == 0 {
					return groupNotFound(st, group)
				}
				out.P.Print("group.list", groupMembers{Group: group, Members: cutRows(m, limit)}, nil)
				return nil
			}
			l := allGroups(st)
			l.Groups, l.Tags = cutMap(l.Groups, limit), cutMap(l.Tags, limit)
			out.P.Print("group.list", l, nil)
			return nil
		},
	}
	limitFlag(list, &limit, 0, "groups and tags each, or members of GROUP")
	c.AddCommand(list, synonymWrapper(list, "show GROUP", "group.list", "group list GROUP", cobra.ExactArgs(1)))
	c.AddCommand(groupAddCmd(), groupRmCmd(), groupMvCmd())
	return c
}

func groupAddCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "add GROUP TARGET...",
		Short: "Add servers, conns and VPNs matching TARGET to GROUP",
		Example: `  komando group add web web1,web2
  komando group add web web3 web4
  komando group add prod 'tag:live,!staging-*'`,
		Args: cobra.MinimumNArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			group := strings.TrimPrefix(args[0], "@")
			if err := validLabelName("group", group); err != nil {
				return err
			}
			res := map[string]any{"group": group}
			var added []string
			err := store.Update(func(s *store.State) error {
				sel, err := resolveSelection(s, strings.Join(args[1:], ","))
				if err != nil {
					return err
				}
				hosts, conns, vpns := []string{}, []string{}, []string{}
				has := func(gs []string) bool {
					for _, x := range gs {
						if strings.EqualFold(x, group) {
							return true
						}
					}
					return false
				}
				for _, h := range sel.Hosts {
					if h2, ok := s.Hosts[h.Name]; ok && !has(h2.Groups) { // not ad-hoc
						h2.Groups = dedupe(append(h2.Groups, group))
						hosts = append(hosts, h.Name)
					}
				}
				for _, c := range sel.Conns {
					if !has(c.Groups) {
						c.Groups = dedupe(append(c.Groups, group))
						conns = append(conns, c.Name)
					}
				}
				for _, v := range sel.Vpns {
					if !has(v.Groups) {
						v.Groups = dedupe(append(v.Groups, group))
						vpns = append(vpns, v.Name)
					}
				}
				res["hosts"], res["conns"], res["vpns"] = hosts, conns, vpns
				added = append(append(append(added, hosts...), conns...), vpns...)
				return nil
			})
			if err != nil {
				return err
			}
			audit(nil, "group.add", added, "", true, map[string]any{"group": group})
			out.P.Print("group.add", textAs{res, textBlob(changeSay("add", joinAnd(added), "to @"+group))}, nil)
			return nil
		},
	}
}

func groupRmCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "rm GROUP [TARGET...]",
		Short: "Take servers, conns and VPNs out of GROUP (without TARGET: delete the group)",
		Long: `Takes the entries TARGET picks out of GROUP; entries that are not in it are
left alone. Without TARGET the group is deleted: every member leaves it.
Deleting a group with more than 3 members needs --yes; try --dry-run first.`,
		Example: `  komando group rm web web2
  komando group rm old-batch --dry-run   # who would leave it
  komando group rm old-batch --yes`,
		Args: cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			group := strings.TrimPrefix(args[0], "@")
			removed := []string{}
			err := store.Update(func(s *store.State) error {
				members := groupMembersOf(s, group)
				if len(members) == 0 {
					return groupNotFound(s, group)
				}
				pick := map[string]bool{}
				if len(args) >= 2 {
					sel, err := resolveSelection(s, strings.Join(args[1:], ","))
					if err != nil {
						return err
					}
					for _, h := range sel.Hosts {
						pick[h.Name] = true
					}
					for _, c := range sel.Conns {
						pick[c.Name] = true
					}
					for _, v := range sel.Vpns {
						pick[v.Name] = true
					}
				} else {
					for _, m := range members {
						pick[m] = true
					}
					if len(members) > manyMembers && !yesOK() && !confirmYes(fmt.Sprintf("Delete group %s from %d entries?", group, len(members))) {
						if err := policyStop(out.Errf(out.ExitPolicy, "CONFIRM_REQUIRED", "check the members with `komando group list "+group+"`, then re-run with --yes",
							"deleting group %s takes %d entries out of it", group, len(members))); err != nil {
							return err
						}
					}
				}
				drop := func(name string, gs []string) []string {
					if !pick[name] {
						return gs
					}
					left := removeFold(gs, []string{group})
					if len(left) != len(gs) {
						removed = append(removed, name)
					}
					return left
				}
				for _, h := range s.Hosts {
					h.Groups = drop(h.Name, h.Groups)
				}
				for _, c := range s.Conns {
					c.Groups = drop(c.Name, c.Groups)
				}
				for _, v := range s.Vpns {
					v.Groups = drop(v.Name, v.Groups)
				}
				sort.Strings(removed)
				return nil
			})
			if err != nil {
				return err
			}
			audit(nil, "group.rm", removed, "", true, map[string]any{"group": group, "whole_group": len(args) == 1})
			key := "removed"
			if g.dryRun {
				key = "would_remove"
			}
			say := changeSay("remove", joinAnd(removed), "from @"+group)
			if len(args) == 1 {
				say = changeSay("remove", "group @"+group, "from "+cmp.Or(joinAnd(removed), "nothing"))
			}
			out.P.Print("group.rm", textAs{map[string]any{"group": group, key: removed}, textBlob(say)}, nil)
			return nil
		},
	}
}
