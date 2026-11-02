package cli

import (
	"sort"
	"strings"

	"github.com/spf13/cobra"

	"github.com/sgnd/komando/internal/store"
	"github.com/sgnd/komando/internal/vault"
)

// addCompletion lets the shell complete the first argument of every command
// from the inventory: TARGET gets servers, conns, VPNs, @groups and tag:x;
// CONN gets conns; NAME under host/conn/vpn/key/secret/recipe gets those
// names (docs/design/ux.md, section 10).
func addCompletion(c *cobra.Command) {
	for _, sub := range c.Commands() {
		addCompletion(sub)
	}
	if c.ValidArgsFunction != nil || !c.Runnable() {
		return
	}
	f := strings.Fields(c.Use)
	if len(f) < 2 {
		return
	}
	kind := f[1]
	if kind == "NAME" || kind == "NAME..." {
		kind = c.Parent().Name()
	}
	kind = strings.TrimSuffix(kind, "...")
	switch kind {
	case "TARGET", "CONN", "host", "conn", "vpn", "key", "secret", "recipe":
	default:
		return
	}
	c.ValidArgsFunction = func(_ *cobra.Command, args []string, _ string) ([]string, cobra.ShellCompDirective) {
		if len(args) > 0 && !strings.HasSuffix(f[1], "...") {
			return nil, cobra.ShellCompDirectiveDefault // later args: files, as the shell would
		}
		return completionNames(kind), cobra.ShellCompDirectiveNoFileComp
	}
}

func completionNames(kind string) []string {
	if kind == "secret" {
		var names []string
		if l, err := vault.List(); err == nil {
			for _, i := range l {
				names = append(names, i.Name)
			}
		}
		return names
	}
	st, err := store.Load()
	if err != nil {
		return nil
	}
	var names []string
	add := func(n string) { names = append(names, n) }
	groups, tags := map[string]bool{}, map[string]bool{}
	if kind == "TARGET" || kind == "host" {
		for _, h := range st.SortedHosts() {
			add(h.Name)
			for _, g := range h.Groups {
				groups[g] = true
			}
			for _, t := range h.Tags {
				tags[t] = true
			}
		}
	}
	if kind == "TARGET" || kind == "CONN" || kind == "conn" {
		for _, c := range st.SortedConns() {
			add(c.Name)
			for _, g := range c.Groups {
				groups[g] = true
			}
			for _, t := range c.Tags {
				tags[t] = true
			}
		}
	}
	if kind == "TARGET" || kind == "vpn" {
		for _, v := range st.SortedVpns() {
			add(v.Name)
		}
	}
	switch kind {
	case "key":
		for n := range st.Keys {
			add(n)
		}
	case "recipe":
		for n := range st.Snippets { // saved recipes
			add(n)
		}
	}
	if kind == "TARGET" || kind == "CONN" {
		for g := range groups {
			add("@" + g)
		}
		for t := range tags {
			add("tag:" + t)
		}
		add("all")
	}
	sort.Strings(names)
	return names
}
