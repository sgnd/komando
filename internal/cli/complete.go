package cli

import (
	"bytes"
	"slices"
	"sort"
	"strings"

	"github.com/spf13/cobra"

	"github.com/sgnd/komando/internal/driver"
	"github.com/sgnd/komando/internal/netx"
	"github.com/sgnd/komando/internal/store"
	"github.com/sgnd/komando/internal/vault"
)

// addCompletion lets the shell complete arguments and flags from the
// inventory: TARGET gets servers, conns, VPNs, @groups, tag:x and kind:x
// (also after a comma or !); CONN gets conns; NAME under
// host/conn/vpn/key/secret/recipe gets those names; GROUP gets groups; the
// settings of `config get/set` and their values; --key, --via and --target
// get keys, servers and VPNs, and targets (docs/design/ux.md, section 10).
func addCompletion(c *cobra.Command) {
	for _, sub := range c.Commands() {
		addCompletion(sub)
	}
	if c.Name() == "completion" && c.HasParent() && !c.Parent().HasParent() {
		completionScripts(c)
	}
	flagCompletion(c, "key", func(string) []string { return completionNames("key") })
	flagCompletion(c, "via", func(prefix string) []string { return listPrefixed(prefix, completionNames("via")) })
	flagCompletion(c, "target", func(prefix string) []string { return targetCompletions(prefix) })
	if c.ValidArgsFunction != nil || !c.Runnable() {
		return
	}
	words := strings.Fields(c.Use)
	if len(words) < 2 {
		return
	}
	var kinds []string
	variadic := false
	for _, w := range words[1:] {
		w = strings.Trim(w, "[]")
		variadic = strings.HasSuffix(w, "...")
		w = strings.TrimSuffix(w, "...")
		if i := strings.LastIndex(w, "|"); i >= 0 {
			w = w[i+1:] // NAME|TARGET: complete targets
		}
		// completion is keyed by (group, word): NAME is the command's own
		// noun, KEY a cache key (none), SETTING a setting (S-4.2)
		switch {
		case w == "NAME":
			w = c.Parent().Name()
		case w == "SERVER":
			w = "host"
		case w == "SETTING":
			w = "setting"
		case w == "VALUE" && c.Parent().Name() == "config":
			w = "setting-value"
		}
		kinds = append(kinds, w)
	}
	known := false
	for _, k := range kinds {
		switch k {
		case "TARGET", "CONN", "host", "conn", "vpn", "key", "secret", "recipe", "GROUP", "setting", "setting-value":
			known = true
		}
	}
	if !known {
		return
	}
	c.ValidArgsFunction = func(_ *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
		i := len(args)
		if i >= len(kinds) {
			if !variadic {
				return nil, cobra.ShellCompDirectiveDefault // later args: files, as the shell would
			}
			i = len(kinds) - 1
		}
		switch kinds[i] {
		case "TARGET":
			return keepTargets(targetCompletions(toComplete), targetKinds(c)), cobra.ShellCompDirectiveNoFileComp | cobra.ShellCompDirectiveNoSpace
		case "setting-value":
			if len(args) > 0 {
				if s, err := findSetting(args[0]); err == nil {
					return settingValues(s), cobra.ShellCompDirectiveNoFileComp
				}
			}
			return nil, cobra.ShellCompDirectiveNoFileComp
		case "CONN":
			return connsOfFamily(completionNames("CONN"), commandFamily(c)), cobra.ShellCompDirectiveNoFileComp
		case "key":
			if c.Name() == "deploy" || c.Name() == "revoke" {
				return completionNames("key"), cobra.ShellCompDirectiveDefault // a key name or a .pub file
			}
			return completionNames("key"), cobra.ShellCompDirectiveNoFileComp
		case "host", "conn", "vpn", "secret", "recipe", "GROUP", "setting":
			return completionNames(kinds[i]), cobra.ShellCompDirectiveNoFileComp
		}
		return nil, cobra.ShellCompDirectiveDefault
	}
}

// commandFamily is the conn family a command works with: "cache" for
// `cache info`, "db" for `db user grants`; "" for other commands.
func commandFamily(c *cobra.Command) string {
	for ; c.HasParent(); c = c.Parent() {
		if !c.Parent().HasParent() {
			switch c.Name() {
			case "db", "cache", "queue", "storage", "cluster", "registry":
				return c.Name()
			}
		}
	}
	return ""
}

// connsOfFamily leaves out the conns another command works with, so
// `cache info <Tab>` offers caches, not databases. Groups, tags, all and
// kind: stay: they pick the right conns when the command runs.
func connsOfFamily(names []string, family string) []string {
	if family == "" {
		return names
	}
	st, err := store.Load()
	if err != nil {
		return names
	}
	var keep []string
	for _, n := range names {
		if c, ok := st.Conns[n]; ok && connFamily(c) != family {
			continue
		}
		keep = append(keep, n)
	}
	return keep
}

func flagCompletion(c *cobra.Command, flag string, f func(prefix string) []string) {
	if c.LocalFlags().Lookup(flag) == nil {
		return
	}
	_ = c.RegisterFlagCompletionFunc(flag, func(_ *cobra.Command, _ []string, toComplete string) ([]string, cobra.ShellCompDirective) {
		return f(toComplete), cobra.ShellCompDirectiveNoFileComp
	})
}

// listPrefixed completes the last item of a comma-separated list.
func listPrefixed(toComplete string, names []string) []string {
	head := ""
	if i := strings.LastIndex(toComplete, ","); i >= 0 {
		head = toComplete[:i+1]
	}
	out := make([]string, len(names))
	for i, n := range names {
		out[i] = head + n
	}
	return out
}

// targetCompletions completes the last part of a selector expression,
// keeping what comes before it ("web1,!") and kind: values.
func targetCompletions(toComplete string) []string {
	head, last := "", toComplete
	if i := strings.LastIndex(toComplete, ","); i >= 0 {
		head, last = toComplete[:i+1], toComplete[i+1:]
	}
	if strings.HasPrefix(last, "!") {
		head, last = head+"!", last[1:]
	}
	var names []string
	if strings.HasPrefix(last, "kind:") {
		names = kindValues()
	} else {
		names = completionNames("TARGET")
	}
	for i, n := range names {
		names[i] = head + n
	}
	return names
}

func kindValues() []string {
	seen := map[string]bool{"kind:host": true, "kind:conn": true, "kind:vpn": true}
	for _, k := range driver.Kinds() {
		seen["kind:"+k.Name], seen["kind:"+k.Family] = true, true
	}
	for k := range netx.Kinds {
		seen["kind:"+k] = true
	}
	return mapKeys(seen)
}

func settingValues(s *setting) []string {
	if !strings.Contains(s.Values, "|") {
		return nil
	}
	var v []string
	for _, x := range strings.Split(s.Values, "|") {
		v = append(v, strings.TrimSpace(x))
	}
	return v
}

func completionNames(kind string) []string {
	switch kind {
	case "secret":
		var names []string
		if l, err := vault.List(); err == nil {
			for _, i := range l {
				names = append(names, i.Name)
			}
		}
		return names
	case "setting":
		return settingKeys()
	}
	st, err := store.Load()
	if err != nil {
		return nil
	}
	var names []string
	add := func(n string) { names = append(names, n) }
	groups, tags := map[string]bool{}, map[string]bool{}
	if kind == "TARGET" || kind == "host" || kind == "via" || kind == "GROUP" {
		for _, h := range st.SortedHosts() {
			if kind != "GROUP" {
				add(h.Name)
			}
			for _, g := range h.Groups {
				groups[g] = true
			}
			for _, t := range h.Tags {
				tags[t] = true
			}
		}
	}
	if kind == "TARGET" || kind == "CONN" || kind == "conn" || kind == "GROUP" {
		for _, c := range st.SortedConns() {
			if kind != "GROUP" {
				add(c.Name)
			}
			for _, g := range c.Groups {
				groups[g] = true
			}
			for _, t := range c.Tags {
				tags[t] = true
			}
		}
	}
	if kind == "TARGET" || kind == "vpn" || kind == "via" || kind == "GROUP" {
		for _, v := range st.SortedVpns() {
			if kind != "GROUP" {
				add(v.Name)
			}
			for _, g := range v.Groups {
				groups[g] = true
			}
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
	case "GROUP":
		for g := range groups {
			add(g)
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
		add("kind:")
	}
	sort.Strings(names)
	return names
}

// completionHelp is how each shell turns completion on, as a line a person
// adds once to the shell's startup file. bash takes eval, not source <(...):
// the bash 3.2 of macOS reads nothing from source <(...).
var completionHelp = map[string]string{
	"bash": `Prints the tab-completion script for bash. Turn it on once, then open a new
terminal:

  echo 'eval "$(komando completion bash)"' >> ~/.bashrc

On macOS, where a new terminal reads ~/.bash_profile, add the line there.
Completing flags and names works without the bash-completion package; with
it, bash completes a little more.`,
	"zsh": `Prints the tab-completion script for zsh. Turn it on once, then open a new
terminal:

  echo 'source <(komando completion zsh)' >> ~/.zshrc

The script turns on zsh's completion system (compinit) itself when
~/.zshrc has not. Or save it where zsh finds completions:
komando completion zsh > "${fpath[1]}/_komando".`,
	"fish": `Prints the tab-completion script for fish. Turn it on once, then open a new
terminal:

  komando completion fish > ~/.config/fish/completions/komando.fish`,
	"powershell": `Prints the tab-completion script for PowerShell. Turn it on once: add this
line to your PowerShell profile (notepad $PROFILE), then open a new window:

  komando completion powershell | Out-String | Invoke-Expression`,
}

// zshInit turns on zsh's completion system when ~/.zshrc has not (a new
// Mac's has not): the script calls compdef, which compinit defines, so
// without it every new terminal said "command not found: compdef" and
// nothing completed.
const zshInit = "(( $+functions[compdef] )) || { autoload -Uz compinit && compinit }\n"

// completionScripts gives the shells' scripts komando's help, and the zsh
// script the line that makes `source <(komando completion zsh)` work on its
// own.
func completionScripts(c *cobra.Command) {
	for _, sh := range c.Commands() {
		if h, ok := completionHelp[sh.Name()]; ok {
			sh.Long = h
		}
		if sh.Name() != "zsh" {
			continue
		}
		sh.RunE = func(cmd *cobra.Command, _ []string) error {
			var b bytes.Buffer
			var err error
			if noDesc, _ := cmd.Flags().GetBool("no-descriptions"); noDesc {
				err = cmd.Root().GenZshCompletionNoDesc(&b)
			} else {
				err = cmd.Root().GenZshCompletion(&b)
			}
			if err != nil {
				return err
			}
			// after "#compdef komando", which must stay the first line
			first, rest, _ := bytes.Cut(b.Bytes(), []byte("\n"))
			script := slices.Concat(first, []byte("\n"+zshInit), rest)
			_, err = cmd.OutOrStdout().Write(script)
			return err
		}
	}
}
