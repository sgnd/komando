package cli

import (
	"context"
	"strings"

	"github.com/spf13/cobra"

	"github.com/sgnd/komando/internal/capability"
	"github.com/sgnd/komando/internal/out"
	"github.com/sgnd/komando/internal/store"
)

// The vpn type of the table: komando vpn KIND VERB. The verbs are today's
// vpn commands run through runBody (add, edit, remove, rename, show, list,
// test, start, stop, status), each on the VPNs of its kind only: the kind
// in the path must be the kind the VPN was saved with (WRONG_KIND).
// Nothing is built per provider here: the providers, their texts and their
// options come from the table when the tree is mounted, and a form hint is
// made when a command asks for it (vpnHint).

// vpnBodies are today's commands that the vpn leaves run, by verb.
var vpnBodies = map[string]func(kind string) *cobra.Command{
	"add":    func(string) *cobra.Command { return vpnAddCmd() },
	"edit":   func(string) *cobra.Command { return vpnEditCmd() },
	"list":   func(kind string) *cobra.Command { return listCmdKind("vpn", kind) },
	"remove": func(string) *cobra.Command { return vpnRmCmd() },
	"rename": func(string) *cobra.Command { return vpnMvCmd() },
	"show":   func(string) *cobra.Command { return vpnShowCmd() },
	"start":  func(string) *cobra.Command { return vpnUpCmd() },
	"status": vpnStatusCmd,
	"stop":   func(string) *cobra.Command { return vpnDownCmd() },
	"test":   func(string) *cobra.Command { return testCmdFor("vpn") },
}

// vpnVerbsOnNames are the verbs whose first arguments are VPN names or
// selectors that must be of the kind in the path.
var vpnVerbsOnNames = map[string]bool{"edit": true, "remove": true, "rename": true, "show": true,
	"start": true, "stop": true, "status": true, "test": true}

func init() {
	for _, p := range capability.Children("vpn") {
		for verb, body := range vpnBodies {
			handlers[capability.Key{Type: "vpn", Provider: p, Verb: verb}] = func(cl *call, ctx context.Context, in leafInput) error {
				if vpnVerbsOnNames[verb] {
					targets := in.Args
					if verb == "rename" {
						targets = in.Args[:1] // the second word is a new name
					}
					if err := withVpnTargets(cl, targets, p, verb); err != nil {
						return err
					}
				}
				if verb == "add" { // today's add takes the kind as its second word
					if in.Bool("overwrite") { // it replaces a VPN of this kind only
						if err := withVpnTargets(cl, in.Args[:1], p, verb); err != nil {
							return err
						}
					}
					in.Args = append(in.Args[:1:1], p)
				}
				return runBody(cl, ctx, body(p), in, nil)
			}
		}
		groupShorts["vpn "+p] = capability.VpnGroupShort(p)
		examples["komando vpn "+p] = vpnGroupExample(p)
	}
	moveType("vpn")
}

// vpnGroupExample is the example of a provider's group: the add lines of
// its leaf, then the commands that follow a VPN being added.
func vpnGroupExample(p string) string {
	add, _ := capability.Find(capability.Key{Type: "vpn", Provider: p, Verb: "add"})
	c := "  komando vpn " + p + " "
	return add.Example + "\n" + c + "test office\n" + c + "start office\n" + c + "status"
}

// withVpnTargets is nil when every VPN the targets name or pick is of this
// kind. A name that is no VPN, or a selector that picks none, is left to
// the command to say.
func withVpnTargets(cl *call, targets []string, kind, verb string) error {
	st, err := loadState()
	if err != nil {
		return err
	}
	for _, t := range targets {
		vs := []*store.Vpn{st.Vpns[t]}
		if vs[0] == nil {
			if !isSelector(t) {
				continue
			}
			sel, err := resolveSelection(cl, st, t)
			if err != nil {
				return err
			}
			vs = sel.Vpns
		}
		for _, v := range vs {
			if err := vpnIsOf(v, kind, verb); err != nil {
				return err
			}
		}
	}
	return nil
}

// vpnIsOf is nil when v is a VPN of this kind; another kind is WRONG_KIND
// with the path that fits it.
func vpnIsOf(v *store.Vpn, kind, verb string) error {
	if v.Kind == kind {
		return nil
	}
	return out.Errf(out.ExitUsage, "WRONG_KIND", "use `komando vpn "+v.Kind+" "+verb+" "+v.Name+"`",
		"%s is a %s VPN, not a %s one", v.Name, v.Kind, kind)
}

// vpnTakes says whether `vpn KIND add` takes the option, as the table
// writes it.
func vpnTakes(kind, option string) bool {
	l, ok := capability.Find(capability.Key{Type: "vpn", Provider: kind, Verb: "add"})
	if !ok {
		return false
	}
	_, has := l.Option(option)
	return has
}

// vpnEditTakes says whether `vpn KIND edit` takes the flag (spelled as
// today's commands have it), as the table writes it.
func vpnEditTakes(kind, flag string) bool {
	l, ok := capability.Find(capability.Key{Type: "vpn", Provider: kind, Verb: "edit"})
	if !ok {
		return false
	}
	_, has := l.Option(vpnFlagWord(flag))
	return has
}

// vpnFlagWord is a flag of today's commands as the table spells it.
func vpnFlagWord(flag string) string {
	switch flag {
	case "password-ref":
		return "credential"
	case "psk-ref":
		return "psk-credential"
	}
	return flag
}

// vpnFlagWords is vpnFlagWord for a list, as one line.
func vpnFlagWords(flags []string) string {
	words := make([]string, len(flags))
	for i, f := range flags {
		words[i] = vpnFlagWord(f)
	}
	return strings.Join(words, ", ")
}

// vpnKindsTaking are the kinds whose add takes the option, for a message.
func vpnKindsTaking(option string) []string {
	var kinds []string
	for _, p := range capability.Children("vpn") {
		if vpnTakes(p, option) {
			kinds = append(kinds, p)
		}
	}
	return kinds
}

// vpnPath is the words that run a verb on a VPN of this kind.
func vpnPath(kind, verb string) string { return "komando vpn " + kind + " " + verb }

// vpnKindWord is the kind of the saved VPN called name, for a hint that
// names its path; the word KIND when none is saved under it.
func vpnKindWord(name string) string {
	if st, err := loadState(); err == nil && st.Vpns[name] != nil {
		return st.Vpns[name].Kind
	}
	return "KIND"
}

// vpnStopAgain is the hint of a failed stop: the path that stops the VPN
// called name again. A session left from a removed VPN has no kind, so the
// hint names no path.
func vpnStopAgain(kind, name string) string {
	if kind == "" {
		return "run the same stop again"
	}
	return "run `" + vpnPath(kind, "stop") + " " + name + "` again"
}
