package cli

import (
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

// A flag with a permanent synonym (kubectl's --to-revision, --tail) has it
// as a hidden spelling that shares the flag's value: there is one variable,
// so every check that
// reads the flag (the ssh gate's gateReadForm, the guards, the dry run)
// sees what was typed under either name. Gate code reads flag values
// (GetBool, GetString), never Changed alone; flagChanged covers every
// spelling where a check needs to know whether a flag was given
// (docs/design/command-standard.md, S-5.18).

// flagAliasOf names, on a hidden spelling, the flag it is a spelling of.
const flagAliasOf = "komando.flag-alias-of"

// flagAlias adds old as a hidden spelling of c's local flag now, sharing
// its value. It panics when now is not a flag of c: that is a bug in
// komando, found by every test that builds the command tree.
func flagAlias(c *cobra.Command, old, now string) {
	f := c.Flags().Lookup(now)
	if f == nil {
		panic("flagAlias: " + c.CommandPath() + " has no --" + now)
	}
	a := &pflag.Flag{Name: old, Usage: "old name of --" + now, Value: f.Value, DefValue: f.DefValue,
		NoOptDefVal: f.NoOptDefVal, Hidden: true, Annotations: map[string][]string{flagAliasOf: {now}}}
	c.Flags().AddFlag(a)
}

// flagSpellings are the names of c's flag name: itself and its hidden
// spellings.
func flagSpellings(c *cobra.Command, name string) []string {
	names := []string{name}
	c.Flags().VisitAll(func(f *pflag.Flag) {
		if a := f.Annotations[flagAliasOf]; len(a) == 1 && a[0] == name {
			names = append(names, f.Name)
		}
	})
	return names
}

// flagChanged reports whether c's flag name was given under any spelling.
func flagChanged(c *cobra.Command, name string) bool {
	for _, n := range flagSpellings(c, name) {
		if c.Flags().Changed(n) {
			return true
		}
	}
	return false
}
