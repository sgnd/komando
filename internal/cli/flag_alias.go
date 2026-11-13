package cli

import (
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

// A flag that gets a new name keeps its old one as a hidden spelling that
// shares the new flag's value: there is one variable, so every check that
// reads the flag (the ssh gate's gateReadForm, the guards, the dry run)
// sees what was typed under either name. Gate code reads flag values
// (GetBool, GetString), never Changed alone; flagChanged covers every
// spelling where a check needs to know whether a flag was given
// (docs/design/command-standard.md, S-5.18).

const (
	flagAliasOf = "komando.flag-alias-of" // the flag this one is a spelling of
	flagRetired = "komando.flag-retired"  // using it is noted (retiredName)
)

// flagAlias adds old as a hidden spelling of c's local flag now, sharing
// its value. It panics when now is not a flag of c: that is a bug in
// komando, found by every test that builds the command tree.
func flagAlias(c *cobra.Command, old, now string) *pflag.Flag {
	f := c.Flags().Lookup(now)
	if f == nil {
		panic("flagAlias: " + c.CommandPath() + " has no --" + now)
	}
	a := &pflag.Flag{Name: old, Usage: "old name of --" + now, Value: f.Value, DefValue: f.DefValue,
		NoOptDefVal: f.NoOptDefVal, Hidden: true, Annotations: map[string][]string{flagAliasOf: {now}}}
	c.Flags().AddFlag(a)
	return a
}

// retiredFlag is flagAlias for a retired flag: each use is noted with
// retiredName (meta.deprecated, and stderr at a terminal).
func retiredFlag(c *cobra.Command, old, now string) {
	flagAlias(c, old, now).Annotations[flagRetired] = []string{"true"}
}

// retiredShort adds -letter as a retired short spelling of c's flag now
// (a hidden flag that owns the letter and shares the value).
func retiredShort(c *cobra.Command, letter, now string) {
	f := c.Flags().Lookup(now)
	if f == nil {
		panic("retiredShort: " + c.CommandPath() + " has no --" + now)
	}
	c.Flags().AddFlag(&pflag.Flag{Name: letter, Shorthand: letter, Usage: "old short form of --" + now, Value: f.Value,
		DefValue: f.DefValue, Hidden: true, Annotations: map[string][]string{flagAliasOf: {now}, flagRetired: {"true"}}})
}

// noteRetiredFlags notes each retired flag spelling cmd was given.
func noteRetiredFlags(cmd *cobra.Command) {
	cmd.Flags().Visit(func(f *pflag.Flag) {
		if f.Annotations[flagRetired] != nil {
			used := "--" + f.Name
			if len(f.Name) == 1 {
				used = "-" + f.Name // retiredShort
			}
			retiredName(used, "--"+f.Annotations[flagAliasOf][0])
		}
	})
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
