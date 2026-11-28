package cli

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"

	"github.com/sgnd/komando/internal/kube"
	"github.com/sgnd/komando/internal/out"
)

// Every cluster verb names an object the same two ways kubectl does:
// TYPE NAME (deployment api) or TYPE/NAME (deployment/api). TYPE may be
// group-qualified (deployment.apps) and Swarm takes service/svc, task, ...

// splitRef parses TYPE/NAME, as in deployment/api.
func splitRef(ref string) (string, string, error) {
	typ, name, ok := strings.Cut(ref, "/")
	if !ok || typ == "" || name == "" || strings.Contains(name, "/") {
		return "", "", out.Usage("give TYPE/NAME (or TYPE NAME), for example deployment/api")
	}
	return typ, name, nil
}

// resource finds a Kubernetes kind. An unknown kind is a usage error that
// suggests the nearest one; a failed discovery stays a cluster error.
func resource(ctx context.Context, k *kube.Client, typ string) (kube.ResourceType, error) {
	r, err := k.Resource(ctx, typ)
	var uk *kube.UnknownKindError
	if errors.As(err, &uk) {
		e := out.Usage("%v", err)
		e.Hint = "see every kind with `komando cluster kubernetes raw NAME -- api-resources`"
		return r, e
	}
	return r, err
}

// limitValue is a cluster command's --limit: how many (it has no -n there,
// where -n is --namespace).
type limitValue struct {
	limit *int
}

func (v *limitValue) String() string { return strconv.Itoa(*v.limit) }
func (v *limitValue) Type() string   { return "int" }
func (v *limitValue) Set(s string) error {
	n, err := strconv.Atoi(s)
	switch {
	case err != nil:
		return fmt.Errorf("--limit is how many (a number); a namespace is --namespace %s", s)
	case n < 0:
		return errors.New("a count is 0 or more")
	}
	*v.limit = n
	return nil
}

// nsShort is -n in cluster commands: --namespace, as in kubectl. -n was
// a count (--limit) on cluster events, logs and ls, where only a number
// parsed; a number given as -n is therefore refused, always, so no old
// command line is read as a namespace named 50 (S-5.14).
type nsShort struct{ base pflag.Value } // --namespace's own value

func (v *nsShort) String() string     { return v.base.String() }
func (v *nsShort) Type() string       { return "string" }
func (v *nsShort) wraps() pflag.Value { return v.base }
func (v *nsShort) Set(s string) error {
	if s != "" && strings.Trim(s, "0123456789") == "" {
		return flagHint(fmt.Sprintf("%s is a count, but -n is --namespace in cluster commands", s),
			fmt.Sprintf("`--limit %s`, or `--namespace=%s` for a namespace named %s", s, s, s))
	}
	return v.base.Set(s)
}

// limitOpt describes a command's --limit.
type limitOpt struct {
	p     *int
	def   int
	usage string
}

// nsFlags adds -n/--namespace, --all-namespaces/-A when all is set, and
// --limit when lim is set (no shorthand: -n is the namespace here).
func nsFlags(c *cobra.Command, ns *string, all *bool, lim *limitOpt) {
	fl := c.Flags()
	// -n goes to nsShort, which refuses a number; help and schema show it on
	// --namespace. The parser finds -n through the set's own table, which
	// AddFlag fills, so the shorthand is set on the flag for the parser and
	// then moved to --namespace for every set derived from this one (help).
	fl.StringVar(ns, "namespace", "", "Kubernetes namespace (default: the context's, else default)")
	nsShorthand(fl, fl.Lookup("namespace"))
	if all != nil {
		fl.BoolVarP(all, "all-namespaces", "A", false, "every namespace")
	}
	if lim != nil {
		*lim.p = lim.def
		fl.Var(&limitValue{lim.p}, "limit", lim.usage)
	}
}

// nsShorthand gives the --namespace flag long its -n, through nsShort.
func nsShorthand(fl *pflag.FlagSet, long *pflag.Flag) {
	short := &pflag.Flag{Name: "n", Shorthand: "n", Usage: "-n NAMESPACE", Value: &nsShort{long.Value}, Hidden: true,
		Annotations: map[string][]string{flagAliasOf: {"namespace"}}}
	fl.AddFlag(short)
	short.Shorthand, long.Shorthand = "", "n"
}

// kindRef is "deployment/api".
func kindRef(r kube.ResourceType, name string) string {
	return strings.ToLower(r.KindName()) + "/" + name
}
