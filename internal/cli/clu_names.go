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

// objectRef reads the object from the words after TARGET: one word
// TYPE/NAME, or two words TYPE NAME.
func objectRef(words []string) (typ, name string, err error) {
	switch len(words) {
	case 1:
		return splitRef(words[0])
	case 2:
		if strings.Contains(words[0], "/") {
			return "", "", out.Usage("write TYPE/NAME or TYPE NAME, not both (%s %s)", words[0], words[1])
		}
		if words[0] == "" || words[1] == "" {
			return "", "", out.Usage("give TYPE/NAME or TYPE NAME, e.g. deployment/api")
		}
		return words[0], words[1], nil
	}
	return "", "", out.Usage("give TYPE/NAME or TYPE NAME, e.g. deployment/api")
}

// splitRef parses TYPE/NAME, as in deployment/api.
func splitRef(ref string) (string, string, error) {
	typ, name, ok := strings.Cut(ref, "/")
	if !ok || typ == "" || name == "" || strings.Contains(name, "/") {
		return "", "", out.Usage("give TYPE/NAME (or TYPE NAME), e.g. deployment/api")
	}
	return typ, name, nil
}

// refArgs says how many words a TYPE/NAME or TYPE NAME object takes when
// extra more positional words follow it (scale's REPLICAS).
func refArgs(before, extra int) cobra.PositionalArgs {
	return func(cmd *cobra.Command, args []string) error {
		if n := len(args); n < before+1+extra || n > before+2+extra {
			return cobra.RangeArgs(before+1+extra, before+2+extra)(cmd, args)
		}
		return nil
	}
}

// swarmKind maps what people type for Swarm objects to one kind: service,
// task, node or stack ("" when it is none of them).
func swarmKind(typ string) string {
	switch strings.ToLower(typ) {
	case "service", "services", "svc", "svcs":
		return "service"
	case "task", "tasks", "pod", "pods", "po", "container", "containers":
		return "task"
	case "node", "nodes", "no":
		return "node"
	case "stack", "stacks":
		return "stack"
	}
	return ""
}

// resource finds a Kubernetes kind. An unknown kind is a usage error that
// suggests the nearest one; a failed discovery stays a cluster error.
func resource(ctx context.Context, k *kube.Client, typ string) (kube.ResourceType, error) {
	r, err := k.Resource(ctx, typ)
	var uk *kube.UnknownKindError
	if errors.As(err, &uk) {
		e := out.Usage("%v", err)
		e.Hint = "see every kind with `komando cluster run TARGET -- api-resources`"
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
type nsShort struct{ ns *string }

func (v *nsShort) String() string { return *v.ns }
func (v *nsShort) Type() string   { return "string" }
func (v *nsShort) Set(s string) error {
	if s != "" && strings.Trim(s, "0123456789") == "" {
		return flagHint(fmt.Sprintf("%s is a count, but -n is --namespace in cluster commands", s),
			fmt.Sprintf("`--limit %s`, or `--namespace=%s` for a namespace named %s", s, s, s))
	}
	*v.ns = s
	return nil
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
	short := &pflag.Flag{Name: "n", Shorthand: "n", Usage: "-n NAMESPACE", Value: &nsShort{ns}, Hidden: true,
		Annotations: map[string][]string{flagAliasOf: {"namespace"}}}
	fl.AddFlag(short)
	short.Shorthand = ""
	fl.StringVar(ns, "namespace", "", "Kubernetes namespace (default: the context's, else default)")
	fl.Lookup("namespace").Shorthand = "n"
	if all != nil {
		fl.BoolVarP(all, "all-namespaces", "A", false, "every namespace")
	}
	if lim != nil {
		*lim.p = lim.def
		fl.Var(&limitValue{lim.p}, "limit", lim.usage)
	}
}

// nsOrAll refuses --namespace with -A, which kubectl lets -A win silently.
func nsOrAll(ns string, all bool) error {
	if ns != "" && all {
		return out.Usage("--namespace and -A (every namespace) do not go together; pick one")
	}
	return nil
}

// noNamespace refuses --namespace on Swarm, which has none.
func noNamespace(t clusterTarget, ns string) error {
	if t.host != nil && ns != "" {
		return out.Usage("Swarm has no namespaces: leave out --namespace (a stack's services are named STACK_SERVICE)")
	}
	return nil
}
