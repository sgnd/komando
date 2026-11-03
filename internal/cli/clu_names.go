package cli

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/spf13/cobra"

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

// limitValue is --limit/-n. In komando -n always means how many (one
// meaning per short flag); kubectl users type -n NAMESPACE out of habit, so
// a name there gets an answer that says what to write instead.
type limitValue struct {
	limit *int // nil: the command counts nothing; -n is only there to explain
}

func (v *limitValue) String() string {
	if v.limit == nil {
		return ""
	}
	return strconv.Itoa(*v.limit)
}
func (v *limitValue) Type() string { return "int" }
func (v *limitValue) Set(s string) error {
	n, err := strconv.Atoi(s)
	switch {
	case err != nil:
		return fmt.Errorf("-n is how many (a number); a namespace is --namespace %s", s)
	case v.limit == nil:
		return fmt.Errorf("this command counts nothing: -n is how many in komando; a namespace is --namespace NAME")
	case n < 0:
		return errors.New("a count is 0 or more")
	}
	*v.limit = n
	return nil
}

// limitOpt describes a command's --limit.
type limitOpt struct {
	p     *int
	def   int
	usage string
}

// nsFlags adds --namespace, --all-namespaces/-A when all is set, and
// --limit/-n (lim nil: a hidden -n that explains namespaces are --namespace).
func nsFlags(c *cobra.Command, ns *string, all *bool, lim *limitOpt) {
	c.Flags().StringVar(ns, "namespace", "", "Kubernetes namespace (default: the context's, else default)")
	if all != nil {
		c.Flags().BoolVarP(all, "all-namespaces", "A", false, "every namespace")
	}
	if lim == nil {
		c.Flags().VarP(&limitValue{}, "limit", "n", "")
		_ = c.Flags().MarkHidden("limit")
		return
	}
	*lim.p = lim.def
	c.Flags().VarP(&limitValue{lim.p}, "limit", "n", lim.usage)
}

// noNamespace refuses --namespace on Swarm, which has none.
func noNamespace(t clusterTarget, ns string) error {
	if t.host != nil && ns != "" {
		return out.Usage("Swarm has no namespaces: leave out --namespace (a stack's services are named STACK_SERVICE)")
	}
	return nil
}
