package cli

import (
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/sgnd/komando/internal/driver"
	"github.com/sgnd/komando/internal/kube"
	"github.com/sgnd/komando/internal/out"
	"github.com/sgnd/komando/internal/store"
)

// kctlVerbs are the commands dispatch runs.
var kctlVerbs = []string{"get", "describe", "logs", "log", "events", "version", "api-resources", "api-versions", "cluster-info",
	"explain", "top", "auth", "wait", "rollout", "apply", "diff", "create", "replace", "delete", "patch", "label", "annotate",
	"scale", "set", "cordon", "uncordon", "drain", "taint", "run", "exec", "cp", "debug", "certificate", "config"}

// kctlUsage refuses, before the command is rated, what komando's kubectl
// never runs, so the answer is the real reason and not "needs --write": an
// unknown verb, a session (port-forward), edit, and the config subcommands
// other than current-context and get-contexts.
func kctlUsage(args []string) error {
	verb, sub := strings.ToLower(args[0]), ""
	if len(args) > 1 {
		sub = strings.ToLower(args[1])
	}
	switch {
	case oneOf(verb, "port-forward", "proxy", "attach"):
		return out.Usage("%s is a session: use `komando cluster forward` (ports) or `komando cluster shell` (a terminal)", verb)
	case verb == "edit":
		return out.Usage("edit opens an editor: use `komando cluster get TARGET TYPE NAME -o yaml`, change the file, then `cluster run --write -- apply -f FILE`")
	case verb == "config" && !oneOf(sub, "current-context", "get-contexts"):
		return out.Usage("config supports current-context and get-contexts (komando keeps the kubeconfig in its vault; `komando conn show NAME` shows the conn)")
	case !oneOf(verb, kctlVerbs...):
		e := out.Usage("unknown command %q for komando's kubectl", verb)
		if near := kube.Nearest(verb, slices.Clone(kctlVerbs)); near != "" {
			e.Message += fmt.Sprintf("; did you mean %q?", near)
		}
		e.Hint = "see the commands it knows with `komando cluster run --help`"
		return e
	}
	return nil
}

// kindErr words a kind the cluster does not serve as kubectl does; any
// other error (discovery could not reach the cluster) stays as it is, so
// it is reported as what it is.
func kindErr(err error, format string, a ...any) error {
	var uk *kube.UnknownKindError
	if errors.As(err, &uk) {
		return kfail(format, a...)
	}
	return err
}

// kubectlRisk checks a kubectl command line and rates it.
func kubectlRisk(args []string) (driver.Risk, error) {
	if err := kctlUsage(args); err != nil {
		return 0, err
	}
	if err := checkKubectlFlags(args); err != nil {
		return 0, err
	}
	return classifyKubectl(args), nil
}

// auditBrokenWrite records a change whose connection broke: it may have
// reached the cluster before the connection went.
func auditBrokenWrite(st *store.State, conn string, args []string, risk driver.Risk, stop *out.Error) {
	if stop.Code == "K8S_UNREACHABLE" && risk > driver.RiskRead {
		audit(st, "cluster.run", nil, "kubectl "+strings.Join(redactArgs(args), " "), false, map[string]any{"conns": []string{conn}, "risk": risk.String(), "error": stop.Code})
	}
}
