package kube

import (
	"cmp"
	"context"
	"errors"
	"os"
	"os/user"
	"path/filepath"
	"slices"
	"strconv"
	"strings"

	"github.com/sgnd/komando/internal/cloud"
)

// Credential plugins: the ones komando makes the token for itself (EKS,
// GKE), and the environment of the ones that run as a program.

// gcpAccessToken and eksToken make the builtin plugins' tokens; tests
// replace them.
var (
	gcpAccessToken = cloud.GCPAccessToken
	eksToken       = cloud.EKSToken
)

// ErrUncheckedLogin stops a token made from this computer's cloud login
// on its way to a server over plain http, or one whose certificate is not
// checked: the token is good for the cloud account, not only this cluster.
var ErrUncheckedLogin = errors.New("a login made from this computer's AWS or Google Cloud login goes to a cluster only over https with its certificate checked: take insecure-skip-tls-verify out of the kubeconfig (certificate-authority-data trusts the cluster's CA) and import it again")

// CloudLogin is the plugin whose token komando makes itself from this
// computer's AWS or Google Cloud login (Builtin), or nil. No program
// runs, but a credential of this computer goes to the context's server.
func (x *Context) CloudLogin() *ExecAuth {
	e := x.User.Exec
	if e == nil || x.User.Token != "" || !e.Builtin() {
		return nil
	}
	return e
}

// keptVars are what a credential plugin that runs with a recorded PATH
// keeps of the caller's environment: who and where it is, its language and
// its screen. Everything else is the caller's to set, and an AI agent's
// caller sets it to steer the program: a library to load (LD_PRELOAD,
// PYTHONPATH, NODE_OPTIONS, JAVA_TOOL_OPTIONS), a config of its own
// (KUBECONFIG, AWS_CONFIG_FILE), a proxy with its own CA. What the plugin
// needs beyond these is in the kubeconfig's own env.
var keptVars = []string{"USER", "LOGNAME", "LANG", "LC_ALL", "LC_CTYPE", "LC_MESSAGES", "TZ", "TMPDIR", "TERM", "DISPLAY", "WAYLAND_DISPLAY", "XDG_RUNTIME_DIR",
	"SYSTEMROOT", "SYSTEMDRIVE", "WINDIR", "PATHEXT", "TEMP", "TMP", "USERNAME", "USERDOMAIN"}

// userHome is the home folder of the user komando runs as, from the
// system's user list, not from HOME (the caller's to set).
func userHome() string {
	u, err := user.LookupId(strconv.Itoa(os.Getuid()))
	if err != nil {
		if u, err = user.Current(); err != nil {
			return ""
		}
	}
	return u.HomeDir
}

// pluginEnv is the environment of a credential plugin: base and what the
// kubeconfig sets. With a PATH the cli recorded for it (SearchPath), only
// keptVars of base stay, the home folder is the user's real one and PATH
// is the recorded one.
func pluginEnv(base []string, e *ExecAuth) []string {
	env := make([]string, 0, len(base)+len(e.Env)+2)
	for _, kv := range base {
		name, _, _ := strings.Cut(kv, "=")
		if e.SearchPath != "" && !slices.Contains(keptVars, strings.ToUpper(name)) {
			continue
		}
		env = append(env, kv)
	}
	if e.SearchPath != "" {
		env = append(env, "PATH="+e.SearchPath)
		if home := userHome(); home != "" {
			env = append(env, "HOME="+home, "USERPROFILE="+home)
		}
	}
	for _, kv := range e.Env {
		env = append(env, kv.Name+"="+kv.Value)
	}
	return env
}

// builtinToken makes the tokens of the common credential plugins without
// running them: `aws eks get-token`, aws-iam-authenticator and
// gke-gcloud-auth-plugin. ok is false for any other plugin, which then runs
// as the kubeconfig says.
func builtinToken(ctx context.Context, e *ExecAuth) (tok string, ok bool, err error) {
	if !e.Builtin() {
		return "", false, nil
	}
	env := map[string]string{}
	for _, kv := range e.Env {
		env[kv.Name] = kv.Value
	}
	arg := func(names ...string) string { return execArg(e.Args, names...) }
	profile := cmp.Or(arg("--profile"), env["AWS_PROFILE"], os.Getenv("AWS_PROFILE"))
	switch filepath.Base(e.Command) {
	case "aws":
		cluster := arg("--cluster-name", "--cluster-id")
		if cluster == "" {
			return "", true, errors.New("aws eks get-token in the kubeconfig names no --cluster-name")
		}
		tok, err := eksToken(ctx, profile, cmp.Or(arg("--region"), env["AWS_REGION"], env["AWS_DEFAULT_REGION"]), cluster, arg("--role-arn"))
		return tok, true, err
	case "aws-iam-authenticator":
		tok, err := eksToken(ctx, profile, cmp.Or(arg("--region"), env["AWS_REGION"]), arg("-i", "--cluster-id"), arg("-r", "--role"))
		return tok, true, err
	case "gke-gcloud-auth-plugin":
		tok, err := gcpAccessToken(ctx)
		return tok, true, err
	}
	return "", false, nil
}
