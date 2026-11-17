package cli

import (
	"cmp"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/sgnd/komando/internal/driver"
	"github.com/sgnd/komando/internal/kube"
	"github.com/sgnd/komando/internal/out"
	"github.com/sgnd/komando/internal/policy"
	"github.com/sgnd/komando/internal/sshx"
	"github.com/sgnd/komando/internal/store"
)

// `komando cluster` works the same on Kubernetes (a k8s conn: the API is
// called directly, through --via and VPNs) and Docker Swarm (a manager
// server: docker runs there over SSH). Verbs that exist in both engines
// sit directly under `cluster` (docs/design/principles.md).

type clusterTarget struct {
	conn *store.Conn // Kubernetes
	host *store.Host // Swarm manager
}

func resolveCluster(cl *call, st *store.State, expr string) (clusterTarget, error) {
	sel, err := resolveSelection(cl, st, expr)
	if err != nil {
		return clusterTarget{}, err
	}
	var k8s []*store.Conn
	for _, c := range sel.Conns {
		if connFamily(c) == "cluster" {
			k8s = append(k8s, c)
		}
	}
	switch {
	case len(k8s) == 1 && len(sel.Hosts) == 0:
		return clusterTarget{conn: k8s[0]}, nil
	case len(k8s) == 0 && len(sel.Hosts) == 1:
		return clusterTarget{host: sel.Hosts[0]}, nil
	case len(k8s)+len(sel.Hosts) == 0:
		return clusterTarget{}, noMatch(expr, "clusters (a k8s conn, or a Swarm manager server)", sel)
	}
	return clusterTarget{}, out.Usage("target %q picks %d clusters; this command works on one", expr, len(k8s)+len(sel.Hosts))
}

// kubeClient opens the API of a k8s conn through its --via path.
func kubeClient(cl *call, ctx context.Context, st *store.State, c *store.Conn) (*kube.Client, func(), error) {
	x, err := kubeContext(cl, c)
	if err != nil {
		return nil, nil, err
	}
	a, err := openAccess(cl, ctx, st, c)
	if err != nil {
		return nil, nil, err
	}
	var dial kube.Dialer
	if a.Dial != nil {
		dial = kube.Dialer(a.Dial)
	}
	k, err := kube.New(x, dial)
	if err != nil {
		a.Close()
		return nil, nil, out.Errf(out.ExitUsage, "KUBECONFIG", "check the kubeconfig", "conn %s: %v", c.Name, err)
	}
	k.Env = cl.environ() // a login program gets this command's environment
	return k, a.Close, nil
}

// kubeContext reads the conn's kubeconfig from the vault and checks its
// login program (guardKubePlugin), without connecting to anything.
func kubeContext(cl *call, c *store.Conn) (*kube.Context, error) {
	kc, err := resolvePassword(cl, nil, c)
	if err != nil {
		return nil, err
	}
	cfg, err := kube.Parse([]byte(kc))
	if err != nil {
		return nil, out.Errf(out.ExitUsage, "KUBECONFIG", "import it again with `komando import kubeconfig`", "conn %s: %v", c.Name, err)
	}
	x, err := cfg.Resolve("")
	if err != nil {
		return nil, out.Errf(out.ExitUsage, "KUBECONFIG", "import it again with `komando import kubeconfig`", "conn %s: %v", c.Name, err)
	}
	if ns := c.Options["namespace"]; ns != "" {
		x.Namespace = ns
	}
	if err := guardKubePlugin(cl, c, x); err != nil {
		return nil, err
	}
	return x, nil
}

// dryRunKubeCheck is for a dry run that stops before it connects (cluster
// exec, shell, forward): what the real run would need for the conn's
// login program still lands in meta.would_be_blocked.
func dryRunKubeCheck(cl *call, c *store.Conn) error {
	if _, err := kubeContext(cl, c); err != nil && !errors.Is(err, errDryRunStopped) {
		return err
	}
	return nil
}

// errDryRunStopped ends a dry run before it would run something only a
// person may allow (a kubeconfig's login program); the stop is in
// meta.would_be_blocked, and the command prints its plan instead.
var errDryRunStopped = errors.New("dry run stopped before a step that needs a person")

// guardKubePlugin: a kubeconfig credential plugin that komando does not
// make itself runs a program on this computer each time komando logs in,
// like a host's --proxy-command (guardProxyCommand). An AI agent can bring
// one in (import kubeconfig, or a kubeconfig stored with secret set), so
// an agent command that would run it needs a person's yes, unless a person
// trusted this very program for the conn (Conn.TrustedPlugin, set only by
// an import a person made or allowed). The plugin runs only after that.
// People and scripts wired it themselves.
//
// The program an agent's command runs for a trusted conn is the file the
// import found (Conn.PluginProgram), with the import's PATH: the agent's
// own PATH (`PATH=dir:$PATH komando ...`) picks neither the program nor
// its helpers, so the kubeconfig's arguments and environment (an OIDC
// client secret) reach only what the person trusted.
//
// A plugin komando makes the token for (EKS, GKE) runs nothing, but sends
// a login made from this computer's cloud login to the kubeconfig's
// server: guardCloudLogin.
func guardKubePlugin(cl *call, c *store.Conn, x *kube.Context) error {
	if b := x.CloudLogin(); b != nil {
		return guardCloudLogin(cl, c, x, b)
	}
	e := x.Plugin()
	if e == nil {
		return nil
	}
	line := pluginLine(e)
	if hits := policy.Check(line, nil); len(hits) > 0 && !cl.dangerOK() && !policyAsk(cl, "the kubeconfig of conn "+c.Name+" logs in with `"+line+"`, which matches "+hits[0].Reason, c.Name) {
		stop := out.Errf(out.ExitPolicy, "POLICY_BLOCKED", "a credential plugin only prints a token; check the kubeconfig of this conn (if this program is intended, --allow-dangerous lets it run)",
			"the kubeconfig of conn %s logs in with `%s`, which matches destructive rules: %s (a credential plugin only prints a token: check the kubeconfig of this conn)", c.Name, line, hits[0].Reason)
		if cl.flags.dryRun {
			cl.out.WouldBlock(stop)
			return errDryRunStopped
		}
		return stop
	}
	if !cl.isAgent() {
		return nil
	}
	if c.TrustedPlugin != "" && c.PluginProgram != "" {
		trusted := func() bool {
			t, ok := pluginTrust(cl, e, c.PluginProgram, x.Cluster)
			return ok && t == c.TrustedPlugin
		}
		if trusted() {
			want := *e // the kubeconfig's line, before the full path goes in
			e.Command, e.SearchPath = c.PluginProgram, cmp.Or(c.PluginSearchPath, systemPath)
			// once more right before it starts (connecting takes a while,
			// and the file may be the user's to replace)
			e.Check = func() error {
				if t, ok := pluginTrust(cl, &want, c.PluginProgram, x.Cluster); !ok || t != c.TrustedPlugin {
					return out.Errf(out.ExitPolicy, "NEEDS_PERSON", "run it again; if the program was updated, the user imports the kubeconfig again (`komando import kubeconfig FILE --overwrite`)",
						"the login program %s of conn %s changed while komando was connecting", c.PluginProgram, c.Name).NoFlag()
				}
				return nil
			}
			return nil
		}
	}
	prog := pluginProgram(e.Command)
	what := "the kubeconfig of conn " + c.Name + " runs `" + line + "` on this computer to log in" + programNote(e.Command, prog)
	stop := approvalErr(cl, "SAFETY_SETTING",
		what+"; a program on this computer is outside the agent guard's view, so an AI agent needs a person's yes each time, read-only commands too (to trust it for this conn for good, the user runs `komando import kubeconfig FILE --overwrite` themselves)")
	if err := agentLoginYes(cl, what, stop); err != nil {
		return err
	}
	if prog != "" {
		// the file the window named, with the system's PATH and none of
		// the agent's other variables (kube.ExecAuth.SearchPath)
		e.Command, e.SearchPath = prog, filepath.Dir(prog)+string(os.PathListSeparator)+systemPath
	}
	return nil
}

// systemPath is the PATH of a login program an AI agent's command runs
// when no import recorded one: the system's folders only.
// On Windows the folder comes from Windows itself (windowsDir), never
// from SystemRoot in the environment, which the caller sets.
var systemPath = systemPathFor()

func systemPathFor() string {
	if runtime.GOOS == "windows" {
		root := cmp.Or(windowsDir(), `C:\Windows`)
		return root + `\System32;` + root
	}
	return "/usr/bin:/bin:/usr/sbin:/sbin"
}

// guardCloudLogin: a kubeconfig that logs in with `aws eks get-token`,
// aws-iam-authenticator or gke-gcloud-auth-plugin gets a token komando
// makes from this computer's AWS or Google Cloud login, sent to the
// kubeconfig's server. An AI agent that brings such a kubeconfig in with
// a server of its own would be handed the person's cloud login, so an
// agent's command needs a person's yes unless a person's import trusted
// this plugin line and cluster block for the conn.
func guardCloudLogin(cl *call, c *store.Conn, x *kube.Context, b *kube.ExecAuth) error {
	if !cl.isAgent() {
		return nil
	}
	if t, _ := pluginTrust(cl, b, "", x.Cluster); c.TrustedPlugin != "" && c.TrustedPlugin == t {
		return nil
	}
	what := "the kubeconfig of conn " + c.Name + " sends a login made from this computer's " + cloudLoginName(b) + " login to " + clusterWay(x.Cluster)
	stop := approvalErr(cl, "SAFETY_SETTING",
		what+"; no person sent that login there, so an AI agent needs a person's yes each time, read-only commands too (to trust it for this conn for good, the user runs `komando import kubeconfig FILE --overwrite` themselves)")
	return agentLoginYes(cl, what, stop)
}

// agentLoginYes asks the person for an agent's kubeconfig login (what),
// or returns stop. A dry run never logs in: it reports the stop and ends
// before the step.
func agentLoginYes(cl *call, what string, stop *out.Error) error {
	if cl.flags.dryRun { // --yes is not asked for here
		if !cl.flags.yes {
			cl.out.WouldBlock(stop)
		}
		return errDryRunStopped
	}
	if cl.sess.SafetyApproved(what) || cl.flags.yes && cl.personAllowsFor("--yes", what) {
		cl.sess.ApproveSafety(what)
		return nil
	}
	return stop
}

// clusterWay says where a cluster block sends a login, for the approval
// window: the server and whatever moves or re-names the connection (a
// proxy, another TLS name, a CA of the kubeconfig's own).
func clusterWay(c kube.Cluster) string {
	way := c.Server
	if c.ProxyURL != "" {
		way += " through the proxy " + c.ProxyURL
	}
	if c.TLSServerName != "" {
		way += ", checked as " + c.TLSServerName
	}
	if c.CertificateAuthorityData != "" || c.CertificateAuthority != "" {
		way += " (trusting the CA in the kubeconfig)"
	}
	return way
}

// cloudLoginName names the cloud whose login a builtin plugin uses.
func cloudLoginName(b *kube.ExecAuth) string {
	if filepath.Base(b.Command) == "gke-gcloud-auth-plugin" {
		return "Google Cloud"
	}
	return "AWS"
}

// pluginProgram is the file a login program's command names on this
// computer, by this command's PATH, as a full path; "" when there is none.
func pluginProgram(command string) string {
	p, err := exec.LookPath(command)
	if err != nil {
		return ""
	}
	if p, err = filepath.Abs(p); err != nil {
		return ""
	}
	return p
}

// programNote names the file behind a command that is not a full path.
func programNote(command, prog string) string {
	if prog == "" || prog == command {
		return ""
	}
	return " (the program " + prog + ")"
}

// pluginTrust is what Conn.TrustedPlugin holds for a kubeconfig login: a
// hash of the plugin as the kubeconfig writes it (command, each argument,
// environment), of the program file it runs (program: its full path, and
// its contents unless only root can change it) and of the cluster block
// its token goes to (server, CA, TLS name, proxy), so any change (another
// program, args, environment, file or destination) asks again. program is
// "" for a plugin komando makes the token for. ok is false when the
// program file cannot be read: nothing is trusted then.
func pluginTrust(cl *call, e *kube.ExecAuth, program string, cluster kube.Cluster) (string, bool) {
	var env [][2]string
	for _, kv := range e.Env {
		env = append(env, [2]string{kv.Name, kv.Value})
	}
	// JSON keeps each word apart: ["--a b"] and ["--a", "b"] differ
	what, err := json.Marshal(struct {
		Command, Program string
		Args             []string
		Env              [][2]string
		Cluster          kube.Cluster
	}{e.Command, program, e.Args, env, cluster})
	if err != nil {
		return "", false
	}
	h := sha256.New()
	h.Write(what)
	if program != "" && !toolSafe(cl, program) {
		f, err := os.Open(program)
		if err != nil {
			return "", false
		}
		defer f.Close()
		if _, err := io.Copy(h, f); err != nil {
			return "", false
		}
	}
	return hex.EncodeToString(h.Sum(nil)), true
}

// pluginLine is a credential plugin's command line, as it would run, with
// the environment the kubeconfig gives it (PATH=... changes what runs).
// The words stay unquoted, so the destructive-command policy sees them as
// written, as with a --proxy-command.
func pluginLine(e *kube.ExecAuth) string {
	words := []string{}
	for _, kv := range e.Env {
		words = append(words, kv.Name+"="+kv.Value)
	}
	words = append(words, e.Command)
	words = append(words, e.Args...)
	return strings.Join(words, " ")
}

func kubeErr(err error) error {
	var e *kube.APIError
	if errors.As(err, &e) {
		code, exit, hint := "K8S_ERROR", out.ExitRemote, "read the cluster's words; `komando cluster events TARGET --warnings` shows what went wrong lately"
		switch {
		case e.Code == 401 || e.Code == 403:
			code, exit, hint = "K8S_FORBIDDEN", out.ExitConnect, "the conn's account may not do this: see who it is with `komando cluster run TARGET -- auth whoami` and what it may do with `komando cluster run TARGET -- auth can-i --list`"
		case e.Code == 404:
			code, exit, hint = "K8S_NOT_FOUND", out.ExitNotFound, "list what exists with `komando cluster list TARGET pods` (or deployments, services ...)"
		case e.Code == 409:
			code, exit, hint = "K8S_CONFLICT", out.ExitConflict, "the object changed meanwhile or exists already: look at it with `komando cluster get TARGET TYPE/NAME`, then run it again"
		case e.Code == 400 && strings.Contains(e.Message, "is not valid for pod"):
			code, exit, hint = "K8S_CONTAINER_NOT_FOUND", out.ExitNotFound, "see the pod's containers with `komando cluster describe TARGET pod/NAME`"
		case e.Code == 400 || e.Code == 422:
			code, exit, hint = "K8S_INVALID", out.ExitUsage, "the cluster refused it as written: check the label selector (-l) or the object's YAML"
		}
		msg := e.Message
		if outer := err.Error(); outer != e.Error() {
			msg = strings.TrimSuffix(outer, e.Error()) + e.Message // keep "deployment/web: " in front
		}
		return out.Errf(exit, code, hint, "%s", cmp.Or(msg, e.Reason))
	}
	var oe *out.Error
	if errors.As(err, &oe) {
		return oe
	}
	if errors.Is(err, kube.ErrUncheckedLogin) {
		return out.Usage("%v", err)
	}
	var pe *kube.PluginError
	if errors.As(err, &pe) {
		if pe.Missing {
			hint := "install " + pe.Command + " on this computer (the conn's kubeconfig logs in with it), or import a kubeconfig that logs in another way: `komando import kubeconfig FILE --overwrite`"
			if pe.InstallHint != "" {
				hint = "the kubeconfig says: " + pe.InstallHint
			}
			return out.Errf(out.ExitNotFound, "TOOL_MISSING", hint, "%s", pe.Error())
		}
		return out.Errf(out.ExitConnect, "LOGIN_FAILED", "run the program in a terminal to see why it cannot log in (it may need a person to sign in first), then run it again",
			"%s", cleanText(pe.Error()))
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return out.Errf(out.ExitTimeout, "TIMEOUT", "raise --timeout, or check the conn with `komando test TARGET` (and its --via path)",
			"the cluster did not answer within the time limit (--timeout)")
	}
	return out.Errf(out.ExitConnect, "CONN_UNREACHABLE", "check the conn with `komando test TARGET` (and its --via path)", "%s", dialMessage(err))
}

// dialMessage says "cannot reach HOST:PORT: connection refused" for a
// failed connection, as `komando test` does, instead of Go's
// `Get "https://...": dial tcp ...: connect: ...`; other errors keep their words.
func dialMessage(err error) string {
	var op *net.OpError
	if !errors.As(err, &op) || op.Op != "dial" || op.Addr == nil {
		return err.Error()
	}
	if sshx.Refused(op.Err) { // Windows has its own words for it
		return "cannot reach " + op.Addr.String() + ": connection refused"
	}
	why := op.Err
	var sys *os.SyscallError
	if errors.As(why, &sys) {
		why = sys.Err
	}
	return "cannot reach " + op.Addr.String() + ": " + why.Error()
}

// ownTimeLimit marks a command that keeps its own time (logs -f, --wait)
// when on, so kubeDeadline adds none.
func ownTimeLimit(ctx context.Context, on bool) context.Context {
	if !on {
		return ctx
	}
	return context.WithValue(ctx, ownLimitKey{}, true)
}

type ownLimitKey struct{}

// kubeDeadline gives one cluster's work the --timeout ("time limit per
// server"), unless the command keeps its own time.
func kubeDeadline(cl *call, ctx context.Context, st *store.State) (context.Context, context.CancelFunc) {
	if ctx.Value(ownLimitKey{}) != nil {
		return context.WithCancel(ctx)
	}
	return context.WithTimeout(ctx, cmdTimeout(cl, st))
}

// withKube runs fn on a k8s conn after the safety check for risk.
func withKube(cl *call, ctx context.Context, name string, t clusterTarget, risk driver.Risk, extra map[string]any,
	fn func(ctx context.Context, k *kube.Client) (any, error)) error {
	return withKubeWhy(cl, ctx, name, t, risk, name, extra, fn)
}

// withKubeWhy is withKube with the reason a person reads when the change
// needs their yes (withKube gives the command's name).
func withKubeWhy(cl *call, ctx context.Context, name string, t clusterTarget, risk driver.Risk, why string, extra map[string]any,
	fn func(ctx context.Context, k *kube.Client) (any, error)) error {
	st, err := loadState()
	if err != nil {
		return err
	}
	// under --dry-run every stop only lands in meta.would_be_blocked
	if err := guardConns(cl, st, []*store.Conn{t.conn}, driver.Verdict{Risk: risk, RuleIDs: []string{"cluster"}, Reasons: []string{why}}); err != nil {
		return err
	}
	ctx, cancel := kubeDeadline(cl, ctx, st)
	defer cancel()
	k, done, err := kubeClient(cl, ctx, st, t.conn)
	if errors.Is(err, errDryRunStopped) {
		cl.out.Print(name, map[string]any{"conn": t.conn.Name, "dry_run": true}, nil)
		return nil
	}
	if err != nil {
		return err
	}
	defer done()
	res, err := fn(ctx, k)
	rec := map[string]any{"conns": []string{t.conn.Name}, "risk": risk.String()}
	for key, v := range extra {
		rec[key] = v
	}
	if err != nil {
		err = kubeErr(err)
		rec["error"] = toErr(err).Code
	}
	if risk > driver.RiskRead {
		audit(cl, st, name, nil, "", err == nil, rec)
	}
	if err != nil && !nilData(res) {
		cl.out.Print(name, res, softErr(err)) // what happened before it failed (a rollout that timed out)
		return exitFor(err)
	}
	if err != nil {
		return err
	}
	cl.out.Print(name, res, nil)
	return nil
}

// confirmObject: deleting a cluster object, or stopping every replica of
// one, asks a person at a terminal to type that object's name ("Type the
// name api-7d9f-x2 to continue"), not the cluster's or "yes": the name
// says what goes, as gh repo delete does. A right answer also counts for
// the cluster check guardConns (or swarmDo) makes next, which asks for the
// same name (askTypes), so the person is asked once; a wrong one stops here and nothing
// changes. Agents and scripts are unchanged: they use --allow-dangerous,
// and a dry run never asks.
func confirmObject(cl *call, names []string, obj, reason string) error {
	if cl.flags.allowDangerous || cl.flags.dryRun || !cl.interactive() {
		return nil
	}
	askTypes(cl, []string{obj}, "objects")
	if !confirmDangerous(cl, names, reason) {
		return cl.policyStop(approvalErr(cl, "POLICY_BLOCKED",
			"the command matches destructive rules [cluster]: "+reason).Say(dangerSay([]string{reason}), dangerHint))
	}
	return nil
}

// age is a Kubernetes timestamp as a kubectl age (40s, 5m, 3h, 12d).
func age(ts string) string {
	t, err := time.Parse(time.RFC3339, ts)
	if err != nil {
		return ""
	}
	return humanAge(time.Since(t))
}

func clusterCmd() *cobra.Command {
	c := &cobra.Command{
		Use:     "cluster",
		Aliases: []string{"k8s", "kube", "swarm"},
		Short:   "Kubernetes and Docker Swarm: check, read logs, roll out, scale",
		Long: `TARGET is a Kubernetes cluster (bring yours in with ` + "`komando import kubeconfig`" + `)
or a Swarm manager server. The same verbs work on both. Reads need nothing; restart,
scale and apply change the cluster (protected targets need --yes; try
--dry-run); rm needs --allow-dangerous. Anything else: ` + "`cluster run`" + `
passes the native kubectl or docker command, read-only unless --write.

A cluster's usual namespace is its kubeconfig context's; change it with
` + "`komando conn edit NAME --option namespace=shop`" + `, or name one per command
with --namespace.`,
		Example: `  komando import kubeconfig                       # one cluster per kubeconfig context
  komando cluster status prod-k8s                     # version, nodes, what is not healthy
  komando cluster list prod-k8s pods --namespace shop
  komando cluster logs prod-k8s deploy/api --namespace shop -f
  komando cluster deploy prod-k8s deploy/api --image ghcr.io/acme/api:1.4.3 --namespace shop --wait`,
	}
	status := clusterStatusCmd()
	c.AddCommand(synonymWrapper(status, "info TARGET", "cluster.status", "cluster status TARGET", cobra.ExactArgs(1)))
	c.AddCommand(connAddCmdFor("cluster"), status, clusterLsCmd(), clusterGetCmd(), clusterDescribeCmd(), clusterEventsCmd(), clusterLogsCmd(), clusterDeployCmd(), clusterHistoryCmd(), clusterRollbackCmd(), clusterExecCmd(), clusterShellCmd(), clusterForwardCmd(), clusterRestartCmd(),
		clusterScaleCmd(), clusterApplyCmd(), clusterRmCmd(), clusterRunCmd(), clusterHelmCmd())
	return c
}

func str(v any) string {
	if s, ok := v.(string); ok {
		return s
	}
	return ""
}
