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
	"slices"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/sgnd/komando/internal/capability"
	"github.com/sgnd/komando/internal/cli/kit/term"
	"github.com/sgnd/komando/internal/inventory"
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
		if inventory.ConnFamily(c) == "cluster" {
			k8s = append(k8s, c)
		}
	}
	hosts, err := swarmHosts(cl, st, sel)
	if err != nil {
		return clusterTarget{}, err
	}
	switch {
	case len(k8s) == 1 && len(hosts) == 0:
		return clusterTarget{conn: k8s[0]}, nil
	case len(k8s) == 0 && len(hosts) == 1:
		return clusterTarget{host: hosts[0]}, nil
	case len(k8s)+len(hosts) == 0:
		return clusterTarget{}, noMatch(expr, "clusters (a k8s conn, or a Swarm manager server)", sel)
	}
	return clusterTarget{}, out.Usage("target %q picks %d clusters; this command works on one", expr, len(k8s)+len(hosts))
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
		if cl.dryRun() {
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
	if cl.dryRun() { // --yes is not asked for here
		if !cl.yes() {
			cl.out.WouldBlock(stop)
		}
		return errDryRunStopped
	}
	if cl.sess.SafetyApproved(what) || cl.yesOKFor(what) {
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
		code, exit, hint := "K8S_ERROR", out.ExitRemote, "read the cluster's words; `komando cluster kubernetes raw NAME -- get events` shows what went wrong lately"
		switch {
		case e.Code == 401 || e.Code == 403:
			code, exit, hint = "K8S_FORBIDDEN", out.ExitConnect, "the conn's account may not do this: see who it is with `komando cluster kubernetes raw NAME -- auth whoami` and what it may do with `komando cluster kubernetes raw NAME -- auth can-i --list`"
		case e.Code == 404:
			code, exit, hint = "K8S_NOT_FOUND", out.ExitNotFound, "list what exists with `komando cluster kubernetes raw NAME -- get pods` (or deployments, services ...)"
		case e.Code == 409:
			code, exit, hint = "K8S_CONFLICT", out.ExitConflict, "the object changed meanwhile or exists already: look at it with `komando cluster kubernetes raw NAME -- get TYPE/NAME -o yaml`, then run it again"
		case e.Code == 400 && strings.Contains(e.Message, "is not valid for pod"):
			code, exit, hint = "K8S_CONTAINER_NOT_FOUND", out.ExitNotFound, "see the pod's containers with `komando cluster kubernetes raw NAME -- describe pod NAME`"
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
			"%s", term.CleanText(pe.Error()))
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

type ownLimitKey struct{}

// kubeDeadline gives one cluster's work the --timeout ("time limit per
// server"), unless the command keeps its own time.
func kubeDeadline(cl *call, ctx context.Context, st *store.State) (context.Context, context.CancelFunc) {
	if ctx.Value(ownLimitKey{}) != nil {
		return context.WithCancel(ctx)
	}
	return context.WithTimeout(ctx, cmdTimeout(cl, st))
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
	return &cobra.Command{
		Use:   "cluster",
		Short: "Kubernetes and Docker Swarm: save clusters, run commands",
		Long: `Save a Kubernetes cluster with ` + "`komando cluster kubernetes add`" + `, or use a Swarm
manager server. ` + "`cluster kubernetes raw`" + ` passes the native kubectl command, read-only
unless --write; protected targets need --yes, and a command that deletes or
scales to zero also needs --allow-dangerous. The built-in snippets helm-list and
helm-release read the Helm releases.`,
		Example: `  komando cluster kubernetes add prod-k8s k8s://api.cluster.example:6443 --credential prod-kubeconfig
  komando cluster kubernetes raw prod-k8s get pods --namespace shop
  komando cluster kubernetes raw prod-k8s logs deploy/api --namespace shop
  komando cluster swarm raw swarm1 service ls`,
	}
}

// The cluster type of the table: komando cluster kubernetes VERB. The
// inventory verbs are the shared ones (inventoryHandlers); raw is today's
// `cluster kubernetes raw`, exec and shell are today's, and tunnel start is today's
// `cluster kubernetes tunnel start`: each runs its body on the cluster NAME, which must be
// a Kubernetes entry (WRONG_KIND). Swarm waits on its entry kind (E1).

var clusterBodies = map[[2]string]func() *cobra.Command{
	{"", "raw"}:         clusterRunCmd,
	{"", "exec"}:        clusterExecCmd,
	{"", "shell"}:       clusterShellCmd,
	{"tunnel", "start"}: clusterForwardCmd,
}

func init() {
	inventoryHandlers("cluster", "kubernetes")
	for k, body := range clusterBodies {
		words := strings.TrimSpace(k[0] + " " + k[1])
		handlers[capability.Key{Type: "cluster", Provider: "kubernetes", Area: k[0], Verb: k[1]}] = func(cl *call, ctx context.Context, in leafInput) error {
			if err := withEntry(cl, in.Args[0], "cluster", "kubernetes", words); err != nil {
				return err
			}
			return runBody(cl, ctx, body(), in, nil)
		}
	}
	handlers[capability.Key{Type: "cluster", Provider: "swarm", Verb: "raw"}] = func(cl *call, ctx context.Context, in leafInput) error {
		if err := withManager(cl, in.Args[0]); err != nil {
			return err
		}
		return runBody(cl, ctx, clusterRunCmd(), in, nil)
	}
	moveType("cluster")
	groupShorts["cluster swarm"] = "Docker Swarm: run docker commands on a manager server"
	groupShorts["cluster kubernetes"] = "Kubernetes clusters: save them, and run commands on them"
	groupShorts["cluster kubernetes tunnel"] = "Reach a port of a pod or service from this computer: start"
}

// withManager is nil when name is not a Kubernetes cluster: a Swarm is a
// manager server today (E1 gives it an entry), so `cluster swarm raw` takes
// the server's name. A Kubernetes entry is WRONG_KIND with its own path.
func withManager(cl *call, name string) error {
	st, err := loadState()
	if err != nil {
		return err
	}
	if c := st.Conns[name]; c != nil && inventory.ConnFamily(c) == "cluster" {
		return out.Errf(out.ExitUsage, "WRONG_KIND", "use `komando cluster kubernetes raw "+name+"`",
			"%s is a Kubernetes cluster, not a Swarm manager", name)
	}
	return nil
}

func str(v any) string {
	if s, ok := v.(string); ok {
		return s
	}
	return ""
}

// swarmHosts are the servers a selection picks, with the manager in place
// of each swarm service, each once. A swarm service works on its manager
// (Q8): every guard of that server applies, and personal data follows it.
func swarmHosts(cl *call, st *store.State, sel selection) ([]*store.Host, error) {
	hosts := slices.Clone(sel.Hosts)
	var managers []*store.Host
	for _, c := range sel.Conns {
		if c.Kind != "swarm" {
			continue
		}
		h := swarmManagerOf(st, c)
		if h == nil {
			return nil, out.Errf(out.ExitNotFound, "SWARM_MANAGER_NOT_FOUND", "add the manager server again (`komando host add NAME ADDRESS`), or remove the swarm service",
				"swarm service %s: its manager server %s is not in your list", c.Name, c.Manager)
		}
		if !slices.ContainsFunc(hosts, func(o *store.Host) bool { return o.Name == h.Name }) {
			hosts, managers = append(hosts, h), append(managers, h)
		}
	}
	notePersonal(cl, st, managers, nil)
	return hosts, nil
}

// swarmManagerOf is the server a swarm service names as its manager, by
// record ID (a rename keeps it), else by name; nil when it is gone.
func swarmManagerOf(st *store.State, c *store.Conn) *store.Host {
	for _, h := range st.Hosts {
		if c.ManagerID != "" && h.Rec.ID == c.ManagerID {
			return h
		}
	}
	if c.ManagerID == "" {
		return st.Hosts[c.Manager]
	}
	return nil
}

// swarmOf is the swarm service whose manager is h, or nil.
func swarmOf(st *store.State, h *store.Host) *store.Conn {
	for _, c := range st.Conns {
		if c.Kind == "swarm" && swarmManagerOf(st, c) == h {
			return c
		}
	}
	return nil
}
