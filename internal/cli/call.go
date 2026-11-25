package cli

import (
	"context"
	"fmt"
	"io"
	"os"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/term"

	"github.com/spf13/cobra"

	kitterm "github.com/sgnd/komando/internal/cli/kit/term"
	"github.com/sgnd/komando/internal/engine"
	"github.com/sgnd/komando/internal/out"
	"github.com/sgnd/komando/internal/store"
	"github.com/sgnd/komando/internal/transport"
	"github.com/sgnd/komando/internal/vault"
	"github.com/sgnd/komando/internal/version"
)

// call is one komando call: who makes it (engine.Caller), its approvals
// (engine.Session), its printer, its flags, its environment and where it
// reads and writes. Nothing a command does reads a package variable for
// any of these: two calls in one process (a person's and an agent's, in
// the Mac app) never see each other's output, answers or environment.
//
// The caller and the approvals are read again when a command starts
// (begin): one answer covers one command, and the next command asks
// again.
//
// The hooks of the lower packages (call_hooks.go) read every running call
// from other goroutines: its caller, its session and its printer's hidden
// values. A call is running from the first step of its command (execute),
// so these change only under a lock: the gate (caller and gate flags) is
// an atomic pointer to a value never changed after it is stored, the
// session is reset in place under its own lock (engine.Session.Reset),
// and the printer's vault values are set with out.Printer.SetSecrets.
type call struct {
	io       engine.Call
	args     []string // the command line: the program, then its words
	terminal bool     // a person can answer at the terminal (engine.Call.Terminal)
	stdin    io.Reader

	g     atomic.Pointer[gate] // the running command's gate: never nil (newCall), replaced whole (startGate)
	sess  *engine.Session      // made once (newCall), reset in place (begin)
	out   *out.Printer         // with the call's stdout (W) and stderr (Err)
	flags globalFlags

	// oldCopy: this command may look at an old copy of the store (doctor,
	// a dry run). The store asks every running call (oldCopyAllowed), so
	// it is atomic.
	oldCopy atomic.Bool

	// command numbers the command running in the call (enter), unique in
	// the process: a path through jump hosts is shared only within one
	// command (sshx.ChainOwner). 0: no command runs in it.
	command atomic.Uint64

	commits uint64   // store.Commits() when the command started
	ttyYes  []string // what a person said yes to at the terminal (the audit's confirm: tty)
	// askedInStep: a person was asked inside a store step (noteAsk), for
	// the audit record
	askedInStep bool

	typed     *typedSpec // what this command's typed question asks for (askTypes)
	typedProt []string   // protected targets a typed answer covered

	body *approvalBody // a file the command sends, which the window shows
	view *approvalView // the window being shown (personAllowsFlags)

	// manifests: the manifest files this command has read (readManifest),
	// and why one could not be read, so the bytes that were rated are the
	// bytes that are sent.
	manifests map[string]manifestRead

	// ask opens the approval window; nil is askOnScreen.
	ask func(text string) (allowed, shown bool)

	// logins are the passwords typed for login-ask servers in this
	// command (login_ask.go)
	logins typedLogins

	// what one command found out as it ran
	askedAbout      []string            // the targets of the last yes/no question, so a "no" can say where nothing was changed
	blockAudited    bool                // the command recorded its safety stop already (auditBlocked)
	interrupted     bool                // the person pressed Ctrl-C at a question (ttyin.go)
	personalCmd     bool                // this command, run by an AI agent, may hide personal data
	twinMask        map[string][]string // per conn: the mask_columns of other conns to the same resource
	fsSudoRetry     string              // the hint of a permission error in an fs command: the line with --sudo
	carriedSecrets  map[string]bool     // the secrets a sealed file being imported brings (import_sealed.go)
	importOverwrite bool                // the import's --overwrite, for a sealed file's secrets
	promptOn        bool                // promptable said yes for this command (prompter.go)
	promptMask      func(string) string // the answer being typed is drawn through it (askMasked)
	promptConfirmed string              // what the person said yes to before the command ran (Run it?)
	fillSeen        fillInfo            // what promptFill asked (prompter_next.go)
	nextNow         []string            // the Next: lines the command worked out as it ran
	liveMu          sync.Mutex          // one followed line at a time on stdout (printLogLine)

	// signals arms Ctrl-C for the command once its questions are answered
	// (execute); only the komando program sets it, an app passes its own
	// context to RunCall
	signals func(context.Context) (context.Context, context.CancelFunc)
}

// newCall is a call that runs with c, its command line program then args.
func newCall(c engine.Call, args []string) *call {
	cl := &call{
		io:       c,
		args:     append([]string{c.Program}, args...),
		terminal: c.Terminal,
		stdin:    c.Stdin,
		ask:      c.Ask,
	}
	if cl.stdin == nil {
		cl.stdin = eofReader{}
	}
	stdout, stderr := c.Stdout, c.Stderr
	if stdout == nil {
		stdout = io.Discard
	}
	if stderr == nil {
		stderr = io.Discard
	}
	cl.out = &out.Printer{Format: "json", W: stdout, Err: stderr, Version: version.Version, Start: time.Now(), Width: cl.width}
	cl.fsSudoRetry = "retry with --sudo"
	cl.sess = engine.NewSession()
	cl.begin(nil)
	return cl
}

// eofReader is the input of a call that has none.
type eofReader struct{}

func (eofReader) Read([]byte) (int, error) { return 0, io.EOF }

// begin starts a command in the call (the root's PersistentPreRunE): its
// gate is made new from its parsed command line (cmd; nil before one is
// parsed) and the caller read again from the call's environment, and no
// answer given so far counts. Other calls' hooks may read the gate and the
// session at the same time, so both change under a lock.
func (cl *call) begin(cmd *cobra.Command) {
	cl.startGate(cmd)
	cl.sess.Reset()
	cl.oldCopy.Store(false)
	cl.commits = store.Commits()
	cl.ttyYes, cl.typed, cl.typedProt, cl.body, cl.manifests = nil, nil, nil, nil, nil
	cl.askedInStep = false
	cl.logins.reset()
}

// storeWrite is how this command's changes to the store and the vault go:
// under --dry-run they are only previewed (store.Preview()).
func (g *gate) storeWrite() store.Write {
	if g.dryRun {
		return store.Preview()
	}
	return store.Save()
}
func (cl *call) storeWrite() store.Write { return cl.gate().storeWrite() }

// gate is what one command's safety decisions read: its four gate flags as
// its command line set them, and who is calling. Only newGate makes one,
// and a stored gate is never changed: a new command stores a new gate
// (startGate), and withDryRun and asAgent store a changed copy. A decision
// loads the gate once (cl.gate()) and reads everything it needs from that
// one value, so a gate stored meanwhile never mixes into it.
type gate struct {
	dryRun         bool // --dry-run: nothing changes, the plan is shown
	yes            bool // --yes as typed: what counts is yesOK
	allowDangerous bool // --allow-dangerous as typed: what counts is dangerOK
	reveal         bool // --reveal as typed: what counts is revealOK
	who            engine.Caller
	// hooks is how the gate's decisions reach the call they decide for:
	// its approvals, the window and the would_be_blocked record. Given to
	// newGate and never set after; nil (noGate, a command only checked)
	// refuses whatever needs a person.
	hooks gateIO
}

// gateIO is what the gate's decisions need from the call: the gate decides,
// and writes and asks only through these (TestGateOnlyDecides). *call is
// the only one.
type gateIO interface {
	// approvals is the command's approval session (engine.Session).
	approvals() *engine.Session
	// windowKeys names what a window for this check shows besides the
	// command line: what, the body the command sends, each reason.
	windowKeys(what string, why []string) []string
	// window makes the window's text for flags, what and why; unshown says
	// why the command cannot be shown in one (tooLong: its body is over the
	// limit), and done ends the window once it was asked.
	window(flags []string, what string, why []string) (text, unshown string, tooLong bool, done func())
	// askPerson opens the window with text and says whether the person
	// allowed it and whether it was shown at all.
	askPerson(text string) (allowed, shown bool)
	// wouldBlock records that the real run would stop at e (a dry run).
	wouldBlock(e *out.Error)
}

// gateFlagNames are the command line flags the gate reads, in the order of
// gate's fields.
var gateFlagNames = [4]string{"dry-run", "yes", "allow-dangerous", "reveal"}

// newGate is the gate of a command with the parsed command line cmd (nil:
// none parsed, all four flags off) run by who, deciding through hooks (nil
// for a command that is only checked, never run). cobra keeps the parsed
// values; nothing else in komando holds them.
func newGate(cmd *cobra.Command, who engine.Caller, hooks gateIO) *gate {
	var on [4]bool
	if cmd != nil {
		for i, name := range gateFlagNames {
			// Flag also finds the root's persistent flags on a command whose
			// flags were not parsed and merged yet
			f := cmd.Flag(name)
			if f == nil {
				panic("komando: the gate flag --" + name + " is not on " + cmd.CommandPath())
			}
			v, err := strconv.ParseBool(f.Value.String())
			if err != nil {
				panic("komando: the gate flag --" + name + " is no yes or no: " + err.Error())
			}
			on[i] = v
		}
	}
	return &gate{dryRun: on[0], yes: on[1], allowDangerous: on[2], reveal: on[3], who: who, hooks: hooks}
}

// startGate stores the gate of the command cmd starts: from its parsed
// command line, the caller read again from the call's environment. The
// root's PersistentPreRunE (begin) and status --short, which skips it,
// call it, so no command runs on the gate of the one before.
func (cl *call) startGate(cmd *cobra.Command) { cl.g.Store(newGate(cmd, cl.io.Caller(), cl)) }

// noGate is what a call that never stored a gate reads: an AI agent with
// every flag off and no hooks, the strictest caller, never a person: it
// refuses whatever needs one. newCall stores a gate, so only a call made
// without it gets this.
var noGate = gate{who: engine.Caller{Kind: engine.Agent, Agent: "a komando call without a gate"}}

// gate is the gate of the command running in the call.
func (cl *call) gate() *gate {
	if g := cl.g.Load(); g != nil {
		return g
	}
	return &noGate
}

// dryRun, yes, allowDangerous and reveal are the running command's gate
// flags as its command line set them (--dry-run, --yes, --allow-dangerous,
// --reveal). --yes, --allow-dangerous and --reveal are what was typed, not
// what is allowed: an AI agent's needs a person (yesOK, dangerOK,
// revealOK). A decision that reads more than one of them, or one and the
// caller, loads the gate once instead (cl.gate()).
func (cl *call) dryRun() bool         { return cl.gate().dryRun }
func (cl *call) yes() bool            { return cl.gate().yes }
func (cl *call) allowDangerous() bool { return cl.gate().allowDangerous }
func (cl *call) reveal() bool         { return cl.gate().reveal }

// caller is who makes the running command (engine.Caller).
func (cl *call) caller() engine.Caller { return cl.gate().who }

// withDryRun runs f with --dry-run on and puts the gate back after it:
// kctl's diff is an apply the server only pretends to do. It turns only
// --dry-run on, never off, and changes nothing else of the gate. The old
// gate comes back only if f stored none meanwhile (an asAgent inside f):
// that one stays, with --dry-run still on.
func (cl *call) withDryRun(f func() error) error {
	old := cl.gate()
	g := *old
	g.dryRun = true
	cl.g.Store(&g)
	defer cl.g.CompareAndSwap(&g, old)
	return f()
}

// asAgent makes the running command's caller the ssh-gate key label: an AI
// agent, whoever called before, with the same Actor (the audit log and
// the ownership of runs and sessions follow it). It only makes a caller an
// agent, never a person, and changes no gate flag. label is only a name:
// the approval window, the audit log and messages show it, no decision
// reads it.
func (cl *call) asAgent(label string) {
	old := cl.gate()
	g := *old
	g.who = engine.Caller{Kind: engine.Agent, Agent: "ssh-gate key " + label, Actor: old.who.Actor}
	cl.g.Store(&g)
}

// width is the column the call's stderr lines wrap at: none for an AI
// agent, which reads each message on one line, and none when the call's
// stderr is no terminal (a pipe, an app's writer).
func (cl *call) width() int {
	if cl.isAgent() {
		return 0
	}
	return out.WidthOf(cl.out.Err)
}

// textWidth is the column a text result wraps at: none for an AI agent or
// when the call's stdout is no terminal (a pipe, an app's writer).
func textWidth(cl *call) int {
	if cl.isAgent() {
		return 0
	}
	return out.WidthOf(cl.out.W)
}

// isTerminal reports whether f is a terminal of this process: a call's
// stdout or stderr is one only when the caller handed in the terminal's
// file (processCall), never an app's writer.
func isTerminal(f any) bool {
	o, ok := f.(*os.File)
	return ok && term.IsTerminal(int(o.Fd()))
}

// getenv and lookupEnv read the call's environment, never the process's:
// an app's calls each have their own.
func (cl *call) getenv(key string) string            { return cl.io.Getenv(key) }
func (cl *call) lookupEnv(key string) (string, bool) { return cl.io.Lookup(key) }

// environ is the call's environment for a program it starts, without the
// secret stores' unlock values (vault.StripUnlock): no child inherits
// them. A komando process that needs the vault gets vault.SelfEnv or the
// values on its stdin (vault.PassOnStdin). It is never nil: an exec.Cmd
// whose Env is nil inherits the process's whole environment, so a call
// with no environment starts programs with none.
func (cl *call) environ() []string { return vault.StripUnlock(cl.io.Env()) }

// treeCall is a call for a command tree that is only read (its
// commands, flags and help) and never run: it reads no environment and
// writes nowhere.
func treeCall() *call { return newCall(engine.Call{Program: "komando"}, nil) }

type callKey struct{}

// withCall is ctx carrying cl, for the commands of cl's command tree.
func withCall(ctx context.Context, cl *call) context.Context {
	return context.WithValue(ctx, callKey{}, cl)
}

// callFrom is the call ctx carries, or nil.
func callFrom(ctx context.Context) *call {
	if ctx == nil {
		return nil
	}
	cl, _ := ctx.Value(callKey{}).(*call)
	return cl
}

// inCall is a command's RunE that runs in the command's call (callOf).
func inCall(run func(cl *call, cmd *cobra.Command, args []string) error) func(*cobra.Command, []string) error {
	return func(cmd *cobra.Command, args []string) error { return run(callOf(cmd), cmd, args) }
}

// callOf is the call cmd runs in: the one its context, or a parent's,
// carries. Every command tree is built for one call (newRoot), so there
// is always one; none is a bug.
func callOf(cmd *cobra.Command) *call {
	for c := cmd; c != nil; c = c.Parent() {
		if cl := callFrom(c.Context()); cl != nil {
			return cl
		}
	}
	panic("komando: command " + cmd.CommandPath() + " runs outside a call")
}

// runExecute runs one command in a call. root.go sets it to execute, the
// function that builds the command tree, so that this file does not name
// the tree.
var runExecute func(cl *call, ctx context.Context, args []string) int

// runCall runs one command in cl, or says on stderr that there is no
// command tree to run it in: a program that never set runExecute stops
// with exit 1 and runs nothing.
func runCall(cl *call, ctx context.Context, args []string) int {
	if runExecute == nil {
		fmt.Fprintln(cl.out.Err, "komando: the command tree is not loaded")
		return 1
	}
	return runExecute(cl, ctx, args)
}

// Execute runs the komando program: one call, made from this process
// (its arguments, environment and terminal), and its exit code.
func Execute() int {
	// no program komando starts inherits the secret stores' unlock values
	vault.TakeUnlockEnv()
	noCoreDumps() // a crash writes no memory, secrets and all, to disk
	noPeek()      // Linux: no process of the same user reads komando's memory
	// a Windows console shows colour and line clearing only when asked
	ok, restore := kitterm.ConsoleVT(int(os.Stderr.Fd()))
	defer restore()
	kitterm.VTOK = ok
	// the store is closed when the program ends
	defer store.Close()
	cl := newCall(processCall(), os.Args[1:])
	if cl.isAgent() {
		transport.DistrustEnv() // its HTTPS_PROXY is the agent's: no proxy from it
	}
	cl.signals = signalContext
	return runCall(cl, context.Background(), os.Args[1:])
}

// ancestorAgent names the AI agent among the processes above this program.
// Tests replace it.
var ancestorAgent = engine.ParentAgent

// processCall is the call the komando program makes: its own
// environment, input and output, and its terminal.
func processCall() engine.Call {
	return engine.Call{
		Program:   os.Args[0],
		LookupEnv: os.LookupEnv,
		Environ:   os.Environ,
		Stdin:     os.Stdin,
		Stdout:    os.Stdout,
		Stderr:    os.Stderr,
		Terminal:  term.IsTerminal(int(os.Stdin.Fd())) && term.IsTerminal(int(os.Stderr.Fd())),
		Ancestors: func() string { return ancestorAgent() },
	}
}

// RunCall runs one komando command (args are the words after "komando")
// as the call c: its envelope or text goes to c.Stdout, its notes to
// c.Stderr, and its approvals and environment are its own. It returns the
// exit code. Calls may run at the same time in one process.
func RunCall(ctx context.Context, c engine.Call, args []string) int {
	return runCall(newCall(c, args), ctx, args)
}
