package cli

import (
	"context"
	"io"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/term"

	"github.com/spf13/cobra"

	"github.com/sgnd/komando/internal/engine"
	"github.com/sgnd/komando/internal/out"
	"github.com/sgnd/komando/internal/store"
	"github.com/sgnd/komando/internal/vault"
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
// so these change only under a lock: the caller is an atomic value, the
// session is reset in place under its own lock (engine.Session.Reset),
// and the printer's vault values are set with out.Printer.SetSecrets.
type call struct {
	io       engine.Call
	args     []string // the command line: the program, then its words
	terminal bool     // a person can answer at the terminal (engine.Call.Terminal)
	stdin    io.Reader

	who   atomic.Pointer[engine.Caller] // caller and setCaller
	sess  *engine.Session               // made once (newCall), reset in place (begin)
	out   *out.Printer                  // with the call's stdout (W) and stderr (Err)
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

	typed     *typedSpec // what this command's typed question asks for (askTypes)
	typedProt []string   // protected targets a typed answer covered

	body *approvalBody // a file the command sends, which the window shows

	// ask opens the approval window; nil is askOnScreen.
	ask func(text string) (allowed, shown bool)

	// what one command found out as it ran
	askedAbout      []string            // the targets of the last yes/no question, so a "no" can say where nothing was changed
	blockAudited    bool                // the command recorded its safety stop already (auditBlocked)
	interrupted     bool                // the person pressed Ctrl-C at a question (ttyin.go)
	auditSyslog     string              // the audit_syslog setting of this command's state
	personalCmd     bool                // this command, run by an AI agent, may hide personal data
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
	cl.out = &out.Printer{Format: "json", W: stdout, Err: stderr, Version: Version, Start: time.Now(), Width: cl.width}
	cl.fsSudoRetry = "retry with --sudo"
	cl.sess = engine.NewSession()
	cl.begin()
	return cl
}

// eofReader is the input of a call that has none.
type eofReader struct{}

func (eofReader) Read([]byte) (int, error) { return 0, io.EOF }

// begin starts a command in the call (the root's PersistentPreRunE): the
// caller is read again from the call's environment, and no answer given
// so far counts. Other calls' hooks may read the caller and the session
// at the same time, so both change under a lock.
func (cl *call) begin() {
	cl.setCaller(cl.io.Caller())
	cl.sess.Reset()
	cl.oldCopy.Store(false)
	cl.commits = store.Commits()
	cl.ttyYes, cl.typed, cl.typedProt, cl.body = nil, nil, nil, nil
}

// storeWrite is how this command's changes to the store and the vault go:
// under --dry-run they are only previewed (store.Preview()).
func (cl *call) storeWrite() store.Write {
	if cl.flags.dryRun {
		return store.Preview()
	}
	return store.Save()
}

// caller is who makes the call (engine.Caller).
func (cl *call) caller() engine.Caller { return *cl.who.Load() }

// setCaller makes c the call's caller.
func (cl *call) setCaller(c engine.Caller) { cl.who.Store(&c) }

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

// Execute runs the komando program: one call, made from this process
// (its arguments, environment and terminal), and its exit code.
func Execute() int {
	// no program komando starts inherits the secret stores' unlock values
	vault.TakeUnlockEnv()
	noCoreDumps() // a crash writes no memory, secrets and all, to disk
	noPeek()      // Linux: no process of the same user reads komando's memory
	// a Windows console shows colour and line clearing only when asked
	ok, restore := consoleVT(int(os.Stderr.Fd()))
	defer restore()
	vtOK = ok
	// the store is closed when the program ends
	defer store.Close()
	cl := newCall(processCall(), os.Args[1:])
	cl.signals = signalContext
	return cl.execute(context.Background(), os.Args[1:])
}

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
	}
}

// RunCall runs one komando command (args are the words after "komando")
// as the call c: its envelope or text goes to c.Stdout, its notes to
// c.Stderr, and its approvals and environment are its own. It returns the
// exit code. Calls may run at the same time in one process.
func RunCall(ctx context.Context, c engine.Call, args []string) int {
	return newCall(c, args).execute(ctx, args)
}
