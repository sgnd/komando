package cli

import (
	"context"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/sgnd/komando/internal/cli/kit/phonekey"
	"github.com/sgnd/komando/internal/driver"
	"github.com/sgnd/komando/internal/inventory"
	"github.com/sgnd/komando/internal/out"
	"github.com/sgnd/komando/internal/sshx"
	"github.com/sgnd/komando/internal/store"
)

// revokeTarget reads what `key revoke` should remove: a key in the
// keychain, a .pub file, or a public key line ("ssh-ed25519 AAAA... who").
// It returns the key's base64 part, which is what authorized_keys lines
// are matched on, and a label.
func revokeTarget(st *store.State, arg string) (blob, label string, k *store.Key, err error) {
	line := arg
	if key, ok := st.Keys[arg]; ok {
		if key.PublicKey == "" {
			return "", "", nil, out.Errf(out.ExitUsage, "NO_PUBLIC_KEY", "place "+key.Path+".pub next to the key, then `komando key rm "+key.Name+"` and add it again", "komando does not have the public key of %s", key.Name)
		}
		line, label, k = key.PublicKey, "key "+key.Name, key
	} else if b, rerr := os.ReadFile(inventory.ExpandHome(arg)); rerr == nil {
		line, label = strings.TrimSpace(string(b)), arg
	}
	f := strings.Fields(line)
	if len(f) < 2 || !strings.HasPrefix(f[0], "ssh-") && !strings.HasPrefix(f[0], "ecdsa-") && !strings.HasPrefix(f[0], "sk-") {
		return "", "", nil, out.Usage("give a key name from `komando key list`, a .pub file, or a public key line (ssh-ed25519 AAAA...)")
	}
	if label == "" {
		label = f[0] + " ..." + f[1][max(0, len(f[1])-12):]
	}
	return f[1], label, k, nil
}

func keyRevokeCmd() *cobra.Command {
	var user string
	var allUsers bool
	c := &cobra.Command{
		Use:   "revoke NAME TARGET",
		Short: "Take a public key off servers' authorized_keys",
		Long: `KEY is a key in komando's key list, a .pub file, or a public key line. Every line
with that key is removed from ~/.ssh/authorized_keys of the login user, or
of --user NAME (with sudo), or of every user on the server with --all-users
(with sudo: someone who left may have put the key in another account too;
the dry run names each user whose file holds it). The file keeps its owner
and mode, and is read and written as its user. Revoking the
key komando itself logs in with needs --allow-dangerous: you would lock
yourself out. --dry-run counts the lines it would remove.`,
		Example: `  komando key revoke ~/keys/alice.pub @prod --dry-run
  komando key revoke "ssh-ed25519 AAAAC3Nz...xyz alice@laptop" @prod
  komando key revoke old-deploy @web --user deploy
  komando key revoke ~/keys/alice.pub @prod --all-users --dry-run`,
		Args: cobra.ExactArgs(2),
		RunE: inCall(func(cl *call, cmd *cobra.Command, args []string) error {
			st, err := loadState()
			if err != nil {
				return err
			}
			blob, label, k, err := revokeTarget(st, args[0])
			if err != nil {
				return err
			}
			hosts, err := resolveTargets(cl, st, args[1])
			if err != nil {
				return err
			}
			if allUsers && user != "" {
				return out.Usage("give --user NAME or --all-users, not both")
			}
			if k != nil && user == "" {
				if err := guardRevokeSelf(cl, st, hosts, k.Name); err != nil {
					return err
				}
			}
			if err := Guard(cl, st, hosts, "", true); err != nil {
				return err
			}
			if user != "" && !inventory.NameRe.MatchString(user) {
				return out.Usage("%q cannot be a user name: use letters, digits and . _ -", user)
			}
			script := revokeScript(user, blob, cl.dryRun())
			if allUsers {
				script = revokeAllScript(blob, cl.dryRun())
			}
			res := fanout(cl, cmd.Context(), st, hosts, func(ctx context.Context, c *sshx.Client) (any, error) {
				r, err := sshx.Run(ctx, c, sshx.RunRequest{Command: script, Sudo: user != "" || allUsers, Timeout: 30 * time.Second, MaxOutput: 64 << 10})
				if err != nil {
					return nil, err
				}
				if e := sudoProblem(c.Host.Name, r); e != nil && (user != "" || allUsers) {
					return nil, e
				}
				if r.ExitCode != 0 {
					return nil, out.Errf(out.ExitRemote, "REVOKE_FAILED", "run it again; to look at the file: `komando fs cat SERVER ~/.ssh/authorized_keys`", "%s", strings.TrimSpace(r.Stderr))
				}
				if allUsers {
					return parseRevokeAll(r.Stdout), nil
				}
				n, _ := strconv.Atoi(strings.TrimSpace(r.Stdout))
				return n, nil
			})
			data, worst := revokeResults(cl, label, res)
			if !cl.dryRun() {
				audit(cl, st, "key.revoke", hostNames(hosts), "", data.Summary.Failed == 0, map[string]any{"key": label, "user": user, "all_users": allUsers})
			}
			return finish(cl, "key.revoke", data, data.Summary, worst, soleError(res))
		}),
	}
	c.Flags().StringVar(&user, "user", "", "edit this user's authorized_keys instead of the login user's (uses sudo)")
	c.Flags().BoolVar(&allUsers, "all-users", false, "edit every user's authorized_keys on the server (uses sudo)")
	return c
}

// revokedUsers is what --all-users removed (or would remove) per user:
// only the users whose file held the key, and those whose file could not
// be changed (removed -1).
type revokedUsers []revokedUser

type revokedUser struct {
	User    string `json:"user"`
	Removed int    `json:"removed"` // -1: the file could not be read or changed
}

func (u revokedUsers) total() int {
	n := 0
	for _, r := range u {
		n += max(r.Removed, 0)
	}
	return n
}

// parseRevokeAll reads revokeAllScript's lines "USER COUNT" (COUNT is
// "err" when the user's file could not be changed).
func parseRevokeAll(s string) revokedUsers {
	res := revokedUsers{}
	for _, l := range strings.Split(strings.TrimSpace(s), "\n") {
		f := strings.Fields(l)
		if len(f) != 2 {
			continue
		}
		n, err := strconv.Atoi(f[1])
		switch {
		case err != nil:
			n = -1
		case n == 0:
			continue
		}
		res = append(res, revokedUser{User: f[0], Removed: n})
	}
	return res
}

// revokeAllScript is revokeScript for every user that has an
// authorized_keys file (getent passwd), run as root: each file is read
// and written as its own user, as with --user. It prints "USER COUNT".
func revokeAllScript(blob string, dry bool) string {
	edit := revokeEdit(dry)
	loop := `getent passwd | while IFS=: read -r u _ _ _ _ h _; do ` +
		`case "$h" in /*) ;; *) continue ;; esac; [ "$h" != / ] && [ -f "$h/.ssh/authorized_keys" ] || continue; ` +
		`if [ "$(id -un)" = "$u" ]; then n=$(sh -c "$1" sh "$h" "$2" 2>/dev/null); else n=$(su -s /bin/sh "$u" -c "$1" sh "$h" "$2" 2>/dev/null </dev/null); fi; ` +
		`case "$n" in ''|*[!0-9]*) n=err ;; esac; echo "$u $n"; done`
	// the edit and the key go as $1 and $2, never inside the loop's text
	return "sh -c " + sshx.Q(loop) + " sh " + sshx.Q(edit) + " " + sshx.Q(blob)
}

// revokeData is key revoke's result: one row per server.
type revokeData struct {
	Key     string           `json:"key"`
	Results []map[string]any `json:"results"`
	Summary fleetSummary     `json:"summary"`
}

// revokeResults turns each server's outcome into its row, and the worst
// exit code.
func revokeResults(cl *call, label string, res []outcome) (revokeData, int) {
	data := revokeData{Key: label}
	worst := 0
	for _, o := range res {
		r := map[string]any{"host": o.Host.Name}
		if o.Err != nil {
			e := toErr(o.Err)
			r["ok"], r["error"] = false, e
			worst = worse(worst, e.Exit)
			data.Summary.Failed++
			data.Summary.FailedHosts = append(data.Summary.FailedHosts, o.Host.Name)
		} else {
			field := "removed"
			if cl.dryRun() {
				field = "would_remove"
			}
			r["ok"], r[field] = true, o.Value
			if all, ok := o.Value.(revokedUsers); ok {
				r[field], r["users"] = all.total(), all
			}
			data.Summary.OK++
		}
		data.Results = append(data.Results, r)
	}
	data.Summary.Total = len(res)
	return data, worst
}

// guardRevokeSelf stops key revoke of the key komando logs in to hosts
// with: that locks komando out. A person types the key's name.
func guardRevokeSelf(cl *call, st *store.State, hosts []*store.Host, key string) error {
	var self []string
	for _, h := range hosts {
		if h.Key == key {
			self = append(self, h.Name)
		}
	}
	if len(self) == 0 || cl.dangerOK() {
		return nil
	}
	askTypes(cl, []string{key}, "keys")
	return GuardConns(cl, st, nil, driver.Verdict{Risk: driver.RiskDestructive, RuleIDs: []string{"key-revoke-self"},
		Reasons: []string{"komando logs in to " + strings.Join(self, ", ") + " with this key; switch them first (`komando host edit TARGET --key OTHER`)"}})
}

// revokeEdit removes the key ($2) from $1/.ssh/authorized_keys and prints
// how many lines held it (dry: only counts).
func revokeEdit(dry bool) string {
	edit := `f="$1/.ssh/authorized_keys"; [ -f "$f" ] || { echo 0; exit 0; }; n=$(grep -cF -- "$2" "$f" || true); `
	if !dry {
		edit += `if [ "$n" -gt 0 ]; then t=$(umask 077; mktemp "$f.XXXXXX") && { grep -vF -- "$2" "$f" > "$t" || true; } && cat "$t" > "$f"; rm -f "$t"; fi; `
	}
	return edit + `echo "$n"`
}

// revokeScript removes the key blob from authorized_keys and prints how
// many lines held it (dry: only counts). With user it runs as root, but
// the file belongs to that user, often the one leaving: it is read and
// written as the user (su), never by root through a link they planted.
func revokeScript(user, blob string, dry bool) string {
	edit := revokeEdit(dry)
	if user == "" {
		return "sh -c " + sshx.Q(edit) + ` sh "$HOME" ` + sshx.Q(blob)
	}
	q := sshx.Q(user)
	return asUserFunc(q) + "h=$(getent passwd " + q + " | cut -d: -f6); ku " + sshx.Q(edit) + ` sh "$h" ` + sshx.Q(blob)
}

// A device's key (C372, U108; option C of the U107 design): `key deploy
// TARGET --user NAME --public-key-file FILE [--from-address ADDRESS]`,
// the --public-key-file form of credential key install, writes a phone's
// public key for a named user on one server, and always behind komando's
// gate in server mode there (restrict, command= to the server's own
// komando ssh-gate --here). No flag writes it without the gate. Only a
// person at a terminal runs it; the checks are in kit/phonekey.
type deviceKeyOpts struct{ file, user, from string }

func (o *deviceKeyOpts) flags(c *cobra.Command) {
	c.Flags().StringVar(&o.file, "public-key-file", "", "a device's public key file (a phone's): install it for --user behind komando's gate on the server; a person at a terminal only")
	c.Flags().StringVar(&o.user, "user", "", "with --public-key-file: the user the device logs in as (never root)")
	c.Flags().StringVar(&o.from, "from-address", "", "with --public-key-file: the addresses the device logs in from, as the server sees them (from= in authorized_keys)")
}

// args: key deploy takes NAME TARGET, its --public-key-file form TARGET.
func (o *deviceKeyOpts) args(c *cobra.Command, args []string) error {
	if o.file != "" {
		return cobra.ExactArgs(1)(c, args)
	}
	if o.user != "" || o.from != "" {
		return out.Usage("--user and --from-address go with --public-key-file")
	}
	return cobra.ExactArgs(2)(c, args)
}

// deviceKey is what `key deploy --public-key-file` prints.
type deviceKey struct {
	Host        string   `json:"host"`
	User        string   `json:"user"`
	Name        string   `json:"name"`        // the key's name: its comment, the gate's --name
	Fingerprint string   `json:"fingerprint"` // SHA256:...
	FromAddress string   `json:"from_address,omitempty"`
	Komando     string   `json:"komando"` // the server's komando the line runs
	Line        string   `json:"line"`
	Status      string   `json:"status"`     // added, present; would_add in a dry run
	SystemLog   bool     `json:"system_log"` // the server has a system log the gate copies its records to
	Notes       []string `json:"notes,omitempty"`
}

func (d deviceKey) Text() string {
	s := d.Status + ": " + d.Name + " (" + d.Fingerprint + ") for " + d.User + " on " + d.Host + "\n" + d.Line + "\n"
	for _, n := range d.Notes {
		s += "note: " + n + "\n"
	}
	return s
}

// deviceKeyInstall runs the --public-key-file form on target.
func deviceKeyInstall(cl *call, cmd *cobra.Command, o deviceKeyOpts, target string) error {
	if !phonekey.UserName.MatchString(o.user) {
		return out.Usage("--user takes the user the device logs in as: letters, digits, dot, dash and underscore, starting with a letter")
	}
	if on, _ := cmd.Flags().GetBool("set-default"); on {
		return out.Usage("--set-default does not go with --public-key-file: komando never logs in with a device's key")
	}
	var notes []string
	if o.from != "" {
		host, err := phonekey.CheckAddress(o.from)
		if err != nil {
			return out.Errf(out.ExitUsage, "USAGE", "give addresses or networks, comma-separated, for example 10.0.0.0/8,192.0.2.7", "%v", err)
		}
		if host {
			notes = append(notes, "from= names a host pattern: sshd matches it only with UseDNS yes, which is not its default; give the addresses the server sees")
		}
	}
	k, err := readDeviceKey(o.file)
	if err != nil {
		return err
	}
	if cl.isAgent() || !cl.interactive() {
		if err := cl.policyStop(out.Errf(out.ExitPolicy, "NEEDS_PERSON", "a person runs `komando key deploy SERVER --user NAME --public-key-file FILE` in their own terminal",
			"installing a device's key lets that device log in to the server, so only a person at a terminal does it").NoFlag()); err != nil {
			return err
		}
	}
	st, err := loadState()
	if err != nil {
		return err
	}
	hosts, err := resolveTargets(cl, st, target)
	if err != nil {
		return err
	}
	if len(hosts) != 1 || hosts[0].Windows() {
		return out.Usage("--public-key-file installs a device's key on one Linux or Unix server at a time")
	}
	if err := Guard(cl, st, hosts, "", true); err != nil {
		return err
	}
	res := deviceKey{Host: hosts[0].Name, User: o.user, Name: k.Name, Fingerprint: k.Fingerprint, FromAddress: o.from, Notes: notes}
	f, err := deviceKeyRun(cl, cmd.Context(), st, hosts, sshCmd(phonekey.ProbeScript, o.user))
	if err != nil {
		return err
	}
	facts := phonekey.ParseFacts(f)
	if err := deviceKeyRefusal(facts, o.user, res.Host); err != nil {
		return err
	}
	res.Komando, res.SystemLog = facts.Komando, facts.Syslog
	res.Line = phonekey.Line(facts.Komando, k, o.from)
	if !facts.Syslog {
		res.Notes = append(res.Notes, "the server has no system log: the gate's records stay only in komando's audit log in "+o.user+"'s home, which "+o.user+" owns")
	}
	if cl.dryRun() {
		res.Status = "would_add"
		cl.out.Print("key.deploy", res, nil)
		return nil
	}
	if !confirmYes(cl, "This lets the key "+k.Name+" ("+k.Fingerprint+") log in to "+res.Host+" as "+o.user+
		" and run komando commands there through its gate. Install it?") {
		return out.Errf(out.ExitPolicy, "NEEDS_PERSON", "run it again and answer y", "nothing was written: the person said no")
	}
	write := sshCmd(phonekey.WriteScript, facts.Home, res.Line, k.Type+" "+k.Data)
	if facts.Login != o.user {
		write = "sudo -n -H -u " + sshx.Q(o.user) + " " + write // as the user, never as root
	}
	res.Status, err = deviceKeyRun(cl, cmd.Context(), st, hosts, write)
	switch {
	case err != nil, res.Status == "added", res.Status == "present":
	case res.Status == "other":
		err = out.Errf(out.ExitConflict, "KEY_LINE_CONFLICT", "remove the older line for this key from "+o.user+"'s ~/.ssh/authorized_keys on the server, then run `komando key deploy` again",
			"%s: the key is there already in another line, which sshd would use first; nothing was written", res.Host)
	default:
		err = out.Errf(out.ExitRemote, "DEPLOY_FAILED", "make ~/.ssh and its key files plain files and folders on the server, then run `komando key deploy` again",
			"%s: %s; komando writes through no link, so nothing was written", res.Host, res.Status)
	}
	audit(cl, st, "key.deploy", []string{res.Host}, "", err == nil, map[string]any{"key": k.Name, "fingerprint": k.Fingerprint, "user": o.user,
		"from_address": o.from, "device_key": true})
	if err != nil {
		return err
	}
	cl.out.Print("key.deploy", res, nil)
	return nil
}

// readDeviceKey reads and checks a device's public key file.
func readDeviceKey(file string) (phonekey.Key, error) {
	path := inventory.ExpandHome(file)
	fi, err := os.Stat(path)
	if err != nil || !fi.Mode().IsRegular() || fi.Size() > 64<<10 {
		return phonekey.Key{}, out.Errf(out.ExitUsage, "KEY_INVALID", "give the device's .pub file", "%s is not a public key file", file)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return phonekey.Key{}, err
	}
	k, err := phonekey.Parse(b)
	if err != nil {
		return phonekey.Key{}, out.Errf(out.ExitUsage, "KEY_INVALID", "give the device's .pub file: one line, TYPE KEY komando-phone-DEVICE", "%s: %v", file, err)
	}
	return k, nil
}

// sshCmd is sh -c SCRIPT with args as its positional parameters, quoted
// for the server's shell: no value is ever part of the script's text.
func sshCmd(script string, args ...string) string {
	s := "sh -c " + sshx.Q(script) + " komando-key"
	for _, a := range args {
		s += " " + sshx.Q(a)
	}
	return s
}

// deviceKeyRun runs command on the one host and gives its output.
func deviceKeyRun(cl *call, ctx context.Context, st *store.State, hosts []*store.Host, command string) (string, error) {
	res := fanout(cl, ctx, st, hosts, func(ctx context.Context, c *sshx.Client) (any, error) {
		o, code, err := sshx.Output(ctx, c, command, 30*time.Second)
		if err != nil {
			return nil, err
		}
		if code != 0 {
			return nil, out.Errf(out.ExitRemote, "DEPLOY_FAILED", "check that the login user may run sudo -n -u USER there, or log in as that user", "%s", strings.TrimSpace(o))
		}
		return strings.TrimSpace(o), nil
	})
	if res[0].Err != nil {
		return "", res[0].Err
	}
	return res[0].Value.(string), nil
}

// deviceKeyRefusal is the stop for what the probe found on host, or nil:
// no such user or uid 0, no komando, a gate the user could replace (rule
// b), or a komando without the server mode.
func deviceKeyRefusal(f phonekey.Facts, user, host string) error {
	code, why := f.Refusal(user)
	hint := "fix it on the server as the message says, then run `komando key deploy` again"
	switch code {
	case "":
		return nil
	case "KEY_USER_INVALID":
		return out.Errf(out.ExitUsage, "KEY_USER_INVALID", "name a user that is not root: fix it on the server as the message says, then run `komando key deploy` again", "%s: %s", host, why)
	case "KOMANDO_MISSING":
		return out.Errf(out.ExitNotFound, "KOMANDO_MISSING", hint, "%s: %s", host, why)
	case "GATE_UNSUPPORTED":
		return out.Errf(out.ExitUsage, "GATE_UNSUPPORTED", hint, "%s: %s", host, why)
	}
	return out.Errf(out.ExitUsage, "GATE_BINARY_INVALID", hint, "%s: %s", host, why)
}
