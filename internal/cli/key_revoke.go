package cli

import (
	"context"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/sgnd/komando/internal/driver"
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
	} else if b, rerr := os.ReadFile(expandHome(arg)); rerr == nil {
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
		RunE: func(cmd *cobra.Command, args []string) error {
			st, err := loadState()
			if err != nil {
				return err
			}
			blob, label, k, err := revokeTarget(st, args[0])
			if err != nil {
				return err
			}
			hosts, err := resolveTargets(st, args[1])
			if err != nil {
				return err
			}
			if allUsers && user != "" {
				return out.Usage("give --user NAME or --all-users, not both")
			}
			if k != nil && user == "" {
				if err := guardRevokeSelf(st, hosts, k.Name); err != nil {
					return err
				}
			}
			if err := guard(st, hosts, "", true); err != nil {
				return err
			}
			if user != "" && !nameRe.MatchString(user) {
				return out.Usage("%q cannot be a user name: use letters, digits and . _ -", user)
			}
			script := revokeScript(user, blob, g.dryRun)
			if allUsers {
				script = revokeAllScript(blob, g.dryRun)
			}
			res := fanout(cmd.Context(), st, hosts, func(ctx context.Context, c *sshx.Client) (any, error) {
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
			data := struct {
				Key     string           `json:"key"`
				Results []map[string]any `json:"results"`
				Summary fleetSummary     `json:"summary"`
			}{Key: label}
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
					if g.dryRun {
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
			if !g.dryRun {
				audit(st, "key.revoke", hostNames(hosts), "", data.Summary.Failed == 0, map[string]any{"key": label, "user": user, "all_users": allUsers})
			}
			return finish("key.revoke", data, data.Summary, worst)
		},
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

// guardRevokeSelf stops key revoke of the key komando logs in to hosts
// with: that locks komando out. A person types the key's name.
func guardRevokeSelf(st *store.State, hosts []*store.Host, key string) error {
	var self []string
	for _, h := range hosts {
		if h.Key == key {
			self = append(self, h.Name)
		}
	}
	if len(self) == 0 || dangerOK() {
		return nil
	}
	askTypes([]string{key}, "keys")
	return guardConns(st, nil, driver.Verdict{Risk: driver.RiskDestructive, RuleIDs: []string{"key-revoke-self"},
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
