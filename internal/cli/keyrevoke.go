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
	c := &cobra.Command{
		Use:   "revoke KEY TARGET",
		Short: "Remove a public key from authorized_keys on many servers (offboarding, rotation)",
		Long: `KEY is a key in komando's key list, a .pub file, or a public key line. Every line
with that key is removed from ~/.ssh/authorized_keys of the login user, or
of --user NAME (with sudo). The file keeps its owner and mode. Revoking the
key komando itself logs in with needs --allow-dangerous: you would lock
yourself out. --dry-run counts the lines it would remove.`,
		Example: `  komando key revoke ~/keys/budi.pub @prod --dry-run
  komando key revoke "ssh-ed25519 AAAAC3Nz...xyz budi@laptop" @prod
  komando key revoke old-deploy @web --user deploy`,
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
			if k != nil && user == "" {
				var self []string
				for _, h := range hosts {
					if h.Key == k.Name {
						self = append(self, h.Name)
					}
				}
				if len(self) > 0 && !dangerOK() {
					if err := guardConns(st, nil, driver.Verdict{Risk: driver.RiskDestructive, RuleIDs: []string{"key-revoke-self"},
						Reasons: []string{"komando logs in to " + strings.Join(self, ", ") + " with this key; switch them first (`komando host edit HOST --key OTHER`)"}}); err != nil {
						return err
					}
				}
			}
			if err := guard(st, hosts, "", true); err != nil {
				return err
			}
			file := `$HOME/.ssh/authorized_keys`
			if user != "" {
				if !nameRe.MatchString(user) {
					return out.Usage("invalid user name %q: use letters, digits and . _ -", user)
				}
				file = `$(getent passwd ` + sshx.Q(user) + ` | cut -d: -f6)/.ssh/authorized_keys`
			}
			count := `f="` + file + `"; [ -f "$f" ] || { echo 0; exit 0; }; n=$(grep -cF -- ` + sshx.Q(blob) + ` "$f" || true); `
			script := count + `if [ "$n" -gt 0 ]; then t="$f.komando-$$"; (umask 077; grep -vF -- ` + sshx.Q(blob) + ` "$f" > "$t" || true) && cat "$t" > "$f" && rm -f "$t"; fi; echo "$n"`
			if g.dryRun {
				script = count + `echo "$n"`
			}
			res := fanout(cmd.Context(), st, hosts, func(ctx context.Context, c *sshx.Client) (any, error) {
				r, err := sshx.Run(ctx, c, sshx.RunRequest{Command: script, Sudo: user != "", Timeout: 30 * time.Second, MaxOutput: 4096})
				if err != nil {
					return nil, err
				}
				if r.ExitCode != 0 {
					return nil, out.Errf(out.ExitRemote, "REVOKE_FAILED", "run it again; to look at the file: `komando fs cat HOST ~/.ssh/authorized_keys`", "%s", strings.TrimSpace(r.Stderr))
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
					data.Summary.OK++
				}
				data.Results = append(data.Results, r)
			}
			data.Summary.Total = len(res)
			if !g.dryRun {
				audit(st, "key.revoke", hostNames(hosts), "", data.Summary.Failed == 0, map[string]any{"key": label, "user": user})
			}
			return finish("key.revoke", data, data.Summary, worst)
		},
	}
	c.Flags().StringVar(&user, "user", "", "edit this user's authorized_keys instead of the login user's (uses sudo)")
	return c
}
