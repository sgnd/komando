package cli

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"golang.org/x/crypto/ssh"
	"golang.org/x/term"

	"github.com/sgnd/komando/internal/out"
	"github.com/sgnd/komando/internal/sshx"
	"github.com/sgnd/komando/internal/store"
	"github.com/sgnd/komando/internal/vault"
)

func keyCmd() *cobra.Command {
	c := &cobra.Command{Use: "key", Aliases: []string{"keys", "keychain"}, Short: "SSH keychain: generate, register, deploy to servers, list"}
	c.AddCommand(keyGenCmd(), keyAddCmd(), keyListCmd(), keyShowCmd(), keyRmCmd(), keyDeployCmd(), keyEditCmd())
	return c
}

func keyGenCmd() *cobra.Command {
	var typ, comment string
	var bits int
	c := &cobra.Command{
		Use:     "gen NAME",
		Short:   "Generate a new key pair stored in ~/.komando/keys (ed25519 default)",
		Example: "  komando key gen deploy && komando key deploy deploy @web",
		Args:    cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			name := args[0]
			if err := validName("key", name); err != nil {
				return err
			}
			if comment == "" {
				comment = "komando-" + name
			}
			var block *pem.Block
			var pub ssh.PublicKey
			var err error
			switch typ {
			case "ed25519":
				pk, sk, e := ed25519.GenerateKey(rand.Reader)
				if e != nil {
					return e
				}
				block, err = ssh.MarshalPrivateKey(sk, comment)
				if err == nil {
					pub, err = ssh.NewPublicKey(pk)
				}
			case "rsa":
				if bits == 0 {
					bits = 4096
				}
				sk, e := rsa.GenerateKey(rand.Reader, bits)
				if e != nil {
					return e
				}
				block, err = ssh.MarshalPrivateKey(sk, comment)
				if err == nil {
					pub, err = ssh.NewPublicKey(&sk.PublicKey)
				}
			default:
				return out.Usage("--type must be ed25519 or rsa")
			}
			if err != nil {
				return err
			}
			path := store.Path("keys", name)
			var k *store.Key
			err = store.Update(func(s *store.State) error {
				if _, ok := s.Keys[name]; ok {
					return out.Errf(out.ExitConflict, "KEY_EXISTS", "choose another name or `komando key rm` first", "key %q exists", name)
				}
				if err := os.WriteFile(path, pem.EncodeToMemory(block), 0o600); err != nil {
					return err
				}
				pubLine := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(pub))) + " " + comment
				if err := os.WriteFile(path+".pub", []byte(pubLine+"\n"), 0o644); err != nil {
					return err
				}
				k = &store.Key{Name: name, Path: path, Type: pub.Type(), PublicKey: pubLine, Fingerprint: ssh.FingerprintSHA256(pub), Managed: true, CreatedAt: time.Now().UTC()}
				s.Keys[name] = k
				return nil
			})
			if err != nil {
				return err
			}
			audit(nil, "key.gen", nil, "", true, map[string]any{"key": name})
			out.P.Print("key.gen", k, nil)
			return nil
		},
	}
	c.Flags().StringVar(&typ, "type", "ed25519", "ed25519 | rsa")
	c.Flags().IntVar(&bits, "bits", 0, "RSA bits (default 4096)")
	c.Flags().StringVar(&comment, "comment", "", "public key comment")
	return c
}

func keyAddCmd() *cobra.Command {
	var passRef string
	c := &cobra.Command{
		Use:     "add NAME PATH",
		Short:   "Register an existing private key file (not copied; referenced by path)",
		Example: "  komando key add personal ~/.ssh/id_ed25519",
		Args:    cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := validName("key", args[0]); err != nil {
				return err
			}
			p, _ := filepath.Abs(expandHome(args[1]))
			b, err := os.ReadFile(p)
			if err != nil {
				return out.Errf(out.ExitNotFound, "FILE_NOT_FOUND", "", "%v", err)
			}
			k := &store.Key{Name: args[0], Path: p, PassphraseRef: passRef, CreatedAt: time.Now().UTC()}
			signer, err := ssh.ParsePrivateKey(b)
			if _, ok := err.(*ssh.PassphraseMissingError); ok && passRef != "" {
				pass, perr := vault.Resolve(passRef)
				if perr != nil {
					return perr
				}
				signer, err = ssh.ParsePrivateKeyWithPassphrase(b, []byte(pass))
			}
			if err == nil {
				pub := signer.PublicKey()
				k.Type, k.Fingerprint = pub.Type(), ssh.FingerprintSHA256(pub)
				k.PublicKey = strings.TrimSpace(string(ssh.MarshalAuthorizedKey(pub)))
			} else if _, ok := err.(*ssh.PassphraseMissingError); ok {
				if pb, e := os.ReadFile(p + ".pub"); e == nil {
					k.PublicKey = strings.TrimSpace(string(pb))
				}
			} else {
				return out.Errf(out.ExitUsage, "KEY_INVALID", "", "cannot parse %s: %v", p, err)
			}
			err = store.Update(func(s *store.State) error {
				if _, ok := s.Keys[k.Name]; ok {
					return out.Errf(out.ExitConflict, "KEY_EXISTS", "", "key %q exists", k.Name)
				}
				s.Keys[k.Name] = k
				return nil
			})
			if err != nil {
				return err
			}
			out.P.Print("key.add", k, nil)
			return nil
		},
	}
	c.Flags().StringVar(&passRef, "passphrase-ref", "", "passphrase reference for encrypted keys (secret:NAME | env:VAR)")
	return c
}

func keyEditCmd() *cobra.Command {
	var passRef string
	c := &cobra.Command{
		Use:   "edit NAME",
		Short: "Change a key's passphrase reference",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			var k *store.Key
			err := store.Update(func(s *store.State) error {
				var ok bool
				if k, ok = s.Keys[args[0]]; !ok {
					return out.NotFound("key", args[0])
				}
				k.PassphraseRef = passRef
				return nil
			})
			if err != nil {
				return err
			}
			out.P.Print("key.edit", k, nil)
			return nil
		},
	}
	c.Flags().StringVar(&passRef, "passphrase-ref", "", "secret:NAME | env:VAR (empty clears)")
	return c
}

func keyListCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List keys and which hosts use them",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			st, err := loadState()
			if err != nil {
				return err
			}
			type row struct {
				*store.Key
				UsedBy []string `json:"used_by"`
			}
			rows := []row{}
			for _, k := range st.Keys {
				r := row{Key: k, UsedBy: []string{}}
				for _, h := range st.SortedHosts() {
					if h.Key == k.Name {
						r.UsedBy = append(r.UsedBy, h.Name)
					}
				}
				rows = append(rows, r)
			}
			sort.Slice(rows, func(i, j int) bool { return rows[i].Name < rows[j].Name })
			out.P.Print("key.list", map[string]any{"count": len(rows), "keys": rows}, nil)
			return nil
		},
	}
}

func keyShowCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "show NAME",
		Short: "Show a key's public part (never the private key)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			st, err := loadState()
			if err != nil {
				return err
			}
			k, ok := st.Keys[args[0]]
			if !ok {
				return out.NotFound("key", args[0])
			}
			out.P.Print("key.show", k, nil)
			return nil
		},
	}
}

func keyRmCmd() *cobra.Command {
	var deleteFile bool
	c := &cobra.Command{
		Use:   "rm NAME",
		Short: "Remove a key from the keychain (fails if hosts still use it)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			err := store.Update(func(s *store.State) error {
				k, ok := s.Keys[args[0]]
				if !ok {
					return out.NotFound("key", args[0])
				}
				for _, h := range s.Hosts {
					if h.Key == k.Name {
						return out.Errf(out.ExitConflict, "KEY_IN_USE", "reassign hosts with `komando host edit HOST --key OTHER`", "key used by host %s", h.Name)
					}
				}
				if deleteFile && k.Managed {
					os.Remove(k.Path)
					os.Remove(k.Path + ".pub")
				}
				delete(s.Keys, k.Name)
				return nil
			})
			if err != nil {
				return err
			}
			out.P.Print("key.rm", map[string]any{"removed": args[0], "file_deleted": deleteFile}, nil)
			return nil
		},
	}
	c.Flags().BoolVar(&deleteFile, "delete-file", false, "also delete komando-managed key files")
	return c
}

func keyDeployCmd() *cobra.Command {
	var setDefault bool
	c := &cobra.Command{
		Use:   "deploy KEY TARGET",
		Short: "Install a public key into ~/.ssh/authorized_keys on hosts (idempotent, like ssh-copy-id)",
		Long:  "Connects with the hosts' current credentials (e.g. password) and appends the key if missing. With --set-default the hosts are switched to use this key.",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			st, err := loadState()
			if err != nil {
				return err
			}
			k, ok := st.Keys[args[0]]
			if !ok {
				return out.NotFound("key", args[0])
			}
			if k.PublicKey == "" {
				return out.Errf(out.ExitUsage, "NO_PUBLIC_KEY", "place the .pub file next to the key", "public key for %s unknown", k.Name)
			}
			hosts, err := resolveTargets(st, args[1])
			if err != nil {
				return err
			}
			if err := guard(st, hosts, "", true); err != nil {
				return err
			}
			fields := strings.Fields(k.PublicKey)
			match := fields[0] + " " + fields[1]
			script := `umask 077; mkdir -p ~/.ssh && touch ~/.ssh/authorized_keys && ` +
				`if grep -qF ` + sshx.Q(match) + ` ~/.ssh/authorized_keys; then echo present; else printf '%s\n' ` + sshx.Q(k.PublicKey) + ` >> ~/.ssh/authorized_keys && echo added; fi`
			if g.dryRun {
				out.P.Print("key.deploy", map[string]any{"hosts": hostNames(hosts), "would_run": script}, nil)
				return nil
			}
			res := fanout(cmd.Context(), st, hosts, func(ctx context.Context, c *sshx.Client) (any, error) {
				o, code, err := sshx.Output(ctx, c, script, 30*time.Second)
				if err != nil {
					return nil, err
				}
				if code != 0 {
					return nil, out.Errf(out.ExitRemote, "DEPLOY_FAILED", "", "%s", o)
				}
				return o, nil
			})
			data := struct {
				Results []map[string]any `json:"results"`
				Summary fleetSummary     `json:"summary"`
			}{}
			worst := 0
			var okHosts []string
			for _, o := range res {
				r := map[string]any{"host": o.Host.Name}
				if o.Err != nil {
					e := toErr(o.Err)
					r["ok"], r["error"] = false, e
					worst = worse(worst, e.Exit)
					data.Summary.Failed++
					data.Summary.FailedHosts = append(data.Summary.FailedHosts, o.Host.Name)
				} else {
					r["ok"], r["status"] = true, o.Value
					data.Summary.OK++
					okHosts = append(okHosts, o.Host.Name)
				}
				data.Results = append(data.Results, r)
			}
			data.Summary.Total = len(res)
			if setDefault && len(okHosts) > 0 {
				_ = store.Update(func(s *store.State) error {
					for _, n := range okHosts {
						if h, ok := s.Hosts[n]; ok {
							h.Key = k.Name
						}
					}
					return nil
				})
			}
			audit(st, "key.deploy", hostNames(hosts), "", data.Summary.Failed == 0, map[string]any{"key": k.Name})
			return finish("key.deploy", data, data.Summary, worst)
		},
	}
	c.Flags().BoolVar(&setDefault, "set-default", false, "make successful hosts use this key")
	return c
}

func secretCmd() *cobra.Command {
	c := &cobra.Command{
		Use:     "secret",
		Aliases: []string{"secrets", "vault"},
		Short:   "Encrypted vault for passwords/passphrases/tokens (referenced as secret:NAME)",
		Long: `Secrets are AES-256-GCM encrypted in ~/.komando/vault.json. The key comes from
$KOMANDO_VAULT_PASS if set at first use, otherwise a random vault.key file.
Values are never printed unless 'secret get --reveal' is used.`,
	}
	set := &cobra.Command{
		Use:     "set NAME",
		Short:   "Store a secret (asks for it hidden; or from --from-env VAR or stdin)",
		Example: "  komando secret set web1-pass          # type it, nothing is shown\n  komando secret set db-pass --from-env DB_PASS\n  printf %s \"$TOKEN\" | komando secret set api-token",
		Args:    cobra.RangeArgs(1, 2),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := validName("secret", args[0]); err != nil {
				return err
			}
			if len(args) == 2 {
				// A value on the command line lands in shell history and in
				// `ps` for every user on the machine.
				return out.Errf(out.ExitUsage, "SECRET_IN_ARGS",
					fmt.Sprintf("run `komando secret set %s` and type it (hidden), use --from-env VAR, or pipe it on stdin", args[0]),
					"refusing a secret value on the command line: it would be saved in shell history")
			}
			var v string
			fromEnv, _ := cmd.Flags().GetString("from-env")
			switch {
			case fromEnv != "":
				var ok bool
				if v, ok = os.LookupEnv(fromEnv); !ok {
					return out.Usage("env %s not set", fromEnv)
				}
			default:
				b, err := readStdinIfPiped()
				if err != nil {
					return err
				}
				if b != nil && len(strings.TrimSpace(string(b))) == 0 {
					return out.Usage("empty value on stdin")
				}
				if b == nil {
					// a human at a terminal: ask with hidden input (agents never have a TTY)
					if !term.IsTerminal(int(os.Stdin.Fd())) {
						return out.Usage("no value: use --from-env VAR or pipe the value on stdin")
					}
					fmt.Fprintf(os.Stderr, "Value for %s (hidden): ", args[0])
					b, err = term.ReadPassword(int(os.Stdin.Fd()))
					fmt.Fprintln(os.Stderr)
					if err != nil {
						return err
					}
					if len(b) == 0 {
						return out.Usage("empty value")
					}
				}
				v = strings.TrimRight(string(b), "\r\n")
			}
			if err := vault.Set(args[0], v); err != nil {
				return err
			}
			audit(nil, "secret.set", nil, "", true, map[string]any{"secret": args[0]})
			out.P.Print("secret.set", map[string]any{"name": args[0], "ref": "secret:" + args[0]}, nil)
			return nil
		},
	}
	set.Flags().String("from-env", "", "read the value from this environment variable")
	get := &cobra.Command{
		Use:   "get NAME",
		Short: "Check a secret exists; --reveal prints its value",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			v, err := vault.Get(args[0])
			if err == vault.ErrNotFound {
				return out.NotFound("secret", args[0])
			}
			if err != nil {
				return err
			}
			reveal, _ := cmd.Flags().GetBool("reveal")
			res := map[string]any{"name": args[0], "exists": true, "length": len(v)}
			if reveal {
				res["value"] = v
				audit(nil, "secret.reveal", nil, "", true, map[string]any{"secret": args[0]})
			}
			out.P.Print("secret.get", res, nil)
			return nil
		},
	}
	get.Flags().Bool("reveal", false, "include the plaintext value")
	list := &cobra.Command{
		Use:   "list",
		Short: "List secret names",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			l, err := vault.List()
			if err != nil {
				return err
			}
			out.P.Print("secret.list", map[string]any{"count": len(l), "secrets": l}, nil)
			return nil
		},
	}
	rm := &cobra.Command{
		Use:   "rm NAME",
		Short: "Delete a secret",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := vault.Delete(args[0]); err == vault.ErrNotFound {
				return out.NotFound("secret", args[0])
			} else if err != nil {
				return err
			}
			out.P.Print("secret.rm", map[string]any{"removed": args[0]}, nil)
			return nil
		},
	}
	c.AddCommand(set, get, list, rm)
	return c
}
