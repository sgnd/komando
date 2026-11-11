package cli

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"golang.org/x/crypto/ssh"

	"github.com/sgnd/komando/internal/out"
	"github.com/sgnd/komando/internal/sshx"
	"github.com/sgnd/komando/internal/store"
	"github.com/sgnd/komando/internal/vault"
)

func keyCmd() *cobra.Command {
	c := &cobra.Command{Use: "key", Aliases: []string{"keys", "keychain"}, Short: "SSH keys: generate, register, deploy to servers, list"}
	c.AddCommand(keyGenCmd(), keyAddCmd(), keyListCmd(), keyShowCmd(), keyRmCmd(), keyDeployCmd(), keyRevokeCmd(), keyEditCmd(), keyMvCmd())
	return c
}

// minRSABits: NIST SP 800-57 and current OpenSSH guidance; 2048-bit keys
// are being retired and 1024-bit ones are refused by modern servers.
const minRSABits = 3072

// keyResult is a key plus what the person should know about it.
type keyResult struct {
	*store.Key
	Action   string   `json:"action,omitempty"` // added | would_add
	Warnings []string `json:"warnings,omitempty"`
}

// checkKeyType validates a key type and size before anything is made.
func checkKeyType(typ string, bits int) error {
	switch typ {
	case "ed25519":
		if bits != 0 {
			return out.Errf(out.ExitUsage, "USAGE", "leave --bits out for ed25519 (its size is fixed)", "--bits does not apply to ed25519")
		}
	case "rsa":
		if bits != 0 && (bits < minRSABits || bits > 16384) {
			return out.Errf(out.ExitUsage, "USAGE", fmt.Sprintf("use --bits %d or more (4096 is the default), or ed25519", minRSABits),
				"RSA keys of %d bits are too weak or too large", bits)
		}
	case "ecdsa":
		if bits != 0 && bits != 256 && bits != 384 && bits != 521 {
			return out.Errf(out.ExitUsage, "USAGE", "ECDSA takes --bits 256, 384 or 521", "invalid --bits %d for ecdsa", bits)
		}
	default:
		return out.Errf(out.ExitUsage, "USAGE", "use ed25519 (the default), rsa or ecdsa", "unknown key type %q", typ)
	}
	return nil
}

func newSigner(typ string, bits int) (crypto.Signer, error) {
	if err := checkKeyType(typ, bits); err != nil {
		return nil, err
	}
	switch typ {
	case "rsa":
		if bits == 0 {
			bits = 4096
		}
		return rsa.GenerateKey(rand.Reader, bits)
	case "ecdsa":
		curve := map[int]elliptic.Curve{0: elliptic.P256(), 256: elliptic.P256(), 384: elliptic.P384(), 521: elliptic.P521()}[bits]
		return ecdsa.GenerateKey(curve, rand.Reader)
	}
	_, sk, err := ed25519.GenerateKey(rand.Reader)
	return sk, err
}

func keyGenCmd() *cobra.Command {
	var typ, comment string
	var bits int
	var overwrite bool
	c := &cobra.Command{
		Use:   "gen NAME",
		Short: "Make a new key pair in ~/.komando/keys (ed25519 by default)",
		Long: `Makes a key pair like ssh-keygen and adds it to komando's key list. The private
key stays in ~/.komando/keys/NAME (mode 600); put the public part on servers with
` + "`komando key deploy`" + `. RSA keys need at least 3072 bits.`,
		Example: `  komando key gen deploy && komando key deploy deploy @web
  komando key gen legacy --type rsa -b 4096 -C ops@example.com`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			name := args[0]
			if err := validName("key", name); err != nil {
				return err
			}
			typ = strings.ToLower(typ)
			if comment == "" {
				comment = "komando-" + name
			}
			if hasControl(comment) {
				return out.Errf(out.ExitUsage, "USAGE", "use one line of plain text, e.g. -C ops@example.com", "the key comment cannot hold line breaks or control characters")
			}
			path := store.Path("keys", name)
			if _, err := os.Stat(path); err == nil && !overwrite {
				if st, _ := loadState(); st == nil || st.Keys[name] == nil {
					return out.Errf(out.ExitConflict, "KEY_FILE_EXISTS", "a key file from earlier is still there: move it away, or pass --overwrite to replace it",
						"%s already exists", path)
				}
			}
			if g.dryRun {
				if err := checkKeyType(typ, bits); err != nil {
					return err
				}
				st, err := loadState()
				if err != nil {
					return err
				}
				if _, ok := st.Keys[name]; ok {
					return keyExists(name)
				}
				k := &store.Key{Name: name, Path: path, Type: typ, Managed: true}
				out.P.Print("key.gen", keyResult{Key: k, Action: "would_add"}, nil)
				return nil
			}
			sk, err := newSigner(typ, bits)
			if err != nil {
				return err
			}
			block, err := ssh.MarshalPrivateKey(sk, comment)
			if err != nil {
				return err
			}
			pub, err := ssh.NewPublicKey(sk.Public())
			if err != nil {
				return err
			}
			var k *store.Key
			err = store.Update(func(s *store.State) error {
				if _, ok := s.Keys[name]; ok {
					return keyExists(name)
				}
				pubLine := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(pub))) + " " + comment
				if err := os.WriteFile(path, pem.EncodeToMemory(block), 0o600); err != nil {
					return err
				}
				if err := os.Chmod(path, 0o600); err != nil { // an old file keeps its mode
					return err
				}
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
			audit(nil, "key.gen", nil, "", true, map[string]any{"key": name, "type": k.Type, "fingerprint": k.Fingerprint})
			out.P.Print("key.gen", keyResult{Key: k, Action: "added"}, nil)
			return nil
		},
	}
	c.Flags().StringVar(&typ, "type", "ed25519", "ed25519 | rsa | ecdsa")
	c.Flags().IntVarP(&bits, "bits", "b", 0, "key size: RSA 3072-16384 (default 4096), ECDSA 256|384|521")
	c.Flags().StringVarP(&comment, "comment", "C", "", "public key comment (default komando-NAME)")
	c.Flags().BoolVar(&overwrite, "overwrite", false, "replace a key file left in ~/.komando/keys from earlier")
	return c
}

func keyExists(name string) error {
	return out.Errf(out.ExitConflict, "KEY_EXISTS", "choose another name, or `komando key rm "+name+"` first", "key %q already exists", name)
}

// isPublicKey reports whether b is a public key (a .pub file).
func isPublicKey(b []byte) bool {
	_, _, _, _, err := ssh.ParseAuthorizedKey(b)
	return err == nil
}

func keyAddCmd() *cobra.Command {
	var passRef string
	c := &cobra.Command{
		Use:   "add NAME PATH",
		Short: "Add a private key file you already have (komando keeps its path)",
		Long: `Adds a private key file you already have to komando's key list; the file stays
where it is. For a key with a passphrase, store the passphrase in the vault
and pass --passphrase-ref secret:NAME.`,
		Example: `  komando key add personal ~/.ssh/id_ed25519
  komando secret set id-pass && komando key add work ~/.ssh/id_work --passphrase-ref secret:id-pass`,
		Args: cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := validName("key", args[0]); err != nil {
				return err
			}
			if err := checkPassphraseRef(passRef); err != nil {
				return err
			}
			p, _ := filepath.Abs(expandHome(args[1]))
			b, err := os.ReadFile(p)
			if err != nil {
				return out.Errf(out.ExitNotFound, "FILE_NOT_FOUND", "give the path of a private key file, e.g. ~/.ssh/id_ed25519", "%s: %v", p, errText(err))
			}
			if isPublicKey(b) {
				return out.Errf(out.ExitUsage, "KEY_INVALID", "this is a public key; pass the private key file: "+strings.TrimSuffix(args[1], ".pub"),
					"%s is a public key", p)
			}
			res := keyResult{Key: &store.Key{Name: args[0], Path: p, PassphraseRef: passRef, CreatedAt: time.Now().UTC()}, Action: addVerb(false)}
			k := res.Key
			signer, err := ssh.ParsePrivateKey(b)
			var pme *ssh.PassphraseMissingError
			if errors.As(err, &pme) && passRef != "" {
				pass, perr := vault.Resolve(passRef)
				if perr != nil {
					return out.Errf(out.ExitNotFound, "SECRET_UNRESOLVED", "store it with `komando secret set NAME` or fix --passphrase-ref", "passphrase reference %s: %v", passRef, perr)
				}
				if signer, err = ssh.ParsePrivateKeyWithPassphrase(b, []byte(pass)); err != nil {
					return out.Errf(out.ExitUsage, "KEY_INVALID", "check that "+passRef+" holds this key's passphrase", "cannot open %s: %v", p, err)
				}
			}
			switch {
			case err == nil:
				pub := signer.PublicKey()
				k.Type, k.Fingerprint = pub.Type(), ssh.FingerprintSHA256(pub)
				k.PublicKey = strings.TrimSpace(string(ssh.MarshalAuthorizedKey(pub)))
			case errors.As(err, &pme):
				res.Warnings = append(res.Warnings, "the key has a passphrase and no --passphrase-ref: komando cannot log in with it until you run `komando key edit "+k.Name+" --passphrase-ref secret:NAME`")
				if pb, e := os.ReadFile(p + ".pub"); e == nil {
					if pub, comment, _, _, e := ssh.ParseAuthorizedKey(pb); e == nil {
						k.Type, k.Fingerprint = pub.Type(), ssh.FingerprintSHA256(pub)
						k.PublicKey = cleanPubLine(pub, comment)
					}
				} else {
					res.Warnings = append(res.Warnings, "no "+filepath.Base(p)+".pub next to it, so the public key is unknown (needed by key deploy)")
				}
			default:
				return out.Errf(out.ExitUsage, "KEY_INVALID", "give an OpenSSH or PEM private key file", "cannot parse %s: %v", p, err)
			}
			if k.Type == ssh.KeyAlgoRSA && rsaBits(k.PublicKey) > 0 && rsaBits(k.PublicKey) < 2048 {
				res.Warnings = append(res.Warnings, fmt.Sprintf("this RSA key has only %d bits; servers may refuse it: make a new one with `komando key gen`", rsaBits(k.PublicKey)))
			}
			err = store.Update(func(s *store.State) error {
				if _, ok := s.Keys[k.Name]; ok {
					return keyExists(k.Name)
				}
				s.Keys[k.Name] = k
				return nil
			})
			if err != nil {
				return err
			}
			audit(nil, "key.add", nil, "", true, map[string]any{"key": k.Name, "path": k.Path, "fingerprint": k.Fingerprint})
			out.P.Print("key.add", res, nil)
			return nil
		},
	}
	c.Flags().StringVar(&passRef, "passphrase-ref", "", "passphrase reference for encrypted keys (secret:NAME | env:VAR | ...)")
	return c
}

// rsaBits is the size of an RSA public key line, or 0.
func rsaBits(line string) int {
	pub, _, _, _, err := ssh.ParseAuthorizedKey([]byte(line))
	if err != nil {
		return 0
	}
	if cp, ok := pub.(ssh.CryptoPublicKey); ok {
		if r, ok := cp.CryptoPublicKey().(*rsa.PublicKey); ok {
			return r.N.BitLen()
		}
	}
	return 0
}

// cleanPubLine is an authorized_keys line rebuilt from its parts, the
// comment without control characters, so it is always exactly one line.
func cleanPubLine(pub ssh.PublicKey, comment string) string {
	line := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(pub)))
	comment = strings.Join(strings.Fields(strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return ' '
		}
		return r
	}, comment)), " ")
	if comment != "" {
		line += " " + comment
	}
	return line
}

func keyEditCmd() *cobra.Command {
	var passRef string
	c := &cobra.Command{
		Use:   "edit NAME",
		Short: "Change a key's passphrase reference",
		Long: `Sets where komando finds the passphrase of an encrypted key. Store the
passphrase with ` + "`komando secret set NAME`" + ` first and pass secret:NAME; an empty
value clears it.`,
		Example: `  komando secret set work-key-pass
  komando key edit work --passphrase-ref secret:work-key-pass
  komando key edit work --passphrase-ref ''      # clear it`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if !cmd.Flags().Changed("passphrase-ref") {
				return out.Errf(out.ExitUsage, "USAGE", "e.g. komando key edit "+args[0]+" --passphrase-ref secret:NAME", "nothing to change")
			}
			if err := checkPassphraseRef(passRef); err != nil {
				return err
			}
			var k *store.Key
			old := ""
			err := store.Update(func(s *store.State) error {
				var err error
				if k, err = findKey(s, args[0]); err != nil {
					return err
				}
				old = k.PassphraseRef
				k.PassphraseRef = passRef
				return nil
			})
			if err != nil {
				return err
			}
			audit(nil, "key.edit", nil, "", true, map[string]any{"key": k.Name, "old_passphrase_ref": old, "new_passphrase_ref": passRef})
			out.P.Print("key.edit", k, nil)
			return nil
		},
	}
	c.Flags().StringVar(&passRef, "passphrase-ref", "", "where the passphrase is: secret:NAME | env:VAR | ... (empty clears it)")
	return c
}

type sshKeyRow struct {
	*store.Key
	UsedBy []string `json:"used_by"`
}

type sshKeyList struct {
	Count int         `json:"count"`
	Keys  []sshKeyRow `json:"keys"`
}

func (l sshKeyList) Text() string {
	if len(l.Keys) == 0 {
		return "no keys yet: komando key gen NAME, or komando key add NAME PATH\n"
	}
	var rows [][]string
	for _, k := range l.Keys {
		rows = append(rows, []string{k.Name, strings.TrimPrefix(k.Type, "ssh-"), k.Fingerprint, strings.Join(k.UsedBy, ",")})
	}
	return textTable([]string{"NAME", "TYPE", "FINGERPRINT", "USED_BY"}, rows)
}

func keyListCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List keys and the servers that use them",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			st, err := loadState()
			if err != nil {
				return err
			}
			l := sshKeyList{Keys: []sshKeyRow{}}
			for _, k := range st.Keys {
				r := sshKeyRow{Key: k, UsedBy: []string{}}
				for _, h := range st.SortedHosts() {
					if h.Key == k.Name {
						r.UsedBy = append(r.UsedBy, h.Name)
					}
				}
				l.Keys = append(l.Keys, r)
			}
			sort.Slice(l.Keys, func(i, j int) bool { return l.Keys[i].Name < l.Keys[j].Name })
			l.Count = len(l.Keys)
			out.P.Print("key.list", l, nil)
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
			k, err := findKey(st, args[0])
			if err != nil {
				return err
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
		Short: "Remove a key from komando's key list (not while a server uses it)",
		Long: `Removes the key from komando's key list. --delete-file also deletes the key files,
but only for keys komando made (key gen); a key you added stays on disk.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			res := map[string]any{"removed": args[0], "file_deleted": false}
			err := store.Update(func(s *store.State) error {
				k, err := findKey(s, args[0])
				if err != nil {
					return err
				}
				res["removed"] = k.Name
				for _, h := range s.SortedHosts() {
					if h.Key == k.Name {
						return out.Errf(out.ExitConflict, "KEY_IN_USE", "give the server another key first: `komando host edit "+h.Name+" --key OTHER`", "server %s still uses this key", h.Name)
					}
				}
				switch {
				case deleteFile && !k.Managed:
					res["note"] = "komando did not create " + k.Path + ", so the file was left in place"
				case deleteFile && g.dryRun:
					res["would_delete_file"] = k.Path
				case deleteFile:
					if err := os.Remove(k.Path); err != nil && !os.IsNotExist(err) {
						return out.Errf(out.ExitError, "DELETE_FAILED", "check the file's permissions", "cannot delete %s: %v", k.Path, err)
					}
					_ = os.Remove(k.Path + ".pub")
					res["file_deleted"] = true
				}
				delete(s.Keys, k.Name)
				return nil
			})
			if err != nil {
				return err
			}
			if g.dryRun {
				res["would_remove"] = res["removed"] // "removed" stays for scripts that read it (contract 1)
			}
			audit(nil, "key.rm", nil, "", true, map[string]any{"key": res["removed"], "file_deleted": res["file_deleted"]})
			out.P.Print("key.rm", res, nil)
			return nil
		},
	}
	c.Flags().BoolVar(&deleteFile, "delete-file", false, "also delete the key files (only keys komando made)")
	return c
}

// deployKey is what `key deploy` installs: a keychain key, or a .pub file.
func deployKey(st *store.State, arg string) (name, line string, err error) {
	if k, ok := st.Keys[arg]; ok {
		if k.PublicKey == "" {
			return "", "", out.Errf(out.ExitUsage, "NO_PUBLIC_KEY", "place "+k.Path+".pub next to the key, then `komando key rm "+k.Name+"` and add it again", "komando does not have the public key of %s", k.Name)
		}
		pub, comment, _, _, err := ssh.ParseAuthorizedKey([]byte(k.PublicKey))
		if err != nil {
			return "", "", out.Errf(out.ExitUsage, "KEY_INVALID", "remove it with `komando key rm "+k.Name+"` and add it again", "the stored public key of %s is not valid: %v", k.Name, err)
		}
		return k.Name, cleanPubLine(pub, comment), nil
	}
	if b, rerr := os.ReadFile(expandHome(arg)); rerr == nil {
		pub, comment, _, _, err := ssh.ParseAuthorizedKey(b)
		if err != nil {
			return "", "", out.Errf(out.ExitUsage, "KEY_INVALID", "give a .pub file (the public key), not the private key", "%s is not a public key", arg)
		}
		return arg, cleanPubLine(pub, comment), nil
	}
	return "", "", notFoundSuggest("key", arg, mapKeys(st.Keys)).WithHint("give a key name from `komando key list` or a .pub file")
}

func keyDeployCmd() *cobra.Command {
	var setDefault bool
	c := &cobra.Command{
		Use:   "deploy KEY TARGET",
		Short: "Install a public key in ~/.ssh/authorized_keys (like ssh-copy-id)",
		Long: `Installs a public key on servers, like ssh-copy-id. KEY is a key in
komando's key list or a .pub file. komando logs in the way each server is set
up now (a password, for example) and appends the key to ~/.ssh/authorized_keys
unless it is already there. With --set-default the servers then log in with
this key.`,
		Example: `  komando key gen deploy && komando key deploy deploy @web --set-default
  komando key deploy ~/.ssh/id_ed25519.pub web1`,
		Args: cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			st, err := loadState()
			if err != nil {
				return err
			}
			name, pubLine, err := deployKey(st, args[0])
			if err != nil {
				return err
			}
			if setDefault && st.Keys[name] == nil {
				return out.Errf(out.ExitUsage, "USAGE", "add the private key first with `komando key add NAME PATH`, then deploy NAME", "--set-default needs a key in komando's key list, not a .pub file")
			}
			hosts, err := resolveTargets(st, args[1])
			if err != nil {
				return err
			}
			if err := guard(st, hosts, "", true); err != nil {
				return err
			}
			fields := strings.Fields(pubLine)
			match := fields[0] + " " + fields[1]
			script := `umask 077; mkdir -p ~/.ssh && touch ~/.ssh/authorized_keys && ` +
				`if grep -qF ` + sshx.Q(match) + ` ~/.ssh/authorized_keys; then echo present; else printf '%s\n' ` + sshx.Q(pubLine) + ` >> ~/.ssh/authorized_keys && echo added; fi`
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
					return nil, out.Errf(out.ExitRemote, "DEPLOY_FAILED", "check that ~/.ssh is writable there: `komando fs stat HOST ~/.ssh`", "%s", o)
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
							h.Key = name
						}
					}
					return nil
				})
			}
			audit(st, "key.deploy", hostNames(hosts), "", data.Summary.Failed == 0, map[string]any{"key": name})
			return finish("key.deploy", data, data.Summary, worst)
		},
	}
	c.Flags().BoolVar(&setDefault, "set-default", false, "servers that got the key log in with it from now on")
	return c
}
