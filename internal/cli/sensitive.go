package cli

import (
	"errors"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strings"
	"sync"

	"github.com/sgnd/komando/internal/out"
	"github.com/sgnd/komando/internal/vault"
)

// Secrets an AI agent never sees, but can still use (docs/features/safety.md):
//   - output shows [hidden] or [secret:NAME] instead of the value;
//   - text holding those markers is never written over a real file;
//   - {{secret:NAME}} in written text becomes the vault value on the server;
//   - files that are secrets by name (.env, private keys, ...) are not
//     copied to this computer for an agent without a person's yes.

func hiddenValueErr() error {
	return out.Errf(out.ExitUsage, "HIDDEN_VALUE",
		"change only the lines you need with `komando fs replace` (an --old with [hidden] in it matches the hidden value), and put a secret in with {{secret:NAME}}",
		"the text holds a value komando hid ([hidden] or [secret:NAME]); writing it would destroy the real value")
}

// hiddenScanMax: larger files (archives, images) are not read for markers.
const hiddenScanMax = 16 << 20

// hiddenInLocal refuses to upload a local file, or a folder's files, that
// holds a value komando hid: it is a masked copy (saved from fs cat), and
// sending it would put [hidden] where the real value is.
func hiddenInLocal(p string) error {
	return filepath.WalkDir(p, func(f string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil // the upload itself reports what it cannot read
		}
		info, err := d.Info()
		if err != nil || !info.Mode().IsRegular() || info.Size() > hiddenScanMax {
			return nil
		}
		b, err := os.ReadFile(f)
		if err == nil && out.HasHidden(string(b)) {
			return out.Errf(out.ExitUsage, "HIDDEN_VALUE",
				"edit the file on the server with `komando fs replace` (an --old with [hidden] in it matches the hidden value), and put a secret in with {{secret:NAME}}",
				"%s holds a value komando hid ([hidden] or [secret:NAME]); uploading it would destroy the real value", f)
		}
		return nil
	})
}

var secretRef = regexp.MustCompile(`\{\{\s*secret:([A-Za-z0-9_.@/-]+)\s*\}\}`)

// expandSecretRefs puts vault values in place of {{secret:NAME}} in text
// that goes to where (a server's file). A secret komando keeps for itself
// never goes, and for an AI agent each secret needs a person's yes, since
// on the server the value can come back in a form masking does not know
// (guardSecretUse). An agent's dry run reads no secret, since it never
// asks the person: its preview keeps {{secret:NAME}} as it is. With
// dollars set, the values are written for a regexp replacement ($ as $$).
func expandSecretRefs(s, where string, dollars bool) (string, error) {
	var refs []string
	for _, m := range secretRef.FindAllStringSubmatch(s, -1) {
		refs = append(refs, "secret:"+m[1])
	}
	if len(refs) == 0 {
		return s, nil
	}
	if err := guardSecretUse(refs, where); err != nil {
		return "", err
	}
	var err error
	r := secretRef.ReplaceAllStringFunc(s, func(m string) string {
		name := secretRef.FindStringSubmatch(m)[1]
		if isAgent() && g.dryRun {
			return m
		}
		v, e := vault.Get(name)
		if e != nil && err == nil {
			if e == vault.ErrNotFound {
				e = out.NotFound("secret", name)
			}
			err = e
		}
		if dollars {
			v = strings.ReplaceAll(v, "$", "$$")
		}
		return v
	})
	return r, err
}

func expandSecretRefsBytes(b []byte, where string) ([]byte, error) {
	if !secretRef.Match(b) {
		return b, nil
	}
	s, err := expandSecretRefs(string(b), where, false)
	return []byte(s), err
}

// hiddenPattern turns text with [hidden] in it into a regexp in which each
// [hidden] matches one value, as out.MaskSecrets cut it.
func hiddenPattern(s string) string {
	parts := strings.Split(s, out.Hidden)
	for i, p := range parts {
		parts[i] = regexp.QuoteMeta(p)
	}
	return strings.Join(parts, `[^\s"'\\,;&}]+`)
}

// sensitiveName reports whether a file is a secret by its name: env files,
// private keys, certificates' keys, password and credential stores.
func sensitiveName(p string) bool {
	b := strings.ToLower(path.Base(strings.ReplaceAll(p, `\`, "/")))
	switch b {
	case ".env", ".pgpass", ".my.cnf", ".netrc", ".git-credentials", ".htpasswd", ".npmrc", ".pypirc",
		"credentials", "credentials.json", "credentials.yml", "credentials.yaml", "master.key",
		"shadow", "gshadow", "shadow-", "id_rsa", "id_dsa", "id_ecdsa", "id_ed25519", "id_ecdsa_sk", "id_ed25519_sk",
		"secrets.yml", "secrets.yaml", "secrets.json", "secret.yml", "secret.yaml", "vault.key", "vault.json", "wp-config.php":
		return true
	}
	if strings.HasPrefix(b, ".env.") || strings.HasSuffix(b, ".env") {
		for _, safe := range []string{".example", ".sample", ".template", ".dist", ".defaults"} {
			if strings.HasSuffix(b, safe) {
				return false
			}
		}
		return true
	}
	for _, ext := range []string{".pem", ".key", ".p12", ".pfx", ".jks", ".keystore", ".kdbx", ".ovpn"} {
		if strings.HasSuffix(b, ext) && len(b) > len(ext) { // "site.key", not a bare ".key" (a jq filter)
			return true
		}
	}
	return false
}

// sensitiveGlobs are the sensitiveName files as sync --exclude patterns.
var sensitiveGlobs = []string{".env", ".env.*", "*.env", ".pgpass", ".my.cnf", ".netrc", ".git-credentials", ".htpasswd", ".npmrc", ".pypirc",
	"credentials", "credentials.*", "master.key", "shadow", "gshadow", "id_rsa", "id_dsa", "id_ecdsa", "id_ed25519", "id_*_sk",
	"secrets.*", "secret.y*ml", "wp-config.php", "*.pem", "*.key", "*.p12", "*.pfx", "*.jks", "*.keystore", "*.kdbx", "*.ovpn"}

// guardSensitiveCopy stops an AI agent from copying a file that is a secret
// by name to this computer, where it could read it in full. --reveal, which
// a person allows on the screen, lets it through.
func guardSensitiveCopy(remotePath string) error {
	if !isAgent() || !sensitiveName(remotePath) || revealOK() {
		return nil
	}
	return out.Errf(out.ExitPolicy, "SENSITIVE_FILE",
		revealHint("read it with `komando fs cat` instead (passwords, keys and tokens show as [hidden]); if the user wants the real file on this computer, re-run with --reveal"),
		"%s holds secrets; komando does not copy it to this computer for an AI agent", remotePath)
}

// komandoData is secretPath's reason for komando's own folder.
const komandoData = "komando's own data (vault, keys, inventory, audit log)"

// localSecret says why a file on this computer is off limits to an AI
// agent, as the agent guard sees it (guard.go), or "". The path is made
// absolute and its links are followed, so a link to ~/.komando counts too.
func localSecret(p string) string {
	home, err := os.UserHomeDir()
	if err != nil || p == "" {
		return ""
	}
	abs, err := filepath.Abs(expandHome(p))
	if err != nil {
		abs = p
	}
	if why := secretPath(abs, home); why != "" {
		return why
	}
	if real := realPath(abs); real != abs {
		if why := secretPath(real, home); why != "" {
			return why
		}
	}
	return hardLinkSecret(abs, home)
}

// procEnv is secretPath's reason for /proc/PID/environ.
const procEnv = "the environment of a process (it holds tokens and passwords)"

// hardLinkSecret says why a file with more than one name is off limits
// when one of its other names is a protected file (`ln ~/.komando/state.json
// notes.txt` makes notes.txt the same file), or "". Following links does
// not see a hard link, so the files in the protected folders are compared;
// only files with more than one name are looked up.
func hardLinkSecret(p, home string) string {
	fi, err := os.Stat(p)
	if err != nil || !fi.Mode().IsRegular() {
		return ""
	}
	if fileLinks(p, fi) < 2 {
		return ""
	}
	for _, f := range protectedFilesOf(home) {
		if os.SameFile(fi, f.fi) {
			return f.why
		}
	}
	return ""
}

type protectedFile struct {
	fi  os.FileInfo
	why string
}

// protectedFiles caches the files of the protected folders for
// hardLinkSecret: a folder upload can ask for many files.
var protectedFiles struct {
	sync.Mutex
	key   string
	files []protectedFile
}

func protectedFilesOf(home string) []protectedFile {
	dirs := protectedDirs(home)
	key := home + "\x00" + strings.Join(dirs, "\x00")
	protectedFiles.Lock()
	defer protectedFiles.Unlock()
	if protectedFiles.key == key {
		return protectedFiles.files
	}
	var files []protectedFile
	seen := 0
	for _, d := range dirs {
		_ = filepath.WalkDir(d, func(q string, e fs.DirEntry, err error) error {
			if err != nil {
				return nil
			}
			if seen++; seen > 20000 {
				return filepath.SkipAll
			}
			if !e.Type().IsRegular() {
				return nil
			}
			if why := secretPath(q, home); why != "" {
				if fi, err := e.Info(); err == nil {
					files = append(files, protectedFile{fi, why})
				}
			}
			return nil
		})
	}
	protectedFiles.key, protectedFiles.files = key, files
	return files
}

// guardLocalRead stops komando from reading a secret file on this computer
// for an AI agent: what komando reads it sends to a server (--stdin-file,
// script FILE, uploads, fs write --from, db --file, cluster -f), and a
// server can send it back where masking does not see it (base64 of a key).
// The guard keeps the agent's own tools from the same files, so komando
// must not be the way around it. A person allows a project secret (.env,
// a TLS key) with --reveal; komando's own data never goes.
func guardLocalRead(p string) error {
	if p == "" || p == "-" || !isAgent() {
		return nil
	}
	why := localSecret(p)
	switch {
	case why == "":
		return nil
	case why == komandoData:
		return out.Errf(out.ExitPolicy, "SENSITIVE_FILE",
			"komando never reads its own folder for an AI agent; use komando commands (`komando list`, `komando secret list`), or ask the user to run this in their own terminal",
			"%s is %s", p, why).NoFlag()
	case why == procEnv:
		return out.Errf(out.ExitPolicy, "SENSITIVE_FILE",
			"ask the user for the one value you need",
			"%s is %s; komando does not read it for an AI agent", p, why).NoFlag()
	case revealOK():
		return nil
	}
	return out.Errf(out.ExitPolicy, "SENSITIVE_FILE", revealHint("if the user wants komando to send this file, re-run with --reveal; komando asks the user in a window on their screen"),
		"%s is %s; komando does not read it for an AI agent", p, why)
}

// revealHint is h, or under --dry-run, why --reveal does not count there.
func revealHint(h string) string {
	if g.dryRun && g.reveal {
		return "a dry run never asks the user, so --reveal does not count under --dry-run; run it without --dry-run and komando asks the user in a window"
	}
	return h
}

// readLocalFile reads a file on this computer for a command, after
// guardLocalRead. Every command that reads a path given to it uses it.
func readLocalFile(p string) ([]byte, error) {
	if err := guardLocalRead(p); err != nil {
		return nil, err
	}
	return os.ReadFile(p)
}

// readImportFile reads a file an import takes secrets from (kubeconfig,
// .pgpass, ~/.docker/config.json, .env): they go into komando's vault, which
// an AI agent never sees, so the agent may point komando at them, as with
// `key add --file` and `vpn add --config`. komando's own data and process
// environments still never go.
func readImportFile(p string) ([]byte, error) {
	if p == "-" {
		return readAllStdin()
	}
	if isAgent() {
		if why := localSecret(p); why == komandoData || why == procEnv {
			return nil, out.Errf(out.ExitPolicy, "SENSITIVE_FILE",
				"komando does not import its own folder or a process environment for an AI agent; ask the user to run this in their own terminal",
				"%s is %s", p, why).NoFlag()
		}
	}
	return os.ReadFile(p)
}

// skipLocalSecret reports whether a folder upload leaves a file out for an
// AI agent, as folder downloads do; meta.skipped lists it.
func skipLocalSecret(p string) bool {
	if guardLocalRead(p) == nil {
		return false
	}
	out.P.Skip(out.Skipped{Name: p, Kind: "file", Reason: "holds secrets; an AI agent needs --reveal, which the user allows, to send it"})
	return true
}

// unlockVars are the variables that open the secret stores komando reads
// (its vault, KeePass, Bitwarden, 1Password Connect, HashiCorp Vault).
var unlockVars = map[string]bool{
	"KOMANDO_VAULT_PASS": true, "KOMANDO_KDBX_PASSWORD": true, "KOMANDO_KDBX_KEYFILE": true,
	"KOMANDO_BW_PASSWORD": true, "KOMANDO_BW_CLIENT_SECRET": true, "OP_CONNECT_TOKEN": true, "VAULT_TOKEN": true,
}

// refGuard is vault.RefGuard: a secret: reference never reads a secret
// komando keeps for itself (the approval code's key), for anyone. And an
// AI agent cannot point a file: or env: reference (a password komando
// sends to a server) at komando's own data, a private key, a credential
// store or the password of a secret store. Files that are secret only by
// name stay allowed: VPN configs, key and password files are what a person
// points file: references at, and a reference is read on every connection,
// long after the person set it. Other variables stay allowed too: an agent
// can read those in its own shell anyway, and the place a reference goes
// to needs a person's yes (guardSends).
func refGuard(kind, name string) error {
	if kind == "secret" {
		return reservedSecret(name)
	}
	if !isAgent() {
		return nil
	}
	switch kind {
	case "file":
		if why := localSecret(name); why != "" && why != "a file that holds secrets" {
			return out.Errf(out.ExitPolicy, "SENSITIVE_FILE", "store the password in komando's vault and use secret:NAME; the user sets it up in their own terminal",
				"the reference file:%s points at %s; komando does not send it for an AI agent", name, why).NoFlag()
		}
	case "env":
		if unlockVars[name] {
			return out.Errf(out.ExitPolicy, "SENSITIVE_FILE", "use secret:NAME; the user sets it up in their own terminal",
				"the reference env:%s is the password of a secret store; komando does not send it for an AI agent", name).NoFlag()
		}
	}
	return nil
}

// isSensitive reports whether err is guardLocalRead's refusal.
func isSensitive(err error) bool {
	var e *out.Error
	return errors.As(err, &e) && e.Code == "SENSITIVE_FILE"
}

func init() { vault.RefGuard = refGuard }
