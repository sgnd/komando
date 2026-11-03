package cli

import (
	"path"
	"regexp"
	"strings"

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

var secretRef = regexp.MustCompile(`\{\{\s*secret:([A-Za-z0-9_.@/-]+)\s*\}\}`)

// expandSecretRefs puts vault values in place of {{secret:NAME}}.
func expandSecretRefs(s string) (string, error) {
	var err error
	r := secretRef.ReplaceAllStringFunc(s, func(m string) string {
		name := secretRef.FindStringSubmatch(m)[1]
		v, e := vault.Get(name)
		if e != nil && err == nil {
			if e == vault.ErrNotFound {
				e = out.NotFound("secret", name)
			}
			err = e
		}
		return v
	})
	return r, err
}

func expandSecretRefsBytes(b []byte) ([]byte, error) {
	if !secretRef.Match(b) {
		return b, nil
	}
	s, err := expandSecretRefs(string(b))
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
		"read it with `komando fs cat` instead (passwords, keys and tokens show as [hidden]); if the user wants the real file on this computer, re-run with --reveal",
		"%s holds secrets; komando does not copy it to this computer for an AI agent", remotePath)
}
