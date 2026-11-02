package out

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"regexp"
	"strings"
)

// Hidden is what a password, key or token looks like in masked output.
// Writing text that still holds it is refused (HasHidden), so a masked file
// read by an agent can never be written back over the real one.
const Hidden = "[hidden]"

// Masking hides values that look like secrets, wherever they come from: a
// .env or config file, `env`, a log line, a database row. It is applied to
// output for AI agents (Printer.Mask). It is a best effort on top of the
// vault redaction, which hides every vault value exactly.
var (
	pemKey = regexp.MustCompile(`(?s)-----BEGIN ((?:[A-Z0-9]+ )*)PRIVATE KEY( BLOCK)?-----.*?(-----END ((?:[A-Z0-9]+ )*)PRIVATE KEY( BLOCK)?-----|$)`)
	urlPw  = regexp.MustCompile(`\b([a-zA-Z][a-zA-Z0-9+.-]*://[^\s:/@"'\\]+:)([^\s@/"'\\]+)@`)
	bearer = regexp.MustCompile(`(?i)\b(bearer|basic|token)(\s+)([A-Za-z0-9._~+/=-]{12,})`)
	// NAME=value, NAME: value, "name": "value", --name=value
	assign = regexp.MustCompile(`(?i)([A-Za-z0-9_.-]*(?:passw(?:or)?d|passphrase|pwd|pass|secret|token|api[_-]?key|access[_-]?key|private[_-]?key|credentials?|authorization|[_.-]key)[A-Za-z0-9_.-]*)(["']?[ \t]*[:=][ \t]*["']?)([^\s"'\\,;&}]+)`)
	// well-known token shapes, wherever they appear
	tokens = regexp.MustCompile(`\b(?:gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{30,}|glpat-[A-Za-z0-9_-]{20,}|xox[abposr]-[A-Za-z0-9-]{10,}|sk-[A-Za-z0-9_-]{20,}|[rs]k_(?:live|test)_[A-Za-z0-9]{16,}|AIza[0-9A-Za-z_-]{35}|AKIA[0-9A-Z]{16}|ASIA[0-9A-Z]{16}|eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})\b`)
	// password hashes, as in /etc/shadow
	pwHash = regexp.MustCompile(`\$(?:1|2[abxy]?|5|6|y|gy|7|argon2[a-z]*)\$[^\s:"'\\]{8,}`)
	// a JSON object key that names a secret: its whole string value is hidden
	secretKey = regexp.MustCompile(`(?i)^[A-Za-z0-9_.-]*(?:passw(?:or)?d|passphrase|pwd|secret|token|api[_-]?key|access[_-]?key|private[_-]?key|credentials?|authorization|[_.-]key)[A-Za-z0-9_.-]*$`)
	// keys that name a secret but hold no value komando would hide
	notSecretKey = regexp.MustCompile(`(?i)(_ref|_refs|_name|_names|_id|_count|_file|_path|_type|_hint)$`)
)

// MaskSecrets hides secret-looking values in plain text.
func MaskSecrets(s string) string {
	if s == "" {
		return s
	}
	s = pemKey.ReplaceAllString(s, "[hidden: private key]")
	s = urlPw.ReplaceAllString(s, "${1}"+Hidden+"@")
	s = bearer.ReplaceAllString(s, "${1}${2}"+Hidden)
	s = assign.ReplaceAllStringFunc(s, func(m string) string {
		sub := assign.FindStringSubmatch(m)
		if sub[2] == ":" && strings.EqualFold(sub[1], "secret") || keepValue(sub[1], sub[3]) {
			// secret:NAME is a komando reference, [secret:NAME] a hidden value
			return m
		}
		return sub[1] + sub[2] + Hidden
	})
	s = tokens.ReplaceAllString(s, Hidden)
	return pwHash.ReplaceAllString(s, Hidden)
}

// keepValue: values that are not secrets, so masking them would only hide
// what an agent needs (a komando reference, a boolean, a placeholder).
func keepValue(name, v string) bool {
	if notSecretKey.MatchString(name) {
		return true
	}
	lv := strings.ToLower(v)
	switch lv {
	case "true", "false", "yes", "no", "on", "off", "null", "none", "nil", "required", "optional", "string", "[", "bearer", "basic":
		return true
	}
	for _, p := range []string{"[hidden", "[secret:", "secret:", "env:", "file:", "op://", "vault:", "aws-sm:", "gcp-sm:", "${", "$(", "<"} {
		if strings.HasPrefix(lv, p) {
			return true
		}
	}
	return false
}

// HasHidden reports whether text holds a value komando hid from an agent
// ([hidden] or [secret:NAME]). Such text must not be written to a file.
func HasHidden(s string) bool {
	return strings.Contains(s, Hidden) || strings.Contains(s, "[hidden: private key]") || secretLabel.MatchString(s)
}

var secretLabel = regexp.MustCompile(`\[secret:[A-Za-z0-9_.@/-]+\]`)

// maskJSON hides secrets inside the string values of a JSON document: each
// string is decoded, masked as text and encoded again, and a string under a
// key that names a secret (password, token, ...) is hidden whole. Numbers,
// keys and structure are left as they are, so the document stays valid.
func maskJSON(b []byte) []byte {
	var outb bytes.Buffer
	lastKey := ""
	var parents []string // the key each open object or array is the value of
	i := 0
	for i < len(b) {
		c := b[i]
		if c != '"' {
			switch c {
			case '{', '[':
				k := ""
				if isValueOf(&outb) {
					k = lastKey
				}
				parents = append(parents, k)
				lastKey = ""
			case '}', ']':
				if len(parents) > 0 {
					parents = parents[:len(parents)-1]
				}
			}
			outb.WriteByte(c)
			i++
			continue
		}
		end := stringEnd(b, i)
		lit := b[i:end]
		i = end
		// a key is a string followed by ':'
		j := i
		for j < len(b) && (b[j] == ' ' || b[j] == '\t' || b[j] == '\n' || b[j] == '\r') {
			j++
		}
		var s string
		if json.Unmarshal(lit, &s) != nil {
			outb.Write(lit)
			continue
		}
		if j < len(b) && b[j] == ':' {
			lastKey = s
			outb.Write(lit)
			continue
		}
		key := lastKey
		lastKey = ""
		parent := ""
		if len(parents) > 0 {
			parent = parents[len(parents)-1]
		}
		var m string
		switch {
		case key != "" && isValueOf(&outb) && secretKey.MatchString(key) && !keepValue(key, s) && s != "":
			m = Hidden
		case key != "" && (parent == "data" || parent == "stringData") && kubeSecretValue(s):
			// a Kubernetes Secret: every value under data is a secret
			m = Hidden
		default:
			m = MaskSecrets(s)
		}
		if m == s {
			outb.Write(lit)
			continue
		}
		var e bytes.Buffer
		enc := json.NewEncoder(&e)
		enc.SetEscapeHTML(false)
		_ = enc.Encode(m)
		outb.Write(bytes.TrimRight(e.Bytes(), "\n"))
	}
	return outb.Bytes()
}

// kubeSecretValue: a value under data/stringData that looks like a Secret's
// (base64, at least 8 characters), not a ConfigMap's plain text.
func kubeSecretValue(s string) bool {
	if len(s) < 8 || len(s)%4 != 0 {
		return false
	}
	_, err := base64.StdEncoding.DecodeString(s)
	return err == nil
}

// isValueOf: the string just reached is a member value (after "key":), not
// an array element.
func isValueOf(w *bytes.Buffer) bool {
	o := w.Bytes()
	for k := len(o) - 1; k >= 0; k-- {
		switch o[k] {
		case ' ', '\t', '\n', '\r':
			continue
		case ':':
			return true
		default:
			return false
		}
	}
	return false
}

// stringEnd returns the index just past the JSON string starting at b[i].
func stringEnd(b []byte, i int) int {
	for k := i + 1; k < len(b); k++ {
		switch b[k] {
		case '\\':
			k++
		case '"':
			return k + 1
		}
	}
	return len(b)
}
