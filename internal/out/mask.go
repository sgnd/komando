package out

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"regexp"
	"strings"
	"unicode/utf8"
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
	// the end of a key whose BEGIN line was cut off (`fs cat --tail`): the
	// base64 lines right before END (line-numbered or not), and END
	pemBody = regexp.MustCompile(`(?m)(?:^[ \t]*(?:\d+\t)?[A-Za-z0-9+/=]+\r?\n)+[ \t]*(?:\d+\t)?-----END ((?:[A-Z0-9]+ )*)PRIVATE KEY( BLOCK)?-----`)
	urlPw   = regexp.MustCompile(`\b([a-zA-Z][a-zA-Z0-9+.-]*://[^\s:/@"'\\]+:)([^\s@/"'\\]+)@`)
	bearer  = regexp.MustCompile(`(?i)\b(bearer|basic|token)([ \t]+)([A-Za-z0-9._~+/=-]{12,})`) // same line only
	// NAME=value, NAME: value, "name": "value", --name=value
	assign = regexp.MustCompile(`(?i)([A-Za-z0-9_.-]*(?:passw(?:or)?d|passphrase|pwd|pass|secret|token|api[_-]?key|access[_-]?key|private[_-]?key|credentials?|authorization|[_.-]key)[A-Za-z0-9_.-]*)(["']?[ \t]*[:=][ \t]*["']?)([^\s"'\\,;&}]+)`)
	// well-known token shapes, wherever they appear
	tokens = regexp.MustCompile(`\b(?:gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{30,}|glpat-[A-Za-z0-9_-]{20,}|xox[abposr]-[A-Za-z0-9-]{10,}|sk-[A-Za-z0-9_-]{20,}|[rs]k_(?:live|test)_[A-Za-z0-9]{16,}|AIza[0-9A-Za-z_-]{35}|AKIA[0-9A-Z]{16}|ASIA[0-9A-Z]{16}|eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})\b`)
	// Redis and Sentinel config: "requirepass pw", "sentinel auth-pass
	// mymaster pw" (redis.conf, also behind grep's "file:" and "12:")
	redisPw = regexp.MustCompile(`(?mi)^(` + grepPrefix + `[ \t]*(?:` + redisPwNames + `|sentinel[ \t]+sentinel-pass|sentinel[ \t]+auth-pass[ \t]+\S+)[ \t]+)("[^"\r\n]*"|'[^'\r\n]*'|[^\s"']+)`)
	// redis-cli CONFIG GET: the name on one line, the value on the next,
	// numbered ("1) \"requirepass\"") or raw
	redisPwPair = regexp.MustCompile(`(?mi)^([ \t]*(?:\d+\)[ \t]*)?"?(?:` + redisPwNames + `|sentinel-pass)"?[ \t]*\r?\n[ \t]*(?:\d+\)[ \t]*)?)([^\r\n]+)`)
	// a Redis ACL rule: ">pw" and "<pw" are plaintext passwords, "#hash" an
	// unsalted SHA-256 (redis.conf, users.acl, ACL LIST)
	redisACL     = regexp.MustCompile(`(?mi)^` + grepPrefix + `[ \t]*(?:\d+\)[ \t]*)?"?user[ \t]+\S+[ \t].*$`)
	redisACLPass = regexp.MustCompile(`(^|[ \t])([<>])[^\s"]+|(^|[ \t])([#!])[0-9a-fA-F]{64}\b`)
	// password hashes, as in /etc/shadow
	pwHash = regexp.MustCompile(`\$(?:1|2[abxy]?|5|6|y|gy|7|argon2[a-z]*)\$[^\s:"'\\]{8,}`)
	// a JSON object key that names a secret: its whole string value is hidden
	secretKey = regexp.MustCompile(`(?i)^[A-Za-z0-9_.-]*(?:passw(?:or)?d|passphrase|pwd|secret|token|api[_-]?key|access[_-]?key|private[_-]?key|credentials?|authorization|[_.-]key)[A-Za-z0-9_.-]*$`)
	// keys that name a secret but hold no value komando would hide
	notSecretKey = regexp.MustCompile(`(?i)(^(max|min|num|public)_|^public|pub_?keys?$|fingerprint|(ref|refs|_name|_names|_id|_count|_file|_path|_type|_hint|_endpoint|_url|_uri|_host|_port|_length|_len|_size|_ttl|_expiry|_expires|_timeout|_max|_min|_enabled|_required|_policy|_mode|_header|_field|_param)$)`)
)

const (
	redisPwNames = `requirepass|masterauth|primaryauth|tls-key-file-pass|tls-client-key-file-pass`
	grepPrefix   = `(?:[^\s:]+:|[^\s:]*-\d+-)*` // grep -H, -n and context lines
)

// MaskSecrets hides secret-looking values in plain text.
func MaskSecrets(s string) string {
	if s == "" {
		return s
	}
	s = pemKey.ReplaceAllString(s, "[hidden: private key]")
	s = pemBody.ReplaceAllString(s, "[hidden: private key]")
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
	s = maskRedis(s)
	s = tokens.ReplaceAllString(s, Hidden)
	return pwHash.ReplaceAllString(s, Hidden)
}

// maskRedis hides passwords written the Redis way, with a space after the
// name instead of "=" or ":".
func maskRedis(s string) string {
	hide := func(re *regexp.Regexp) func(string) string {
		return func(m string) string {
			sub := re.FindStringSubmatch(m)
			v := sub[2]
			q := ""
			if len(v) >= 2 && (v[0] == '"' || v[0] == '\'') && v[len(v)-1] == v[0] {
				q, v = v[:1], v[1:len(v)-1]
			}
			if v == "" || keepValue("password", v) {
				return m
			}
			return sub[1] + q + Hidden + q
		}
	}
	s = redisPw.ReplaceAllStringFunc(s, hide(redisPw))
	s = redisPwPair.ReplaceAllStringFunc(s, hide(redisPwPair))
	return redisACL.ReplaceAllStringFunc(s, func(line string) string {
		return redisACLPass.ReplaceAllString(line, "${1}${3}${2}${4}"+Hidden)
	})
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
	// references, placeholders, structure ({name: …} in YAML), paths and
	// plain URLs (a URL with a password in it is hidden by urlPw)
	for _, p := range []string{"[hidden", "[secret:", "secret:", "env:", "file:", "op://", "vault:", "aws-sm:", "gcp-sm:", "${", "$(", "<", "{", "[", "/", "./", "http://", "https://"} {
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
		case key != "" && (parent == "data" || parent == "stringData") && len(parents) >= 3 && kubeSecretValue(s):
			// (deeper than komando's own envelope "data", which is at depth 1)
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
	b, err := base64.StdEncoding.DecodeString(s)
	// a Secret holds text (passwords, tokens) or keys and certificates;
	// a word that merely parses as base64 decodes to bytes that are neither
	return err == nil && (utf8.Valid(b) || len(b) >= 32)
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

// View is a text as output for an AI agent shows it (Printer.Redact), with
// the place of every hidden value in the original text. A command that
// edits what the agent saw (fs replace) works on Text and maps its edits
// back with Source, so neither its result nor its errors depend on a value
// the agent never saw.
type View struct {
	Text  string
	marks []mark // in Text order, never overlapping
}

// mark: Text[vs:ve] is the label that stands for original[ss:se].
type mark struct{ vs, ve, ss, se int }

// View hides in s what Redact hides, keeping track of where each value was.
func (p *Printer) View(s string) View {
	v := View{Text: s}
	if p.NoRedact {
		return v
	}
	p.load()
	for _, h := range p.hide {
		v.hide(literal(v.Text, h.raw), h.label)
	}
	if !p.Mask {
		return v
	}
	// the passes and filters of MaskSecrets, in its order
	v.hide(groups(pemKey, v.Text, 0, nil), "[hidden: private key]")
	v.hide(groups(pemBody, v.Text, 0, nil), "[hidden: private key]")
	v.hide(groups(urlPw, v.Text, 2, nil), Hidden)
	v.hide(groups(bearer, v.Text, 3, nil), Hidden)
	v.hide(groups(assign, v.Text, 3, func(sub []string) bool {
		return !(sub[2] == ":" && strings.EqualFold(sub[1], "secret") || keepValue(sub[1], sub[3]))
	}), Hidden)
	v.hide(redisValues(redisPw, v.Text), Hidden)
	v.hide(redisValues(redisPwPair, v.Text), Hidden)
	v.hide(redisACLValues(v.Text), Hidden)
	v.hide(groups(tokens, v.Text, 0, nil), Hidden)
	v.hide(groups(pwHash, v.Text, 0, nil), Hidden)
	return v
}

// redisValues: where maskRedis hides a value matched by re (group 2,
// inside its quotes), for View.
func redisValues(re *regexp.Regexp, s string) [][2]int {
	var at [][2]int
	for _, m := range re.FindAllStringSubmatchIndex(s, -1) {
		a, b := m[4], m[5]
		if b-a >= 2 && (s[a] == '"' || s[a] == '\'') && s[b-1] == s[a] {
			a, b = a+1, b-1
		}
		if a == b || keepValue("password", s[a:b]) {
			continue
		}
		at = append(at, [2]int{a, b})
	}
	return at
}

// redisACLValues: where maskRedis hides the passwords and hashes of Redis
// ACL rules (after > < # or !), for View.
func redisACLValues(s string) [][2]int {
	var at [][2]int
	for _, line := range redisACL.FindAllStringIndex(s, -1) {
		for _, m := range redisACLPass.FindAllStringSubmatchIndex(s[line[0]:line[1]], -1) {
			start := m[5] // after > or <
			if m[4] < 0 {
				start = m[9] // after # or !
			}
			at = append(at, [2]int{line[0] + start, line[0] + m[1]})
		}
	}
	return at
}

// literal: where sub occurs in s (not overlapping, left to right).
func literal(s, sub string) [][2]int {
	var at [][2]int
	for i := 0; sub != ""; {
		j := strings.Index(s[i:], sub)
		if j < 0 {
			break
		}
		at = append(at, [2]int{i + j, i + j + len(sub)})
		i += j + len(sub)
	}
	return at
}

// groups: where group g of re matches in s, for the matches keep accepts.
func groups(re *regexp.Regexp, s string, g int, keep func(sub []string) bool) [][2]int {
	var at [][2]int
	for _, m := range re.FindAllStringSubmatchIndex(s, -1) {
		if m[2*g] < 0 {
			continue
		}
		if keep != nil {
			sub := make([]string, len(m)/2)
			for i := range sub {
				if m[2*i] >= 0 {
					sub[i] = s[m[2*i]:m[2*i+1]]
				}
			}
			if !keep(sub) {
				continue
			}
		}
		at = append(at, [2]int{m[2*g], m[2*g+1]})
	}
	return at
}

// hide puts label in place of each range of Text (in order, not
// overlapping). A range that cuts into a label already there takes it in
// whole, so every label still stands for one stretch of the original.
func (v *View) hide(at [][2]int, label string) {
	var rs [][2]int
	for _, r := range at {
		for _, m := range v.marks {
			if m.vs < r[0] && r[0] < m.ve {
				r[0] = m.vs
			}
			if m.vs < r[1] && r[1] < m.ve {
				r[1] = m.ve
			}
		}
		if n := len(rs); n > 0 && r[0] < rs[n-1][1] {
			rs[n-1][1] = max(rs[n-1][1], r[1])
			continue
		}
		rs = append(rs, r)
	}
	if len(rs) == 0 {
		return
	}
	var b strings.Builder
	var marks []mark
	last, delta, k := 0, 0, 0 // in Text; new minus old position; next old mark
	for _, r := range rs {
		for ; k < len(v.marks) && v.marks[k].vs < r[0]; k++ {
			m := v.marks[k]
			marks = append(marks, mark{m.vs + delta, m.ve + delta, m.ss, m.se})
		}
		for k < len(v.marks) && v.marks[k].vs < r[1] {
			k++ // taken into the new label
		}
		ss, _ := v.source(r[0], true)
		se, _ := v.source(r[1], false)
		marks = append(marks, mark{r[0] + delta, r[0] + delta + len(label), ss, se})
		b.WriteString(v.Text[last:r[0]])
		b.WriteString(label)
		last = r[1]
		delta += len(label) - (r[1] - r[0])
	}
	for ; k < len(v.marks); k++ {
		m := v.marks[k]
		marks = append(marks, mark{m.vs + delta, m.ve + delta, m.ss, m.se})
	}
	b.WriteString(v.Text[last:])
	v.Text, v.marks = b.String(), marks
}

// source maps a position in Text to the original. Inside a label it is
// the label's start (start true) or end, and ok is false.
func (v View) source(x int, start bool) (int, bool) {
	d := 0 // original minus Text position, up to x
	for _, m := range v.marks {
		switch {
		case x <= m.vs:
			return x + d, true
		case x < m.ve:
			if start {
				return m.ss, false
			}
			return m.se, false
		}
		d = m.se - m.ve
	}
	return x + d, true
}

// Hidden returns the values of orig (the text v was made from) that v
// shows as labels, in order.
func (v View) Hidden(orig string) []string {
	vals := make([]string, 0, len(v.marks))
	for _, m := range v.marks {
		vals = append(vals, orig[m.ss:m.se])
	}
	return vals
}

// Masked reports whether v hides a value the agent does not know by name:
// a label other than a vault value's [secret:NAME].
func (v View) Masked() bool {
	for _, m := range v.marks {
		if !strings.HasPrefix(v.Text[m.vs:m.ve], "[secret:") {
			return true
		}
	}
	return false
}

// Source maps Text[a:b] to the stretch of the original it shows. ok is
// false when a or b falls inside a label: the edit would cut a hidden value.
func (v View) Source(a, b int) (start, end int, ok bool) {
	start, ok1 := v.source(a, true)
	end, ok2 := v.source(b, false)
	return start, end, ok1 && ok2
}
