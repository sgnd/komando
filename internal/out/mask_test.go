package out

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestMaskSecretsText(t *testing.T) {
	cases := []struct{ in, want string }{
		{"DB_PASSWORD=hunter2\nDB_HOST=db1", "DB_PASSWORD=[hidden]\nDB_HOST=db1"},
		{"export API_KEY='abc123def'", "export API_KEY='[hidden]'"},
		{"password: s3cret", "password: [hidden]"},
		{`{"client_secret": "xyz789"}`, `{"client_secret": "[hidden]"}`},
		{"postgres://app:pa55word@db:5432/shop", "postgres://app:[hidden]@db:5432/shop"},
		{"Authorization: Bearer abcdefghijklmnop", "Authorization: Bearer [hidden]"},
		{"token ghp_abcdefghijklmnopqrstuvwxyz0123456789", "token [hidden]"},
		{"key AKIAABCDEFGHIJKLMNOP here", "key [hidden] here"},
		{"root:$6$saltsalt$abcdefghijklmnop:19000:0", "root:[hidden]:19000:0"},
		{"-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaA\n-----END OPENSSH PRIVATE KEY-----\nnext", "[hidden: private key]\nnext"},
		// left alone: references, booleans, ordinary words
		{"password_ref: secret:db", "password_ref: secret:db"},
		{"PASSWORD=${DB_PASS}", "PASSWORD=${DB_PASS}"},
		{"require_password: true", "require_password: true"},
		{"host: web1 user: deploy", "host: web1 user: deploy"},
		{"DB_PASSWORD=[hidden]", "DB_PASSWORD=[hidden]"},
		// settings that only name a secret, and values that are structure
		{"max_tokens: 4096", "max_tokens: 4096"},
		{"password_min_length=12", "password_min_length=12"},
		{"token_endpoint: https://auth.example.com/oauth/token\nnext_line_here=1", "token_endpoint: https://auth.example.com/oauth/token\nnext_line_here=1"},
		{"valueFrom: {secretKeyRef: {name: db, key: password}}", "valueFrom: {secretKeyRef: {name: db, key: password}}"},
		{"api_key_file: /run/secrets/api", "api_key_file: /run/secrets/api"},
		{"DB_PASSWORD=12345678", "DB_PASSWORD=[hidden]"},
		{"login ok token=abc123xyz", "login ok token=[hidden]"},
		// Redis config: a space between name and value
		{"port 6379\nrequirepass s3cretpw\nmasterauth s3cretpw\n", "port 6379\nrequirepass [hidden]\nmasterauth [hidden]\n"},
		{"  primaryauth \"two words\"", "  primaryauth \"[hidden]\""},
		{"tls-key-file-pass 'kp1'\nTLS-CLIENT-KEY-FILE-PASS kp2", "tls-key-file-pass '[hidden]'\nTLS-CLIENT-KEY-FILE-PASS [hidden]"},
		{"sentinel auth-pass mymaster s3cretpw\nsentinel sentinel-pass s3ntinel", "sentinel auth-pass mymaster [hidden]\nsentinel sentinel-pass [hidden]"},
		// grep -H, -n and -C output
		{"/etc/redis/redis.conf:12:requirepass s3cretpw\n/etc/redis/redis.conf-13-masterauth s3cretpw", "/etc/redis/redis.conf:12:requirepass [hidden]\n/etc/redis/redis.conf-13-masterauth [hidden]"},
		{"users.acl:user worker on >s3cretpw ~*", "users.acl:user worker on >[hidden] ~*"},
		{"my-requirepass s3cretpw", "my-requirepass s3cretpw"},
		// redis-cli CONFIG GET, numbered and raw
		{"1) \"requirepass\"\n2) \"s3cretpw\"\n", "1) \"requirepass\"\n2) \"[hidden]\"\n"},
		{"masterauth\ns3cretpw\nmaxmemory\n0\n", "masterauth\n[hidden]\nmaxmemory\n0\n"},
		{"1) \"requirepass\"\n2) \"\"\n", "1) \"requirepass\"\n2) \"\"\n"},
		// Redis ACL rules: plaintext passwords and hashes
		{"user worker on >s3cretpw <oldpw ~jobs:* +@list", "user worker on >[hidden] <[hidden] ~jobs:* +@list"},
		{"1) \"user alice on #0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef ~* &* +@all\"", "1) \"user alice on #[hidden] ~* &* +@all\""},
		{"user default on nopass ~* +@all", "user default on nopass ~* +@all"},
		// left alone: comments, references, names in prose
		{"# requirepass foobared", "# requirepass foobared"},
		{"requirepass {{secret:REDIS_PW}}", "requirepass {{secret:REDIS_PW}}"},
		{"requirepass [hidden]", "requirepass [hidden]"},
		{"set requirepass to protect the server", "set requirepass to protect the server"},
	}
	for _, c := range cases {
		if got := MaskSecrets(c.in); got != c.want {
			t.Errorf("MaskSecrets(%q)\n got %q\nwant %q", c.in, got, c.want)
		}
	}
}

func TestMaskJSONStaysValid(t *testing.T) {
	in := `{"ok":true,"data":{"stdout":"DB_PASSWORD=hunter2\nX=1","rows":[{"user":"a","password":"h4sh","login_count":3}],` +
		`"secret":{"data":{"tls.key":"c2VjcmV0dmFsdWU=","note":"plain words"}},"password_ref":"secret:db","token_count":5}}`
	got := maskJSON([]byte(in))
	var v map[string]any
	if err := json.Unmarshal(got, &v); err != nil {
		t.Fatalf("masked JSON is invalid: %v\n%s", err, got)
	}
	s := string(got)
	for _, leak := range []string{"hunter2", "h4sh", "c2VjcmV0dmFsdWU="} {
		if strings.Contains(s, leak) {
			t.Errorf("%q leaked: %s", leak, s)
		}
	}
	for _, keep := range []string{`"login_count":3`, `"secret:db"`, `"token_count":5`, `"plain words"`, `X=1`} {
		if !strings.Contains(s, keep) {
			t.Errorf("%q should stay: %s", keep, s)
		}
	}
}

func TestPrinterMaskOnlyWhenAsked(t *testing.T) {
	p := &Printer{}
	if p.Redact("PASSWORD=abc123") != "PASSWORD=abc123" {
		t.Error("people and scripts see what the server sent")
	}
	p.Mask = true
	if p.Redact("PASSWORD=abc123") != "PASSWORD=[hidden]" {
		t.Error("agents see [hidden]")
	}
}

func TestVaultValueEncodings(t *testing.T) {
	p := &Printer{Secrets: func() map[string]string { return map[string]string{"db": "pa ss/word"} }}
	if got := p.Redact("cGEgc3Mvd29yZA== and pa+ss%2Fword"); got != "[secret:db] and [secret:db]" {
		t.Errorf("got %q", got)
	}
}

func TestHasHidden(t *testing.T) {
	for s, want := range map[string]bool{"A=[hidden]": true, "A=[secret:db]": true, "[hidden: private key]": true, "A=1": false, "[secret]": false} {
		if HasHidden(s) != want {
			t.Errorf("HasHidden(%q) = %v", s, !want)
		}
	}
}

func TestSafeText(t *testing.T) {
	for in, want := range map[string]string{
		"plain\ttext\n":            "plain\ttext\n",
		"\x1b[31mred\x1b[0m":       "\x1b[31mred\x1b[0m",
		"x\x1b]52;c;ZXZpbA==\x07y": `x\e]52;c;ZXZpbA==\x07y`,
		"a\x1b[2Jb":                `a\e[2Jb`,
		"bell\x07 nul\x00 del\x7f": `bell\x07 nul\x00 del\x7f`,
		"ünï 日本":                   "ünï 日本",
	} {
		if got := SafeText(in); got != want {
			t.Errorf("SafeText(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestMaskKeepsPublicKeysAndEnvelope(t *testing.T) {
	in := `{"ok":true,"data":{"name":"deploy","public_key":"ssh-ed25519 AAAAC3Nz komando-deploy","fingerprint":"SHA256:abc","format":"markdown","ordering_key":"customer-42"}}`
	if got := string(maskJSON([]byte(in))); got != in {
		t.Errorf("changed:\n%s", got)
	}
	secret := `{"data":{"object":{"kind":"Secret","data":{"password":"aHVudGVyMg==","note":"bWFya2Rvd24="}}}}`
	if got := string(maskJSON([]byte(secret))); strings.Contains(got, "aHVudGVyMg==") || strings.Contains(got, "bWFya2Rvd24=") {
		t.Errorf("Kubernetes Secret values leaked: %s", got)
	}
}
