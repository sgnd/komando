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
