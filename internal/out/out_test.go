package out

import (
	"bytes"
	"strings"
	"testing"
)

func TestRedactHidesVaultSecrets(t *testing.T) {
	var buf bytes.Buffer
	p := &Printer{Format: "json", W: &buf, Secrets: func() map[string]string {
		return map[string]string{"db-pass": `s3cr"et!x`, "short": "abc", "api": "tok-123456"}
	}}
	p.Print("fs.cat", map[string]any{"content": "DB_PASSWORD=s3cr\"et!x\nAPI=tok-123456\nNAME=abc\n"}, nil)
	got := buf.String()
	if strings.Contains(got, "s3cr") || strings.Contains(got, "tok-123456") {
		t.Fatalf("secret leaked: %s", got)
	}
	if !strings.Contains(got, "DB_PASSWORD=[secret:db-pass]") || !strings.Contains(got, "API=[secret:api]") {
		t.Errorf("secrets not replaced by their names: %s", got)
	}
	if !strings.Contains(got, "NAME=abc") {
		t.Errorf("values shorter than %d must stay: %s", minSecret, got)
	}
	if p.Redact("x tok-123456 y") != "x [secret:api] y" {
		t.Error("text redaction")
	}
	p.NoRedact = true
	if p.Redact("tok-123456") != "tok-123456" {
		t.Error("NoRedact (secret get --reveal) must print the value")
	}
}
