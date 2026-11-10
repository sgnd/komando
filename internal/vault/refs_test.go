package vault

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestValidRef(t *testing.T) {
	for _, ok := range []string{"secret:x", "env:X", "file:/x", "op://v/i/f", "vault:secret/a#b", "aws-sm:n", "gcp-sm:n@p", "azure-kv:v/n"} {
		if !ValidRef(ok) {
			t.Errorf("%s should be valid", ok)
		}
	}
	for _, bad := range []string{"hunter2", "secret:", "op:/x", "https://x", "azure-kv:"} {
		if ValidRef(bad) {
			t.Errorf("%s should be invalid", bad)
		}
	}
}

// op:// is only 1Password Connect: an op program on PATH is never run.
// vault:, aws-sm:, gcp-sm: and azure-kv: are built in (internal/cloud has their tests).
func TestExternalRefs(t *testing.T) {
	dir := t.TempDir()
	ran := filepath.Join(dir, "ran")
	if err := os.WriteFile(filepath.Join(dir, "op"), []byte("#!/bin/sh\ntouch "+ran+"\necho leaked\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("OP_CONNECT_HOST", "")
	t.Setenv("OP_CONNECT_TOKEN", "")
	if _, err := Resolve("op://Shop/db/password"); err == nil || !strings.Contains(err.Error(), "1Password Connect") {
		t.Errorf("op:// without Connect: %v", err)
	}
	if _, err := os.Stat(ran); err == nil {
		t.Error("the op program was run")
	}
	if _, err := Resolve("vault:secret/shop"); err == nil || !strings.Contains(err.Error(), "#FIELD") {
		t.Errorf("vault without #FIELD: %v", err)
	}
	if _, err := Resolve("azure-kv:shop"); err == nil || !strings.Contains(err.Error(), "azure-kv:VAULT/NAME") {
		t.Errorf("azure-kv without a name: %v", err)
	}
	if _, err := Resolve("azure-kv:shop.example.com/db#password"); err == nil || !strings.Contains(err.Error(), "not a Key Vault host") {
		t.Errorf("azure-kv to another host: %v", err)
	}
	// the login hint names the vault's own cloud, where az must get a token
	t.Setenv("AZURE_TENANT_ID", "not a tenant")
	t.Setenv("AZURE_CLIENT_ID", "app")
	t.Setenv("AZURE_CLIENT_SECRET", "s")
	if _, err := Resolve("azure-kv:shop.vault.azure.cn/db-pass"); err == nil || !strings.Contains(err.Error(), "--resource https://vault.azure.cn`") {
		t.Errorf("azure-kv in the China cloud: %v", err)
	}
	if _, err := Resolve("azure-kv:shop/db-pass"); err == nil || !strings.Contains(err.Error(), "--resource https://vault.azure.net`") {
		t.Errorf("azure-kv in the public cloud: %v", err)
	}
	if _, err := jsonKey(`{"password":"pw"}`, "nope"); err == nil {
		t.Error("missing JSON key must fail")
	}
	if v, err := jsonKey(`{"password":"pw"}`, "password"); err != nil || v != "pw" {
		t.Errorf("JSON key: %q %v", v, err)
	}
}
