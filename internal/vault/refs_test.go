package vault

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestValidRef(t *testing.T) {
	for _, ok := range []string{"secret:x", "env:X", "file:/x", "op://v/i/f", "vault:secret/a#b", "aws-sm:n", "gcp-sm:n@p"} {
		if !ValidRef(ok) {
			t.Errorf("%s should be valid", ok)
		}
	}
	for _, bad := range []string{"hunter2", "secret:", "op:/x", "https://x"} {
		if ValidRef(bad) {
			t.Errorf("%s should be invalid", bad)
		}
	}
}

// op:// still runs the 1Password CLI; a fake one on PATH shows the plumbing.
// vault:, aws-sm: and gcp-sm: are built in (internal/cloud has their tests).
func TestExternalRefs(t *testing.T) {
	dir := t.TempDir()
	fake := func(name, body string) {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("#!/bin/sh\n"+body+"\n"), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	fake("op", `printf "op:%s" "$3"`)
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	cases := map[string]string{
		"op://Shop/db/password": "op:op://Shop/db/password",
	}
	for ref, want := range cases {
		got, err := Resolve(ref)
		if err != nil || got != want {
			t.Errorf("%s: got %q, %v; want %q", ref, got, err, want)
		}
	}
	if _, err := Resolve("vault:secret/shop"); err == nil || !strings.Contains(err.Error(), "#FIELD") {
		t.Errorf("vault without #FIELD: %v", err)
	}
	if _, err := jsonKey(`{"password":"pw"}`, "nope"); err == nil {
		t.Error("missing JSON key must fail")
	}
	if v, err := jsonKey(`{"password":"pw"}`, "password"); err != nil || v != "pw" {
		t.Errorf("JSON key: %q %v", v, err)
	}
}
