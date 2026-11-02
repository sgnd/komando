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

// The external refs run a CLI; a fake one on PATH shows the plumbing.
func TestExternalRefs(t *testing.T) {
	dir := t.TempDir()
	fake := func(name, body string) {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("#!/bin/sh\n"+body+"\n"), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	fake("op", `printf "op:%s" "$3"`)
	fake("aws", `echo '{"password":"pw-from-aws","user":"u"}'`)
	fake("vault", `echo "$3 $4"`)
	fake("gcloud", `echo "$5 $6"`)
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	cases := map[string]string{
		"op://Shop/db/password":         "op:op://Shop/db/password",
		"aws-sm:shop/db#password":       "pw-from-aws",
		"vault:secret/shop#db_password": "-field=db_password secret/shop",
		"gcp-sm:db-pass@my-proj":        "--secret=db-pass --project=my-proj",
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
	if _, err := Resolve("aws-sm:shop/db#nope"); err == nil {
		t.Error("missing JSON key must fail")
	}
}
