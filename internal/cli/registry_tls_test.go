package cli

import (
	"crypto/x509"
	"fmt"
	"strings"
	"testing"

	"github.com/sgnd/komando/internal/driver"
	"github.com/sgnd/komando/internal/registry"
)

// A refused certificate says so (not "unreachable") and points at ca= first.
func TestRegistryCertErrors(t *testing.T) {
	e := toErr(registryErr(fmt.Errorf("Get https://r/v2/: %w", x509.UnknownAuthorityError{})))
	if e.Code != "REGISTRY_TLS" || !strings.Contains(e.Hint, "?ca=secret:NAME") ||
		strings.Index(e.Hint, "ca=") > strings.Index(e.Hint, "skip-verify") {
		t.Errorf("unknown CA: %+v", e)
	}
	e = toErr(registryErr(fmt.Errorf("x: %w", x509.HostnameError{Host: "r"})))
	if e.Code != "REGISTRY_TLS" || strings.Contains(e.Hint, "skip-verify") {
		t.Errorf("wrong name: %+v", e)
	}
	if e := toErr(registryErr(fmt.Errorf("dial tcp: connection refused"))); e.Code != "CONN_UNREACHABLE" {
		t.Errorf("refused: %+v", e)
	}
}

func TestRegistryTLSOptions(t *testing.T) {
	setHome(t, t.TempDir())
	t.Setenv("KOMANDO_VAULT_PASS", "a passphrase long enough for tests")
	tg, _ := driver.Parse("registry://me@r.lan?tls=skip-verify")
	if tc, err := registryTLS(tg); err != nil || !tc.SkipVerify || tc.Plain {
		t.Errorf("skip-verify: %+v %v", tc, err)
	}
	tg, _ = driver.Parse("registry://me@r.lan?ca=secret:nope")
	if _, err := registryTLS(tg); toErr(err).Code != "SECRET_NOT_FOUND" {
		t.Errorf("missing CA secret: %v", err)
	}
}

// A 404 says which is missing (C79): a tag (MANIFEST_UNKNOWN, or a bare
// 404 to a manifest or blob request) or the repository (NAME_UNKNOWN, or
// a bare 404 elsewhere).
func TestRegistryNotFoundSays(t *testing.T) {
	for _, c := range []struct {
		e    registry.Error
		want string
	}{
		{registry.Error{Status: 404, Code: "MANIFEST_UNKNOWN"}, "IMAGE_TAG_NOT_FOUND"},
		{registry.Error{Status: 404, Code: "Not Found", Manifest: true}, "IMAGE_TAG_NOT_FOUND"},
		{registry.Error{Status: 404, Code: "NAME_UNKNOWN", Manifest: true}, "REPOSITORY_NOT_FOUND"},
		{registry.Error{Status: 404, Code: "Not Found"}, "REPOSITORY_NOT_FOUND"},
	} {
		e := c.e
		if got := toErr(registryErr(&e)); got.Code != c.want {
			t.Errorf("%+v: %s, want %s", c.e, got.Code, c.want)
		}
	}
}
