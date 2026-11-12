package cli

import (
	"crypto/x509"
	"fmt"
	"strings"
	"testing"

	"github.com/sgnd/komando/internal/driver"
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
	if e := toErr(registryErr(fmt.Errorf("dial tcp: connection refused"))); e.Code != "REGISTRY_UNREACHABLE" {
		t.Errorf("refused: %+v", e)
	}
}

func TestRegistryTLSOptions(t *testing.T) {
	t.Setenv("KOMANDO_HOME", t.TempDir())
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
