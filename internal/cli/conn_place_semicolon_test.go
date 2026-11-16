package cli

import (
	"slices"
	"testing"
)

// A setting joined with ';' (the MongoDB driver reads ';' as a separator)
// is part of where the login goes, like one joined with '&': url.Query
// drops such pairs, so an agent could turn off certificate checks unseen.
func TestConnURLSettingsReadsSemicolons(t *testing.T) {
	got := connURLSettings("mongodb://app@db1.example:27017/app?tls=true&tlsInsecure=true;tlsCAFile=/agent/ca.pem;replicaSet=rs0")
	for _, want := range []string{"tls=true", "tlsInsecure=true", "tlsCAFile=/agent/ca.pem", "replicaSet=rs0"} {
		if !slices.Contains(got, want) {
			t.Errorf("missing %s in %v", want, got)
		}
	}
	if a, b := connURLSettings("mongodb://h/app?tls=true"), connURLSettings("mongodb://h/app?tls=true;tlsInsecure=true"); slices.Equal(a, b) {
		t.Errorf("a ';' setting does not change the place: %v", b)
	}
	// the few settings that move nothing still do not count
	if got := connURLSettings("postgres://h/db?application_name=x;connect_timeout=5"); len(got) != 0 {
		t.Errorf("safe settings counted: %v", got)
	}
}
