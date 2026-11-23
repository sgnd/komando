package capability

import (
	"slices"
	"testing"
)

var wantStores = []string{"vault", "aws-sm", "gcp-sm", "azure-kv", "onepassword", "bitwarden", "keepass", "env", "file"}

// TestCredentialStores: an outside secret store is a provider under
// credential store, with the inventory verbs, and a credential points at
// an item in it instead of a typed reference string.
func TestCredentialStores(t *testing.T) {
	if got := Children("credential", "store"); !slices.Equal(got, wantStores) {
		t.Errorf("credential store providers = %v, want %v", got, wantStores)
	}
	for _, p := range wantStores {
		if got := Children("credential", "store", p); !slices.Equal(got, inventoryVerbs) {
			t.Errorf("credential store %s verbs = %v, want %v", p, got, inventoryVerbs)
		}
		for _, verb := range []string{"add", "edit"} {
			l, _ := Find(Key{Type: "credential", Provider: p, Area: "store", Verb: verb})
			if !slices.Contains(l.Stops, "RefGuard") {
				t.Errorf("credential store %s %s: RefGuard must check the store", p, verb)
			}
		}
	}
	for _, kind := range valueKinds {
		for _, verb := range []string{"add", "edit"} {
			l, _ := Find(Key{Type: "credential", Area: kind, Verb: verb})
			item, ok := l.Option("item")
			if _, store := l.Option("store"); !store || !ok || !slices.Equal(item.Needs, []string{"store"}) {
				t.Errorf("credential %s %s: wants --store and --item (item needs store)", kind, verb)
			}
			if _, typed := l.Option("ref"); typed {
				t.Errorf("credential %s %s: a typed --ref must not exist", kind, verb)
			}
			if !slices.Contains(l.Stops, "RefGuard") {
				t.Errorf("credential %s %s: RefGuard must check the item", kind, verb)
			}
		}
	}
}

// TestCARevokeIsNotRemove: revoking one signed key keeps the CA; removing
// a certificate drops it. remove must not claim to carry revoke.
func TestCARevokeIsNotRemove(t *testing.T) {
	for _, l := range All() {
		if slices.Contains(append(slices.Clone(l.Today), l.Carries...), "host.ca.revoke") {
			t.Errorf("%s: carries host.ca.revoke, a different act", l.Key)
		}
	}
	if !slices.ContainsFunc(Gones(), func(g Gone) bool { return g.Today == "host.ca.revoke" && g.Lost != "" }) {
		t.Error("host.ca.revoke: not in gone with what is lost")
	}
}

// TestReservedSecretStops: the approval code's seed is an internal record,
// not a credential, so every credential leaf, every leaf that names a
// credential (--credential, --psk-credential) and import refuse its name,
// and export leaves it out; otherwise an agent could repoint it, hand it to
// an entry, or carry it out, and compute approval codes.
func TestReservedSecretStops(t *testing.T) {
	for _, l := range All() {
		names := slices.ContainsFunc(l.Options, func(o Option) bool { return o.Kind == Credential })
		if (l.Type == "credential" || names || l.Key == top("import") || l.Key == top("export")) && !slices.Contains(l.Stops, "reservedSecret") {
			t.Errorf("%s: does not run reservedSecret", l.Key)
		}
	}
}
