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
