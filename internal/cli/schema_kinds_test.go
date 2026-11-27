package cli

import (
	"encoding/json"
	"slices"
	"testing"

	"github.com/sgnd/komando/internal/driver"
)

// schemaAddKinds is the add_kinds list of `komando schema PATH...`.
func schemaAddKinds[T any](t *testing.T, path ...string) (kinds []T, flags []string) {
	t.Helper()
	invHome(t)
	d := mustRun(t, append([]string{"schema"}, path...)...)
	cmds, _ := d["commands"].([]any)
	if len(cmds) != 1 {
		t.Fatalf("schema %v: %d commands", path, len(cmds))
	}
	c := cmds[0].(map[string]any)
	for _, f := range c["flags"].([]any) {
		flags = append(flags, f.(map[string]any)["name"].(string))
	}
	b, _ := json.Marshal(c["add_kinds"])
	if err := json.Unmarshal(b, &kinds); err != nil || len(kinds) == 0 {
		t.Fatalf("schema %v: no add_kinds (%v): %s", path, err, b)
	}
	return kinds, flags
}

// kindFlags are the flags a kind lists, all together.
func kindFlags(required []string, oneOf [][]string, optional []string) []string {
	res := slices.Clone(required)
	for _, g := range oneOf {
		res = append(res, g...)
	}
	return append(res, optional...)
}

// `komando schema conn add` lists every conn kind with its URL schemes
// and the flags conn add takes for it; db add, cache add and the other
// family adds list their own kinds only.
func TestSchemaConnAddKinds(t *testing.T) {
	kinds, flags := schemaAddKinds[connKindSchema](t, "conn", "add")
	var ids []string
	for _, k := range kinds {
		ids = append(ids, k.ID)
		d, ok := driver.Lookup(k.ID)
		if !ok || k.Family != d.Family || !slices.Equal(k.URLSchemes, d.Schemes) || k.DisplayName == "" {
			t.Errorf("%s: %+v", k.ID, k)
		}
		if tg, err := driver.Parse(k.URLExample); err != nil || tg.Kind.Name != k.ID {
			t.Errorf("%s: url_example %q is not a %s URL: %v", k.ID, k.URLExample, k.ID, err)
		}
		for _, f := range kindFlags(k.Required, k.OneOf, k.Optional) {
			if !slices.Contains(flags, f) {
				t.Errorf("%s lists --%s, which conn add does not have", k.ID, f)
			}
		}
		if slices.Contains(k.Optional, "via") == k.File {
			t.Errorf("%s: a file kind takes no --via, others do: %v", k.ID, k.Optional)
		}
	}
	var want []string
	for _, k := range driver.Kinds() {
		want = append(want, k.Name)
	}
	if !slices.Equal(ids, want) {
		t.Errorf("add_kinds %v, conn add accepts %v", ids, want)
	}
	wantCode(t, "USAGE", "conn", "add", "local", "sqlite:///var/lib/app.db", "--via", "web1")

	for family := range connAddKinds {
		if slices.Contains(movedTypes, family) {
			continue // its adds are per provider, from the table
		}
		kinds, _ := schemaAddKinds[connKindSchema](t, family, "add")
		for _, k := range kinds {
			if k.Family != family {
				t.Errorf("%s add lists %s, a %s kind", family, k.ID, k.Family)
			}
			if need := k.ID == "k8s"; slices.Contains(k.Required, "password-ref") != need || slices.Contains(k.Optional, "ask-password") == need {
				t.Errorf("%s add, %s: required %v optional %v", family, k.ID, k.Required, k.Optional)
			}
		}
	}
	wantCode(t, "USAGE", "cluster", "kubernetes", "add", "prod-k8s", "k8s://api.cluster.example:6443")
}
