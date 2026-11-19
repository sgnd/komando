package cli

import (
	"encoding/json"
	"testing"
)

func TestImagePatch(t *testing.T) {
	p, err := imagePatch(`a"b`, `ghcr.io/acme/api:1.4.3","x":"y`)
	if err != nil {
		t.Fatal(err)
	}
	var o struct {
		Spec struct {
			Template struct {
				Spec struct {
					Containers []map[string]string `json:"containers"`
				} `json:"spec"`
			} `json:"template"`
		} `json:"spec"`
	}
	if err := json.Unmarshal([]byte(p), &o); err != nil {
		t.Fatalf("%s: %v", p, err)
	}
	cs := o.Spec.Template.Spec.Containers
	if len(cs) != 1 || len(cs[0]) != 2 || cs[0]["name"] != `a"b` || cs[0]["image"] != `ghcr.io/acme/api:1.4.3","x":"y` {
		t.Errorf("patch: %s", p)
	}
	for _, bad := range []string{"", "nginx\x00", "nginx:1\n", "ngi nx", "nginx\xff", "nginx\u202e", "nginx\x1b[2J"} {
		if err := validImage(bad); err == nil {
			t.Errorf("%q passed as an image name", bad)
		}
	}
	if err := validImage("registry.example.com:5000/a/b@sha256:0123abcd"); err != nil {
		t.Error(err)
	}
}
