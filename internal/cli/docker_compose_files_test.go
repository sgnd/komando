package cli

import (
	"os"
	"reflect"
	"strings"
	"testing"
)

// C113 (a): a compose or stack file that is already on the server is
// read there and rated as a local stack file is.
func TestServerComposeFiles(t *testing.T) {
	cases := []struct {
		args string
		want [][]string
	}{
		{"stack deploy -c /srv/x.yml app", [][]string{{"/srv/x.yml"}}},
		{"stack deploy --compose-file=/srv/a.yml -c b.yml app", [][]string{{"/srv/a.yml"}, {"b.yml"}}},
		{"compose -f /srv/c.yml up -d", [][]string{{"/srv/c.yml"}}},
		{"compose --file=/srv/c.yml -p p run web", [][]string{{"/srv/c.yml"}}},
		{"compose up -d", [][]string{composeDefaultNames("")}},
		{"compose --project-directory /srv/app up", [][]string{composeDefaultNames("/srv/app")}},
		{"-H tcp://x compose -f a.yml create", [][]string{{"a.yml"}}},
		{"compose -f a.yml ps", nil},
		{"compose -f a.yml down", nil},
		{"stack ls", nil},
		{"ps", nil},
	}
	for _, c := range cases {
		if got := serverComposeFiles(strings.Fields(c.args)); !reflect.DeepEqual(got, c.want) {
			t.Errorf("%s: got %v, want %v", c.args, got, c.want)
		}
	}
}

func TestComposeFilesRisk(t *testing.T) {
	files := map[string]string{
		"/srv/ok.yml":          "services:\n  web:\n    image: nginx\n",
		"/srv/priv.yml":        "services:\n  web:\n    image: nginx\n    privileged: true\n",
		"/srv/root.yml":        "services:\n  web:\n    image: nginx\n    volumes: [\"/:/host\"]\n",
		"/srv/app/compose.yml": "services:\n  web:\n    image: nginx\n    network_mode: host\n",
	}
	read := func(p string) ([]byte, error) {
		if b, ok := files[p]; ok {
			return []byte(b), nil
		}
		return nil, os.ErrNotExist
	}
	for _, c := range []struct {
		groups [][]string
		bad    bool
	}{
		{[][]string{{"/srv/ok.yml"}}, false},
		{[][]string{{"/srv/priv.yml"}}, true},
		{[][]string{{"/srv/ok.yml"}, {"/srv/root.yml"}}, true},
		{[][]string{composeDefaultNames("/srv/app")}, true},
		{[][]string{{"/srv/missing.yml"}}, true},
		{[][]string{{"-"}}, true},
		{nil, false},
	} {
		if why := composeFilesRisk(read, c.groups); (why != "") != c.bad {
			t.Errorf("%v: got %q, want bad=%v", c.groups, why, c.bad)
		}
	}
}

// `komando docker compose --dir D --file F` reads F in D, as compose does.
func TestComposeGuardArgs(t *testing.T) {
	for _, c := range []struct {
		dir, file string
		want      [][]string
	}{
		{"/srv/shop", "", [][]string{composeDefaultNames("/srv/shop")}},
		{"/srv/shop", "prod.yml", [][]string{{"/srv/shop/prod.yml"}}},
		{"/srv/shop", "/etc/x.yml", [][]string{{"/etc/x.yml"}}},
		{"", "x.yml", [][]string{{"x.yml"}}},
	} {
		if got := serverComposeFiles(composeGuardArgs(c.dir, c.file, []string{"up", "-d"})); !reflect.DeepEqual(got, c.want) {
			t.Errorf("%q %q: got %v, want %v", c.dir, c.file, got, c.want)
		}
	}
}
