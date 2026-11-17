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

// komando rates the file it reads, so a file that pulls in another one,
// or leaves a risky field to a variable, counts as one it cannot check.
func TestComposeEscapesFailsClosed(t *testing.T) {
	for name, c := range map[string]struct {
		yaml string
		esc  bool
	}{
		"include":           {"include: [other.yml]\nservices:\n  web: {image: nginx}\n", true},
		"include long form": {"include:\n  - path: other.yml\n", true},
		"extends file":      {"services:\n  web:\n    extends: {file: base.yml, service: web}\n", true},
		"extends same file": {"services:\n  base: {image: nginx}\n  web:\n    extends: {service: base}\n", false},
		"privileged var":    {"services:\n  web:\n    image: nginx\n    privileged: ${PRIV}\n", true},
		"privileged false":  {"services:\n  web:\n    image: nginx\n    privileged: false\n", false},
		"image var":         {"services:\n  web:\n    image: nginx:${TAG}\n", false},
	} {
		if why := composeEscapes([]byte(c.yaml)); (why != "") != c.esc {
			t.Errorf("%s: %q, want escapes=%v", name, why, c.esc)
		}
	}
}

// Review round: the glued -cFILE form, compose's override files and a
// COMPOSE_FILE in the folder's .env.
func TestComposeFilesReviewRound(t *testing.T) {
	if got := serverComposeFiles(strings.Fields("stack deploy -c/srv/evil.yml st")); !reflect.DeepEqual(got, [][]string{{"/srv/evil.yml"}}) {
		t.Errorf("glued -c: %v", got)
	}
	plain := "services:\n  web: {image: nginx}\n"
	for name, c := range map[string]struct {
		files map[string]string
		bad   bool
	}{
		"plain":               {map[string]string{"/a/compose.yaml": plain}, false},
		"override privileged": {map[string]string{"/a/compose.yaml": plain, "/a/compose.override.yaml": "services:\n  web: {privileged: true}\n"}, true},
		"env COMPOSE_FILE":    {map[string]string{"/a/compose.yaml": plain, "/a/.env": "TAG=1\nCOMPOSE_FILE=evil.yml\n"}, true},
		"env plain":           {map[string]string{"/a/compose.yaml": plain, "/a/.env": "TAG=1\n"}, false},
	} {
		read := func(p string) ([]byte, error) {
			if b, ok := c.files[p]; ok {
				return []byte(b), nil
			}
			return nil, os.ErrNotExist
		}
		if why := composeFilesRisk(read, [][]string{composeDefaultNames("/a")}); (why != "") != c.bad {
			t.Errorf("%s: %q, want bad=%v", name, why, c.bad)
		}
	}
}

// Second review: --env-file, the forms of COMPOSE_FILE compose reads, and
// docker raw compose without the server's COMPOSE_FILE.
func TestComposeEnvForms(t *testing.T) {
	plain := "services:\n  web: {image: nginx}\n"
	for _, env := range []string{"COMPOSE_FILE = evil.yml\n", "COMPOSE_FILE: evil.yml\n", "export\tCOMPOSE_FILE=evil.yml\n"} {
		files := map[string]string{"/a/compose.yaml": plain, "/a/.env": env}
		read := func(p string) ([]byte, error) {
			if b, ok := files[p]; ok {
				return []byte(b), nil
			}
			return nil, os.ErrNotExist
		}
		if composeFilesRisk(read, [][]string{composeDefaultNames("/a")}) == "" {
			t.Errorf("%q in .env passed", env)
		}
	}
	files := map[string]string{"compose.yaml": plain, "x.env": "COMPOSE_FILE=evil.yml\n"}
	read := func(p string) ([]byte, error) {
		if b, ok := files[p]; ok {
			return []byte(b), nil
		}
		return nil, os.ErrNotExist
	}
	if composeFilesRisk(read, serverComposeFiles(strings.Fields("compose --env-file x.env up"))) == "" {
		t.Error("--env-file x.env with COMPOSE_FILE passed")
	}
	if !strings.HasPrefix(dockerLine(strings.Fields("compose up -d")), "env -u COMPOSE_FILE") || strings.HasPrefix(dockerLine([]string{"ps"}), "env") {
		t.Errorf("dockerLine: %q / %q", dockerLine(strings.Fields("compose up -d")), dockerLine([]string{"ps"}))
	}
}
