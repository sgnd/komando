package cli

import (
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/sgnd/komando/internal/policy"
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

// Exec text that starts containers from a compose file reads the file
// from the folder the text cd'd into, as `komando docker compose --dir`
// does; a folder komando cannot tell stops the command.
func TestExecComposeFiles(t *testing.T) {
	cases := []struct {
		cmd  string
		want [][]string
	}{
		{"docker compose up -d", [][]string{composeDefaultNames("")}},
		{"cd /srv/app && docker compose up -d", [][]string{composeDefaultNames("/srv/app")}},
		{"cd /srv/app && docker compose -f prod.yml up -d", [][]string{{"/srv/app/prod.yml"}}},
		{"cd /srv/app && docker compose --file=/etc/x.yml up", [][]string{{"/etc/x.yml"}}},
		{"cd /srv && docker compose --project-directory app up", [][]string{composeDefaultNames("/srv/app")}},
		{"cd /srv/app && docker-compose up -d", [][]string{composeDefaultNames("/srv/app")}},
		{"cd /srv/app && docker stack deploy -c stack.yml app", [][]string{{"/srv/app/stack.yml"}}},
		{"cd /srv/app && docker compose ps", nil},
	}
	for _, c := range cases {
		var got [][]string
		for _, r := range execComposeRuns(c.cmd) {
			got = append(got, serverComposeFiles(r)...)
		}
		if !reflect.DeepEqual(got, c.want) {
			t.Errorf("%s: got %v, want %v", c.cmd, got, c.want)
		}
	}
	for _, cmd := range []string{`cd "$APP" && docker compose up -d`, "(cd /tmp) ; docker compose up -d", "COMPOSE_FILE=x.yml docker compose up -d"} {
		if why := execComposeReason(nil, nil, nil, cmd); !strings.Contains(why, "cannot check") {
			t.Errorf("%s: want a stop for an unknown folder, got %q", cmd, why)
		}
	}
	if why := execComposeReason(nil, nil, nil, `cd "$APP" && docker compose ps`); why != "" {
		t.Errorf("a compose read needs no file: %q", why)
	}
}

// komando's own docker line clears the server's compose settings; the
// guard still reads its compose file from a folder it can tell.
func TestDockerLineFolderKnown(t *testing.T) {
	runs := policy.DockerRuns(dockerLine([]string{"stack", "deploy", "-c", "/tmp/ok.yml", "ok"}))
	if len(runs) != 1 || !runs[0].DirKnown || !reflect.DeepEqual(execComposeRuns(dockerLine([]string{"stack", "deploy", "-c", "/tmp/ok.yml", "ok"})), [][]string{{"stack", "deploy", "-c", "/tmp/ok.yml", "ok"}}) {
		t.Errorf("dockerLine: %+v", runs)
	}
}

// The lab's stack files at unit level: a `cluster run` or `docker raw`
// stack deploy line, as komando builds it, reads its file and rates it. A
// plain file stays a write; a privileged, missing or unreadable file, or
// one from standard input, stops.
func TestDockerLineStackFileRated(t *testing.T) {
	files := map[string]string{
		"/tmp/ok.yml":   "services:\n  web:\n    image: nginx\n",
		"/tmp/priv.yml": "services:\n  web:\n    image: nginx\n    privileged: true\n",
	}
	read := func(p string) ([]byte, error) {
		if p == "/tmp/locked.yml" {
			return nil, os.ErrPermission
		}
		if b, ok := files[p]; ok {
			return []byte(b), nil
		}
		return nil, os.ErrNotExist
	}
	for file, bad := range map[string]bool{"/tmp/ok.yml": false, "/tmp/priv.yml": true, "/tmp/none.yml": true, "/tmp/locked.yml": true, "-": true} {
		runs := execComposeRuns(dockerLine([]string{"stack", "deploy", "-c", file, "app"}))
		if len(runs) != 1 {
			t.Fatalf("%s: runs %v", file, runs)
		}
		if why := composeFilesRisk(read, serverComposeFiles(runs[0])); (why != "") != bad {
			t.Errorf("%s: got %q, want a stop %v", file, why, bad)
		}
	}
}
