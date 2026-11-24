package cli

import (
	"reflect"
	"strings"
	"testing"

	"github.com/sgnd/komando/internal/policy"
)

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
