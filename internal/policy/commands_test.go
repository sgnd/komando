package policy

import (
	"slices"
	"testing"
)

func TestDockerRuns(t *testing.T) {
	tests := []struct {
		name, cmd string
		args      []string
		dir       string
		known     bool
	}{
		{"login folder", "docker compose up -d", []string{"compose", "up", "-d"}, "", true},
		{"after cd", "cd /srv/app && docker compose up -d", []string{"compose", "up", "-d"}, "/srv/app", true},
		{"relative cd", "cd app; docker compose up", []string{"compose", "up"}, "app", true},
		{"two cds", "cd /srv && cd app && sudo docker compose up", []string{"compose", "up"}, "/srv/app", true},
		{"docker-compose", "cd /srv/app && docker-compose -f prod.yml up -d", []string{"compose", "-f", "prod.yml", "up", "-d"}, "/srv/app", true},
		{"in sh -c", `cd /srv/app && sh -c 'docker compose up -d'`, []string{"compose", "up", "-d"}, "/srv/app", true},
		{"cd to a variable", `cd "$APP" && docker compose up -d`, []string{"compose", "up", "-d"}, "", false},
		{"cd home of a user", "cd ~deploy && docker compose up -d", []string{"compose", "up", "-d"}, "", false},
		{"subshell", "(cd /tmp) ; docker compose up -d", []string{"compose", "up", "-d"}, "", false}, // Dir is not used when not known
		{"compose file from env", "COMPOSE_FILE=x.yml docker compose up -d", []string{"compose", "up", "-d"}, "", false},
		{"cd back home", "cd /srv && cd && docker compose up", []string{"compose", "up"}, "", true},
		// komando clears the compose settings so docker reads only the files the guard read
		{"komando's stack line", "env -u COMPOSE_FILE -u COMPOSE_PATH_SEPARATOR docker 'stack' 'deploy' '-c' '/tmp/ok.yml' 'ok'", []string{"stack", "deploy", "-c", "/tmp/ok.yml", "ok"}, "", true},
		{"komando's compose line", "cd '/srv/shop' && env -u COMPOSE_FILE -u COMPOSE_PATH_SEPARATOR docker compose 'up' '-d' 2>&1", []string{"compose", "up", "-d"}, "/srv/shop", true},
		{"env --unset", "env --unset=COMPOSE_FILE --unset COMPOSE_PROFILES -uCOMPOSE_ENV_FILES docker compose up", []string{"compose", "up"}, "", true},
		{"unset", "unset COMPOSE_FILE COMPOSE_PROFILES; docker compose up", []string{"compose", "up"}, "", true},
		{"export a setting", "export COMPOSE_FILE=x.yml; docker compose up", []string{"compose", "up"}, "", false},
		{"env sets one", "env COMPOSE_FILE=x.yml docker compose up", []string{"compose", "up"}, "", false},
		{"clears one, sets another", "env -u COMPOSE_FILE COMPOSE_PROFILES=a docker compose up", []string{"compose", "up"}, "", false},
		{"quoted name", "env -u 'COMPOSE_FILE' docker compose up", []string{"compose", "up"}, "", false},
		{"not a whole name", "env -u COMPOSE_FILE=x docker compose up", []string{"compose", "up"}, "", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			runs := DockerRuns(tt.cmd)
			if len(runs) != 1 {
				t.Fatalf("DockerRuns(%q) = %d runs, want 1: %+v", tt.cmd, len(runs), runs)
			}
			r := runs[0]
			if !slices.Equal(r.Args, tt.args) || r.DirKnown != tt.known || tt.known && r.Dir != tt.dir {
				t.Errorf("DockerRuns(%q) = %+v, want args %q dir %q known %v", tt.cmd, r, tt.args, tt.dir, tt.known)
			}
		})
	}
	if runs := DockerRuns("ls /srv && echo docker compose up"); len(runs) != 0 {
		t.Errorf("no docker command: got %+v", runs)
	}
}
