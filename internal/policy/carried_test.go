package policy

import (
	"slices"
	"testing"
)

func hitIDs(cmd string) []string {
	var ids []string
	for _, h := range Check(cmd, nil) {
		ids = append(ids, h.ID)
	}
	return ids
}

// carriedCase: cmd must hit rule (when rule is set) or hit none of the
// carried rules (when rule is "").
type carriedCase struct {
	name, cmd, rule string
}

func runCarried(t *testing.T, cases []carriedCase) {
	t.Helper()
	carried := []string{"rm-files", "docker-rm", "docker-prune", "docker-kill", "docker-host", "pkg-remove",
		"pkg-remove-essential", "cron-remove", "kubectl-scale-zero", "db-drop-user"}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ids := hitIDs(c.cmd)
			if c.rule != "" && !slices.Contains(ids, c.rule) {
				t.Errorf("%q: want rule %s, got %v", c.cmd, c.rule, ids)
			}
			if c.rule == "" {
				for _, id := range ids {
					if slices.Contains(carried, id) {
						t.Errorf("%q: want none of the carried rules, got %s", c.cmd, id)
					}
				}
			}
		})
	}
}

func TestRuleRmFiles(t *testing.T) {
	runCarried(t, []carriedCase{
		{"plain rm", "rm /srv/app/old.log", "rm-files"},
		{"recursive rm in tmp", "rm -rf /tmp/build", "rm-files"},
		{"sudo with user", "sudo -u deploy rm -f /srv/x", "rm-files"},
		{"after cd", "cd /srv && rm -r old", "rm-files"},
		{"unlink", "unlink /srv/app/current", "rm-files"},
		{"xargs", "find /srv -name '*.bak' | xargs -0 rm", "rm-files"},
		{"find delete", "find /srv/cache -type f -delete", "rm-files"},
		{"find exec rm", "find /srv -name x -exec rm {} +", "rm-files"},
		{"shred remove", "shred -u /srv/key", "rm-files"},
		{"in sh -c", `bash -c 'rm -f /srv/x'`, "rm-files"},
		{"in substitution", "echo $(rm /srv/x)", "rm-files"},
		{"full path", "/bin/rm /srv/x", "rm-files"},
		{"env wrapper", "env LANG=C nice -n 10 rm /srv/x", "rm-files"},
		{"timeout wrapper", "timeout 30 rm -rf /srv/x", "rm-files"},
		{"docker exec inner", "docker exec -u root web rm -rf /data", "rm-files"},
		{"kubectl exec inner", "kubectl exec -n prod web-0 -- rm /data/x", "rm-files"},
		{"powershell", `Remove-Item -Path C:\srv\old -Force`, "rm-files"},
		{"powershell pipe", `Get-ChildItem C:\logs | Remove-Item`, "rm-files"},
		{"cmd del", `cmd /c del C:\srv\x`, "rm-files"},
		{"grep for rm", `grep "rm -rf" notes.txt`, ""},
		{"echo rm", "echo rm /srv/x", ""},
		{"rm with no file", "rm --help", ""},
		{"find without delete", "find /srv -name '*.log'", ""},
		{"rmdir", "rmdir /srv/empty", "rm-files"},
		{"rmdir with no folder", "rmdir --help", ""},
		{"cmd rd", `cmd /c rd C:\srv\old`, "rm-files"},
		{"command -v lookup", "command -v rm", ""},
	})
}

func TestRuleDocker(t *testing.T) {
	runCarried(t, []carriedCase{
		{"rm", "docker rm web", "docker-rm"},
		{"rm force", "docker rm -f web api", "docker-rm"},
		{"rmi", "docker rmi nginx:1.25", "docker-rm"},
		{"container rm", "docker container rm web", "docker-rm"},
		{"image rm", "docker image rm nginx", "docker-rm"},
		{"volume rm", "docker volume rm data", "docker-rm"},
		{"service rm", "docker service rm api", "docker-rm"},
		{"stack rm", "docker stack rm prod", "docker-rm"},
		{"global option", "docker -H ssh://x rm web", "docker-rm"},
		{"compose rm", "docker compose rm -f", "docker-rm"},
		{"compose down volumes", "docker compose -f prod.yml down -v", "docker-rm"},
		{"compose down rmi", "docker-compose down --rmi all", "docker-rm"},
		{"sudo docker", "sudo docker rm web", "docker-rm"},
		{"plain system prune", "docker system prune -f", "docker-prune"},
		{"image prune", "docker image prune", "docker-prune"},
		{"container prune", "docker container prune -f", "docker-prune"},
		{"builder prune", "docker builder prune", "docker-prune"},
		{"kill", "docker kill web", "docker-kill"},
		{"compose kill", "docker compose kill", "docker-kill"},
		{"swarm leave", "docker swarm leave --force", "docker-kill"},
		{"node demote", "docker node demote n2", "docker-kill"},
		{"node drain", "docker node update --availability drain n2", "docker-kill"},
		{"service scale 0", "docker service scale api=0", "docker-kill"},
		{"service replicas 0", "docker service update --replicas 0 api", "docker-kill"},
		{"stack deploy prune", "docker stack deploy --prune -c s.yml prod", "docker-kill"},
		{"privileged run", "docker run --privileged -d img", "docker-host"},
		{"host root bind", "docker run -v /:/host img", "docker-host"},
		{"socket bind", "docker run -v /var/run/docker.sock:/var/run/docker.sock img", "docker-host"},
		{"host pid", "docker run --pid=host img", "docker-host"},
		{"mount bind etc", "docker run --mount type=bind,source=/etc,target=/x img", "docker-host"},
		{"plugin install", "docker plugin install vieux/sshfs", "docker-host"},
		{"compose run privileged", "docker compose run --privileged app sh", "docker-host"},
		{"ps", "docker ps -a", ""},
		{"logs", "docker logs --tail 100 web", ""},
		{"compose down only stops", "docker compose down", ""},
		{"compose up", "docker compose up -d", ""},
		{"run with app folder", "docker run -d -v /srv/app/data:/data img", ""},
		{"read-only etc file", "docker run -v /etc/localtime:/etc/localtime:ro img", ""},
		{"writable etc", "docker run -v /etc/nginx:/etc/nginx img", "docker-host"},
		{"read-only ssh keys", "docker run -v /root/.ssh:/k:ro img", "docker-host"},
		{"compose cp", "docker compose cp app:/x /tmp/x", "docker-host"},
		{"plain volume prune", "docker volume prune", "docker-prune"},
		{"service scale up", "docker service scale api=3", ""},
		{"exec read", "docker exec web ls /data", ""},
		{"restart", "docker restart web", ""},
	})
}

func TestRulePackages(t *testing.T) {
	runCarried(t, []carriedCase{
		{"apt remove", "apt remove -y nginx", "pkg-remove"},
		{"apt-get purge", "sudo apt-get purge nginx", "pkg-remove"},
		{"apt install with minus", "apt-get install nginx-", "pkg-remove"},
		{"dnf remove", "dnf remove -y httpd", "pkg-remove"},
		{"yum erase", "yum erase httpd", "pkg-remove"},
		{"apk del", "apk del nginx", "pkg-remove"},
		{"dpkg purge", "dpkg -P nginx", "pkg-remove"},
		{"rpm erase", "rpm -e httpd", "pkg-remove"},
		{"zypper rm", "zypper rm nginx", "pkg-remove"},
		{"pacman remove", "pacman -Rns nginx", "pkg-remove"},
		{"essential ssh", "apt-get remove -y openssh-server", "pkg-remove-essential"},
		{"essential sudo arch", "dnf remove sudo.x86_64", "pkg-remove-essential"},
		{"essential with version", "apt-get purge sudo=1.9.15", "pkg-remove-essential"},
		{"essential glob", "apt-get remove 'openssh*'", "pkg-remove-essential"},
		{"essential regex", "apt-get remove openssh.server", "pkg-remove-essential"},
		{"essential apk", "apk del busybox", "pkg-remove-essential"},
		{"essential dpkg", "dpkg --purge systemd", "pkg-remove-essential"},
		{"essential install minus", "apt-get install -y nginx sudo-", "pkg-remove-essential"},
		{"autoremove names no package", "apt-get autoremove -y", ""},
		{"dist-upgrade", "apt-get dist-upgrade -y", ""},
		{"apt install", "apt-get install -y nginx", ""},
		{"apt upgrade", "apt-get upgrade -y", ""},
		{"dnf upgrade", "dnf upgrade --security -y", ""},
		{"apt list", "apt list --installed", ""},
		{"rpm query", "rpm -qa", ""},
		{"dpkg list", "dpkg -l", ""},
	})
	for _, c := range []string{"apt-get remove -y nginx", "dnf remove httpd"} {
		if slices.Contains(hitIDs(c), "pkg-remove-essential") {
			t.Errorf("%q: nginx/httpd is not an essential package", c)
		}
	}
}

// cron rm removed one entry by dropping its line and handing the rest to
// crontab - (internal/cli/modules.go cron rm); cron set does the same but
// adds a line back. Only text that visibly drops lines counts.
func TestRuleCronRemove(t *testing.T) {
	runCarried(t, []carriedCase{
		{"drop a line, as cron rm", "crontab -l | grep -v backup | crontab -", "cron-remove"},
		{"drop for a user", "crontab -u deploy -l | grep -v -e backup | sudo crontab -u deploy -", "cron-remove"},
		{"sed drop then crontab", "crontab -l | sed '/backup/d' | crontab -", "cron-remove"},
		{"sed -i drop in spool", "sed -i '/backup/d' /var/spool/cron/crontabs/root", "cron-remove"},
		{"sed -i drop in cron.d", "sed -i -e '/backup/d' /etc/cron.d/jobs", "cron-remove"},
		{"rm cron.d", "rm /etc/cron.d/backup", "rm-files"},
		{"replace and add back, as cron set", `crontab -l | grep -v backup | { cat; echo '0 2 * * * /srv/backup'; } | crontab -`, ""},
		{"add a line", `{ crontab -l; echo '0 2 * * * /srv/backup'; } | crontab -`, ""},
		{"install a file: text cannot tell", "crontab /tmp/new-cron", ""},
		{"filter elsewhere", "grep -v x /etc/hosts > /tmp/h; crontab -l", ""},
		{"sed -i edit, no drop", "sed -i 's/02/03/' /etc/cron.d/jobs", ""},
		{"sed -i drop outside cron", "sed -i '/x/d' /etc/hosts", ""},
		{"overwrite: text cannot tell", "echo '' > /etc/cron.d/backup", ""},
		{"append redirect", "echo '0 2 * * * /srv/backup' >> /etc/cron.d/backup", ""},
		{"append tee", "echo x | sudo tee -a /etc/crontab", ""},
		{"list", "crontab -l", ""},
		{"list for user", "crontab -u deploy -l", ""},
	})
	if !slices.Contains(hitIDs("crontab -r"), "crontab-r") {
		t.Error("crontab -r: want the built-in rule crontab-r")
	}
}

func TestRuleKubectlScaleZero(t *testing.T) {
	runCarried(t, []carriedCase{
		{"equals", "kubectl scale deploy/web --replicas=0", "kubectl-scale-zero"},
		{"space", "kubectl -n prod scale --replicas 0 deployment web", "kubectl-scale-zero"},
		{"not a number", "kubectl scale sts/db --replicas=none", "kubectl-scale-zero"},
		{"k3s", "k3s kubectl scale deploy web --replicas=0", "kubectl-scale-zero"},
		{"scale up", "kubectl scale deploy/web --replicas=3", ""},
		{"get", "kubectl get pods -A", ""},
	})
}

func TestRuleDBDropUser(t *testing.T) {
	runCarried(t, []carriedCase{
		{"psql", `psql -c "DROP USER app"`, "db-drop-user"},
		{"role", `psql -c 'drop role if exists app'`, "db-drop-user"},
		{"mysql", `mysql -e "DROP USER 'app'@'%'"`, "db-drop-user"},
		{"dropuser tool", "sudo -u postgres dropuser app", "db-drop-user"},
		{"mongo", `mongosh --eval 'db.dropUser("app")'`, "db-drop-user"},
		{"create user", `psql -c "CREATE USER app"`, ""},
		{"select users", `psql -c "SELECT usename FROM pg_user"`, ""},
	})
}

// Every carried rule names the command it is about, so the approval
// window and policy list can show it.
func TestCarriedRulesListed(t *testing.T) {
	want := []string{"rm-files", "docker-rm", "docker-prune", "docker-kill", "docker-host", "pkg-remove",
		"pkg-remove-essential", "cron-remove", "kubectl-scale-zero", "db-drop-user"}
	var have []string
	for _, r := range Rules() {
		have = append(have, r.ID)
	}
	for _, id := range want {
		if !slices.Contains(have, id) {
			t.Errorf("Rules() has no %s", id)
		}
	}
}

// komando's own scripts (pkg, cron, docker prune) are rated by their
// command; only the built-in rules check them.
func TestCheckScriptLeavesCarriedOut(t *testing.T) {
	if hits := CheckScript(`tmp=$(mktemp); apt-get remove -y -q $PKGS; rm -f "$tmp"; docker system prune -f`, nil); len(hits) != 0 {
		t.Errorf("CheckScript: want no hit, got %v", hits)
	}
	if !hasRule(CheckScript("rm -rf /", nil), "rm-root") {
		t.Error("CheckScript lost the built-in rule rm-root")
	}
	if !hasRule(Check(`rm -f "$tmp"`, nil), "rm-files") {
		t.Error("Check lost the carried rule rm-files")
	}
}
