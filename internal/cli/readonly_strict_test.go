package cli

import "testing"

// --read-only runs only what komando knows only reads (C92, the strict
// allowlist). One test per audit finding: every payload here ran on a
// protected server, or through a read-only key, before.

func refusedReadOnly(t *testing.T, cmds ...string) {
	t.Helper()
	for _, c := range cmds {
		if readOnlyViolation(c) == "" {
			t.Errorf("%q passed --read-only", c)
		}
	}
}

func allowedReadOnly(t *testing.T, cmds ...string) {
	t.Helper()
	for _, c := range cmds {
		if w := readOnlyViolation(c); w != "" {
			t.Errorf("%q refused under --read-only (%s)", c, w)
		}
	}
}

// cli-guard 10: getopt_long takes any unique start of a long option, so
// only a long option komando knows by its full name passes.
func TestReadOnlyLongOptionStarts(t *testing.T) {
	refusedReadOnly(t,
		`sed --in s/a/b/ /etc/hosts`,
		`sed --in-pl=.bak s/a/b/ /etc/hosts`,
		`tar -cf - /etc/hostname --checkpoint=1 --checkpoint-act=exec=id`,
		`sort --o=/root/.ssh/authorized_keys`,
		`sort --ou /root/.ssh/authorized_keys f`,
		`date --s=2001-01-01`,
		`git ls-remote --up=id .`,
		`git grep --no-index -Oid x /etc`,
		`git log --outp=/etc/x`,
		`journalctl --vacuum-t=1s`,
		`journalctl --rot`,
		`dmesg --cl`,
		`dmesg --console-of`,
		`lz4 -lf a /etc/b`,
		`gawk --so=x 1 f`,
		`uniq --unknown-option a`,
		`file --comp -m NAME`,
	)
	allowedReadOnly(t,
		`sed -n 1,5p /etc/hosts`, `sed --quiet -e 5p /etc/hosts`, `sort -rn --key=2 f`, `sort --reverse f`,
		`date --utc`, `date +%s`, `journalctl -u nginx --no-pager --since=today -n 50`,
		`dmesg --ctime --level=err`,
		`tar -tzf a.tgz`, `tar --list -f a.tar`,
	)
}

// cli-guard 11: bash runs text inside the arguments of its own commands
// (an array subscript, ${x@P}, arithmetic), so those forms do not pass.
func TestReadOnlyBashReparse(t *testing.T) {
	refusedReadOnly(t,
		`let 'a[$(touch /tmp/p)]=1'`,
		`printf -v 'a[$(touch /tmp/p)]' x`,
		`test -v 'a[$(touch /tmp/p)]'`,
		`[ -v 'a[$(touch /tmp/p)]' ]`,
		`[[ -v 'a[$(touch /tmp/p)]' ]]`,
		`[[ 'a[$(touch /tmp/p)]' -eq 1 ]]`,
		`read 'a[$(touch /tmp/p)]' <<< x`,
		`unset 'a[$(touch /tmp/p)]'`,
		`declare 'a[$(touch /tmp/p)]=1'`,
		`export 'a[$(touch /tmp/p)]'`,
		`echo ${x:='$(touch /tmp/p)'}${x@P}`,
		`echo ${X@P}`,
		`x='a[$(touch /tmp/p)]'; echo $((x))`,
		`x='a[$(touch /tmp/p)]'; (( x ))`,
		`x='a[$(touch /tmp/p)]'; echo $[x]`,
		`x='a[$(touch /tmp/p)]'; echo ${y[x]}`,
		`x='a[$(touch /tmp/p)]'; echo ${y:x}`,
		`bash -c "let 'a[\$(touch /tmp/p)]=1'"`,
		`wait -p 'a[$(touch /tmp/p)]' -n`,
		`getopts a 'a[$(touch /tmp/p)]'`,
	)
	if !readOnlyMutates(`echo ${X@P}`, []string{`X=$(touch /tmp/p)`}) {
		t.Error("-e X with ${X@P} passed")
	}
	allowedReadOnly(t,
		`echo $HOME ${USER}`, `test -f /etc/hosts && echo yes`, `[ -d /var/log ] || echo no`,
		`printf '%s\n' a b`, `echo "$(hostname): $(uptime)"`, `x=1; echo $x`,
		`export LC_ALL=C; df -h`,
	)
}

// cli-guard 12 and cli-ssh M1: read tools with an option that writes a
// file, runs a program or kills.
func TestReadOnlyToolsThatWrite(t *testing.T) {
	refusedReadOnly(t,
		`xxd -r -p - /root/.ssh/authorized_keys`,
		`xxd /etc/hosts /tmp/out`,
		`yq -i .a=1 /etc/x.yaml`,
		`xmllint --output /etc/x a.xml`,
		`rg --pre rm x /var/www`,
		`rg --pre=rm x /var/www`,
		`rg --hostname-bin /tmp/x --hyperlink-format default x`,
		`fuser -k 22/tcp`,
		`ss -K dst 10.0.0.5`,
		`arp -d 10.0.0.1`,
		`sar -o /tmp/s 1 1`,
		`file -C -m NAME`,
		`ldd /tmp/evil`,
		`lsof -D b`,
		`sudo xxd -r -p /tmp/hex /etc/cron.d/x`,
	)
	allowedReadOnly(t, `xxd /etc/hostname`, `yq .a /etc/x.yaml`, `rg -n nginx /etc`, `fuser 22/tcp`,
		`ss -tlnp`, `arp -n`, `sar 1 1`, `file /bin/ls`, `lsof -i :80`)
}

// cli-guard 13: bash expands {a,b} in an argument before the command runs.
func TestReadOnlyBraceExpansion(t *testing.T) {
	refusedReadOnly(t,
		`systemctl {restart,status} nginx`,
		`kubectl {delete,get} pod x`,
		`sed {-i,-e} s/a/b/ /etc/hosts`,
		`sort {-o,/root/.ssh/authorized_keys}`,
		`bash -c 'systemctl {stop,status} nginx'`,
		`cat /etc/{passwd,shadow}`,
		`sort -{o,r} f`,
		`echo {1..3}`,
		`sort {-o,}'/etc/x'`,
	)
	allowedReadOnly(t, `awk '{print $1,$2}' f`, `echo '{a,b}'`, `echo "{a,b}"`, `find /var -name '*.{log,txt}'`,
		`docker ps --format '{{.Names}},{{.Status}}'`)
}

// cli-guard 14: a wrapper komando cannot follow hides the real command.
func TestReadOnlyWrappers(t *testing.T) {
	refusedReadOnly(t,
		`timeout 1d rm -rf /srv/x`,
		`timeout inf rm x`,
		`timeout 1d mytool`,
		`timeout 5x cat f`,
		`coproc C { rm -rf /x; }`,
		`coproc cat f`,
		`sudo --unknown-flag cat f`,
		`nice --unknown cat f`,
		`chrt 1 rm x`,
		`busybox mytool`,
	)
	allowedReadOnly(t, `timeout 10 cat f`, `timeout 1.5m cat f`, `timeout 1d cat f`, `timeout -s KILL 5 df -h`,
		`sudo -n cat /etc/shadow`, `sudo -u postgres cat /var/lib/pg/x`, `nice -n 5 du -sh /var`, `time ls`)
}

// cli-guard 15: SQL fed to psql from a file. \gexec and \set with :var
// run SQL the check never sees, and nothing holds psql to a read-only
// transaction, so psql and mysql do not pass --read-only at all (db query
// does that job).
func TestReadOnlyPsqlInput(t *testing.T) {
	refusedReadOnly(t, `psql app`, `psql -d app -X`, `psql -c '\gexec'`, `psql -c "select 1 \gset"`,
		`psql --comm='drop table x'`, `psql -c '\lo_unlink 1'`, `mysql app`)
}

// cli-guard 16: a command with subcommands passes only for a form komando
// knows reads, not for every form it does not know writes.
func TestReadOnlySubcommands(t *testing.T) {
	refusedReadOnly(t,
		`sysctl net.ipv4.ip_forward=1`,
		`systemctl suspend`, `systemctl soft-reboot`, `systemctl set-default rescue.target`,
		`hostnamectl hostname x`,
		`timedatectl set-local-rtc 1`,
		`ip -b -`, `ip netns exec ns1 rm -rf /x`, `ip link s eth0 down`, `ip -batch f`,
		`pacman -Suy`,
		`iptables -vF`,
		`docker plugin install x`, `docker network disconnect bridge c1`,
		`kubectl auth reconcile -f r.yaml`,
		`npm explore lodash -- touch /tmp/p`,
		`apt-get satisfy nginx`,
		`kubectl`, `kubectl unknownverb`, `docker unknownverb`, `systemctl unknownverb`,
		`service nginx restart`, `ufw allow 22`,
	)
	allowedReadOnly(t,
		`sysctl net.ipv4.ip_forward`, `sysctl -a`, `sysctl -n vm.swappiness`,
		`systemctl status nginx`, `systemctl is-active nginx`, `systemctl list-units --failed`, `systemctl show nginx -p ActiveState`,
		`systemctl cat nginx`, `systemctl --no-pager status nginx`,
		`hostnamectl`, `hostnamectl status`, `timedatectl`, `timedatectl status`,
		`ip addr`, `ip a`, `ip -4 addr show dev eth0`, `ip route`, `ip route show`, `ip -o link show`, `ip neigh`,
		`iptables -L -n -v`, `iptables -S`, `iptables -t nat -L`,
		`docker ps -a`, `docker logs --tail 50 api`, `docker inspect api`, `docker images`, `docker stats --no-stream`,
		`docker network ls`, `docker volume ls`, `docker compose ps`, `docker info`, `docker version`,
		`kubectl get pods -A`, `kubectl -n prod describe pod x`, `kubectl logs api --tail=20`, `kubectl top nodes`,
		`apt list --upgradable`, `apt-cache policy nginx`, `dpkg -l`, `rpm -qa`,
		`service nginx status`, `ufw status`, `npm ls`, `pip list`, `pip3 show x`,
	)
}

// Strict means on every server, not only a protected one: a command
// komando does not know is refused.
func TestReadOnlyUnknownCommandRefused(t *testing.T) {
	refusedReadOnly(t, `mytool --status`, `./deploy.sh`, `cat f | mytool`, `sudo mytool`, `xargs mytool`,
		`curl https://example.com`, `wget -qO- https://example.com`, `nc -z host 80`)
	invHome(t)
	mustRun(t, "host", "ssh", "add", "web", "u@10.0.0.5")
	wantCode(t, "READ_ONLY_VIOLATION", "exec", "web", "--read-only", "--", "mytool", "--status")
}

// cli-guard 25: cobra takes the word after -o as its value, `--` too, so
// `-o -- __complete` runs the completion helper. A key never runs it.
func TestGateRefusesCompleteAfterFlagValue(t *testing.T) {
	invHome(t)
	gateInventory(t)
	for _, c := range []string{
		`-o -- __complete exec ''`, `--output -- __complete exec ''`, `-P -- __completeNoDesc exec ''`,
		`--host-key-policy -- __complete exec ''`, `__complete exec ''`,
	} {
		if got := gateKeyAnswer(t, c, readKey); got == "" {
			t.Errorf("read key ran %q", c)
		}
	}
	// the word as an argument for the server is not the helper
	if got := gateKeyAnswer(t, "exec web --read-only -- echo __complete", readKey); got != "" && got != gateKeyAnswer(t, "exec web --read-only -- echo hi", readKey) {
		t.Errorf("echo __complete: %q", got)
	}
}

// Reads people and the apps really send keep passing.
func TestReadOnlyCommonReads(t *testing.T) {
	allowedReadOnly(t,
		// the apps' server readings, before they moved to facts --only
		`echo load $(cut -d' ' -f1 /proc/loadavg); echo cores $(nproc); free -b | awk '/^Mem:/{print "mem", $2, $7}'; `+
			`df -PB1 / | awk 'NR==2{print "disk", $2, $4}'; echo up $(cut -d. -f1 /proc/uptime); `+
			`echo "os $(grep -m1 '^PRETTY_NAME=' /etc/os-release | cut -d= -f2 | tr -d '\"')"`,
		`uname -a`, `hostname`, `whoami`, `id -un`, `true`, `stat -c '%a %U' /etc/hosts`,
		`test -e /tmp/x; echo $?`, `pgrep -fxc "sleep 31" || true`,
		`ls -a /tmp 2>/dev/null | grep -c "^\.komando-" || true`,
		`sh -c 'echo out; echo err >&2; exit 3'`, `docker node ls`,
		`tail -n 100 /var/log/nginx/error.log | grep -i error | sort | uniq -c | sort -rn | head`,
		`for u in $(cut -d: -f1 /etc/passwd); do c=$(crontab -l -u "$u" 2>/dev/null | grep -v '^#'); [ -n "$c" ] && printf '## %s\n%s\n' "$u" "$c"; done`,
		`journalctl -u ssh -u sshd --since -24h --no-pager 2>/dev/null | grep -iE 'failed password' | tail -n 50`,
		`nginx -T 2>/dev/null | grep -E '^\s*(server_name|listen)\s' | sed 's/^\s*//' | sort | uniq -c`,
		`if command -v ufw >/dev/null; then ufw status verbose; elif command -v firewall-cmd >/dev/null; then firewall-cmd --list-all; elif command -v nft >/dev/null; then nft list ruleset; else iptables -S; fi`,
	)
}

// Review round 2 (2026-11-17): a variable bash or a tool reads as code or
// as where programs are cannot be set under --read-only, however it is
// set: read, for, an assignment, export or -e.
func TestReadOnlySpecialVariables(t *testing.T) {
	refusedReadOnly(t,
		`read PS4 < /tmp/f; set -x; ls`,
		`read PATH < /tmp/f; ls`,
		`read -r IFS < /tmp/f`,
		`read PROMPT_COMMAND < /tmp/f`,
		`for PATH in /tmp/evil; do ls; done`,
		`for PS4 in x; do ls; done`,
		`PATH=/tmp/evil ls`,
		`PATH=/tmp/evil; ls`,
		`export PATH=/tmp/evil`,
		`IFS=/ ; cat /etc/hosts`,
		`KUBECONFIG=/tmp/k kubectl get pods`,
		`DOCKER_CONFIG=/tmp/d docker ps`,
		`set -x`, `set -v`, `set -o xtrace`, `set -o verbose`, `set -xe`, `set +o noglob`,
	)
	if !readOnlyMutates(`ls`, []string{`PATH=/tmp/evil`}) {
		t.Error("-e PATH passed")
	}
	allowedReadOnly(t, `read -r line < /etc/hostname; echo $line`, `for f in /etc/*.conf; do wc -l $f; done`,
		`set -e`, `set -eu`, `set -euo pipefail`, `set -o pipefail`, `set -o errexit -o nounset`, `x=1; echo $x`)
}

// git reads the repository's own config, which can run a program on
// status, diff or log (core.fsmonitor, diff.external, textconv), so git
// is not known to only read.
func TestReadOnlyGitRefused(t *testing.T) {
	refusedReadOnly(t, `git -C /tmp/evil status`, `cd /tmp/evil && git diff`, `git log -p`, `git status`)
}

// A kubeconfig or docker config komando does not know can name a program
// to run for credentials.
func TestReadOnlyClientConfigRefused(t *testing.T) {
	refusedReadOnly(t, `kubectl get pods --kubeconfig /tmp/k`, `kubectl get pods --kubeconfig=/tmp/k`,
		`kubectl --kubeconfig /tmp/k get pods`, `kubectl get pods --server https://x`, `kubectl get pods --token x`,
		`kubectl -n x get pods --as admin`, `docker --config /tmp/d ps`, `docker -H tcp://x ps`)
	allowedReadOnly(t, `kubectl get pods -n prod --context staging`, `kubectl -n prod logs api --tail=20`)
}

// sudo -E would hand root the caller's environment.
func TestReadOnlySudoKeepsNoEnvironment(t *testing.T) {
	refusedReadOnly(t, `sudo -E cat /etc/shadow`, `sudo --preserve-env cat f`, `sudo --preserve-env=PATH cat f`, `sudo -nE cat f`)
	allowedReadOnly(t, `sudo -n cat /etc/shadow`, `sudo -u postgres -H cat f`)
}

// Review round 3 (2026-11-17).

// An -e value inside double quotes is one word the check cannot see as
// the shell will ("$X" with X=-delete is find's -delete).
func TestReadOnlyEnvInDoubleQuotes(t *testing.T) {
	for _, c := range []struct{ cmd, env string }{
		{`find /tmp "$x"`, `x=-delete`},
		{`sort "$x" a`, `x=-o/tmp/x`},
		{`find /tmp "${x}"`, `x=-delete`},
		{`echo "a $x b"`, `x=x`},
	} {
		if !readOnlyMutates(c.cmd, []string{c.env}) {
			t.Errorf("%q with -e %s passed", c.cmd, c.env)
		}
	}
	if readOnlyMutates(`du -sh $dir`, []string{`dir=/var/log`}) {
		t.Error("du -sh $dir with -e dir=/var/log refused")
	}
	if readOnlyMutates(`echo '$x'`, []string{`x=-delete`}) {
		t.Error(`echo '$x' refused: the single quotes keep it literal`)
	}
}

// A variable a program reads as options, a plugin or a config path:
// under --read-only a name must have a lower-case letter (programs read
// upper-case ones) or be one of the few that only set a language or zone.
func TestReadOnlyEnvNames(t *testing.T) {
	for _, env := range []string{
		`TAR_OPTIONS=--checkpoint=1 --checkpoint-action=exec=id`, `JAVA_TOOL_OPTIONS=-javaagent:x`, `_JAVA_OPTIONS=x`,
		`GCONV_PATH=/tmp`, `LOCPATH=/tmp`, `NODE_PATH=/tmp`, `PGOPTIONS=x`, `PGSERVICEFILE=/tmp/x`, `MYSQL_HOME=/tmp`,
		`ZDOTDIR=/tmp`, `XDG_CONFIG_HOME=/tmp`, `SYSTEMD_PAGERSECURE=0`, `DIR=/var/log`,
		`http_proxy=http://x`, `https_proxy=http://x`, `all_proxy=x`, `no_proxy=x`,
	} {
		if !readOnlyMutates(`tar tf a.tar`, []string{env}) {
			t.Errorf("-e %s passed", env)
		}
	}
	refusedReadOnly(t, `TAR_OPTIONS=--checkpoint-action=exec=id tar tf a.tar`, `export TAR_OPTIONS=x; tar tf a.tar`,
		`DIR=/var/log; du -sh $DIR`, `http_proxy=x curl_like`)
	for _, env := range []string{`LANG=C`, `LC_ALL=C`, `TZ=UTC`, `TERM=dumb`, `COLUMNS=200`, `NO_COLOR=1`, `dir=/var/log`, `logDir=/x`} {
		if readOnlyMutates(`ls`, []string{env}) {
			t.Errorf("-e %s refused", env)
		}
	}
	allowedReadOnly(t, `export LC_ALL=C; df -h`, `TZ=UTC date`, `dir=/var/log; du -sh $dir`)
}

// psql and mysql run in no read-only transaction under exec: a function a
// SELECT calls may write, and their meta commands run a shell (\echo `id`).
// komando db query runs SQL in a read-only transaction instead.
func TestReadOnlySQLClientsRefused(t *testing.T) {
	refusedReadOnly(t, `psql -c 'select 1'`, `psql app`, `sudo -u postgres psql -c 'select f()'`,
		`mysql -e 'select 1'`, `mariadb app`, `psql -c '\echo `+"`id`"+`'`)
}

// Review round 4 (2026-11-17): bash's own quoting ($'..', comments,
// here-documents) can hide where a double quote starts, so an -e name in
// a command with any double quote is refused.
func TestReadOnlyEnvQuotingTricks(t *testing.T) {
	for _, cmd := range []string{
		`echo $'\'' "$x"; sort "$x" f`,
		": # '\nsort \"$x\" f",
		"cat <<'E'\n'\nE\nsort \"$x\" f",
		`echo "hi"; sort ${x} f`,
	} {
		if !readOnlyMutates(cmd, []string{`x=-o/tmp/pwn`}) {
			t.Errorf("%q with -e x=-o/tmp/pwn passed", cmd)
		}
	}
	if readOnlyMutates(`echo "hi"; du -sh $xy`, []string{`x=/var`}) {
		t.Error("an -e name that only starts another word refused")
	}
	refusedReadOnly(t, `kubectl get pods -shttp://evil`, `kubectl -n x get pods -s=http://evil`, `kubectl config view --raw`)
	allowedReadOnly(t, `kubectl config view`, `kubectl get svc -o wide`)
}

// Review round 5 (2026-11-17): bash globs an unquoted -e value, so
// -delet[e] can become -delete; and --raw=true is --raw.
func TestReadOnlyEnvGlobAndRaw(t *testing.T) {
	for _, env := range []string{`x=-delet[e]`, `x=-fprin?`, `x=*`, `x=-{a,b}`, `x=a\b`} {
		if !readOnlyMutates(`find /tmp $x`, []string{env}) {
			t.Errorf("find /tmp $x with -e %s passed", env)
		}
	}
	if readOnlyMutates(`du -sh $x`, []string{`x=/var/log`}) {
		t.Error("a plain -e path refused")
	}
	refusedReadOnly(t, `kubectl config view --raw=true`, `kubectl get pods --raw=/x`)
}

// The reads of the removed host areas (service status, logs, file reads,
// facts, cron, docker and package lists) still pass --read-only through
// exec, so a protected server does not ask a person for them.
func TestReadOnlyRemovedAreaReads(t *testing.T) {
	allowedReadOnly(t,
		"systemctl status nginx", "systemctl is-active nginx", "systemctl list-units --failed", "systemctl list-timers",
		"journalctl -u nginx -n 100 --no-pager", "tail -n 100 /var/log/syslog",
		"cat /etc/hosts", "head -n 20 /etc/os-release", "ls -la /etc", "stat /etc/hosts", "sha256sum /etc/hosts", "du -sh /var/log",
		"uname -a", "df -h", "free -m", "uptime", "nproc", "lsblk", "hostnamectl", "timedatectl", "ps aux", "who", "last -n 10",
		"ss -tlnp", "netstat -tlnp", "ip addr", "ip route", "getent passwd", "id deploy",
		"crontab -l", "crontab -l -u deploy", "ls /etc/cron.d", "cat /etc/crontab",
		"docker ps -a", "docker logs --tail 100 web", "docker inspect web", "docker images", "docker stats --no-stream",
		"docker volume ls", "docker network ls", "docker compose ps", "docker compose logs --tail 50",
		"apt list --installed", "apt list --upgradable", "dpkg -l", "rpm -qa", "dnf list installed", "apk info",
	)
}
