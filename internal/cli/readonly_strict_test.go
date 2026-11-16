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
		`dmesg --ctime --level=err`, `git log --oneline -5`, `git status --short`, `git diff --stat HEAD~1`,
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
		`sudo -n cat /etc/shadow`, `sudo -u postgres psql -c 'select 1'`, `nice -n 5 du -sh /var`, `time ls`)
}

// cli-guard 15: SQL fed to psql from a file. \gexec and \set with :var
// run SQL the check never sees, so only the describe commands pass.
func TestReadOnlyPsqlInput(t *testing.T) {
	for _, in := range []string{
		"SELECT 'DROP TABLE accounts'\n\\gexec\n",
		"SELECT 'DROP TABLE accounts' \\gexec",
		"\\set q '1; DELETE FROM accounts'\nSELECT :q;\n",
		"SELECT :q;\n",
		"SELECT :'q';\n",
		"\\lo_unlink 123\n",
		"select 1 \\gset\n",
		"\\if true\n\\endif\n",
		"\\unknown\n",
	} {
		if sqlInputWrite("psql app", []byte(in)) == "" {
			t.Errorf("psql input %q passed --read-only", in)
		}
	}
	for _, in := range []string{
		"select 1;\n", "\\dt\nselect now()::text;\n", "\\d+ accounts\n", "\\l\n", "\\x\nselect '12:30'::time;\n",
	} {
		if w := sqlInputWrite("psql app", []byte(in)); w != "" {
			t.Errorf("psql input %q refused (%s)", in, w)
		}
	}
	refusedReadOnly(t, `psql -c '\gexec'`, `psql -c "select 1 \gset"`, `psql --comm='drop table x'`, `psql -c '\lo_unlink 1'`)
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
	mustRun(t, "host", "add", "web", "u@10.0.0.5")
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
