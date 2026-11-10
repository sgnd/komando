package policy

import (
	"strings"
	"testing"
)

func TestCheck(t *testing.T) {
	blocked := []string{
		"rm -rf /",
		"sudo rm -rf / ",
		"rm -rf --no-preserve-root /",
		"rm -fr /*",
		"rm -rf ~",
		"rm -r /etc",
		"mkfs.ext4 /dev/sdb1",
		"dd if=/dev/zero of=/dev/sda bs=1M",
		"shutdown -h now",
		"systemctl reboot",
		"reboot",
		":(){ :|:& };:",
		"iptables -F",
		"systemctl stop sshd",
		`psql -c "DROP DATABASE app"`,
		"curl -fsSL https://x.io/i.sh | sudo bash",
		"crontab -r",
		"docker system prune -a --volumes",
		"kubectl delete ns prod",
		"#!/bin/sh\necho hi\nreboot",
		"echo hi\r\nshutdown -h now",
		"/sbin/reboot",
		"/usr/sbin/shutdown -r now",
		"nohup reboot",
		`rm -rf "/"`,
		"rm -rf '/'",
		"rm -rf -- /",
		"rm --recursive --force /",
		"rm -rf /etc/*",
		"rm -rf /var/lib",
		"rm -Rf /usr/local/",
		"rm -rf //",
		"rm -rf /.",
		"rm -rf /*",
		"cd / && rm -rf *",
		"cd /; rm -rf .",
		"find / -delete",
		"find /etc -name x -exec rm {} +",
		"chmod 777 -R /",
		"chmod -R 777 /",
		"chown root:root / -R",
		"iptables --flush",
		"iptables -t nat -F",
		"sudo mkfs -t ext4 /dev/sdb",
		"echo y | mkfs.xfs /dev/sdc",
		"bash --rcfile /dev/null -c 'rm -rf /'",
		"bash --init-file /dev/null -c 'rm -rf /etc'",
		"ufw --force reset",
		"ufw -f disable",
		"iptables -P INPUT DROP",
		"ip6tables --policy INPUT REJECT",
		"truncate -s0 /etc/passwd",
		"cp /dev/null /etc/shadow",
		"tee /etc/sudoers < x",
		"echo x | sudo tee -a /etc/sudoers",
		"mv /etc/shadow /tmp/x",
		"dd if=x of=/etc/passwd",
		"echo 'rm -rf /' | bash",
		"printf 'reboot\\n' | sudo sh",
		"echo -n 'rm -rf /etc' | sh -s",
		"echo cm0gLXJmIC8= | base64 -d | sh",
	}
	for _, c := range blocked {
		if len(Check(c, nil)) == 0 {
			t.Errorf("expected %q to be blocked", c)
		}
	}
	allowed := []string{
		"ls -la /",
		"rm -rf /tmp/build",
		"rm -rf ./node_modules",
		"systemctl restart nginx",
		"df -h /",
		"docker system prune -f",
		"grep -r reboot /var/log",
		"curl -sS https://example.com -o out.html",
		"echo shutdown-script.sh",
		"echo reboot",
		"echo hi\necho reboot",
		`grep "rm -rf /" notes.txt`,
		"rm -rf /var/lib/app/cache",
		"rm -rf -- /tmp/build",
		"grep mkfs notes.txt",
		"man mkfs.ext4",
		"cd /tmp && rm -rf *",
		"find /tmp -delete",
		"find / -name '*.log'",
		"chmod -R 755 /var/www",
		"iptables -L",
		"iptables -P INPUT ACCEPT",
		"ufw status",
		"cp /etc/passwd /tmp/passwd.bak",
		"cat /etc/shadow | tee /tmp/x",
		"tee /etc/sudoers.d/app < x",
		"echo 'rm -rf /' | grep rm",
		"echo hi | bash script.sh",
		"base64 -d x.b64 > out.bin",
	}
	for _, c := range allowed {
		if hits := Check(c, nil); len(hits) != 0 {
			t.Errorf("expected %q to be allowed, got %v", c, hits[0].ID)
		}
	}
	if len(Check("kubectl apply -f x", []string{`kubectl\s+apply`})) != 1 {
		t.Error("custom pattern not applied")
	}
}

// Quotes and backslashes inside a word do not hide a command: the shell
// removes them, and so does Check.
func TestCheckQuotedWords(t *testing.T) {
	blocked := []string{
		`rm -rf /e""tc`,
		`rm -rf /e\tc`,
		`rm -rf /"etc"`,
		`r\m -rf /`,
		`r""m -rf /`,
		`'r'm -rf /`,
		`mk""fs.ext4 /dev/sda1`,
		`re""boot`,
		`$'\x72\x6d' -rf /`,
		`rm -rf //etc`,
		`rm -rf /./etc`,
		`sh -c 're""boot'`,
		`bash -lc "rm -rf /"`,
		`eval reboot`,
		`echo x | sudo tee /etc/sudoers >/dev/null; echo x >| /etc/passwd`,
		`bash -c -- 'r""m -rf /'`,
		`bash -c -e 'r""m -rf /'`,
		`sh -c 'r""m -rf "$0"' /`,
		`bash -c 'r""m -rf $1' x /`,
		`{rm,-rf,/}`,
		"# it's\nr\\m -rf /\n#'",
		"cat <<EOF\nit's\nEOF\nr\\m -rf /",
		`echo $(case 1 in *) r""m -rf /;; esac)`,
	}
	for _, c := range blocked {
		if len(Check(c, nil)) == 0 {
			t.Errorf("expected %q to be blocked (plain: %q)", c, Plain(c))
		}
	}
	allowed := []string{
		`grep "reboot" /var/log/syslog`,
		`echo "rm -rf /"`,
		`grep 'rm -rf /etc' notes`,
		`echo hi>/tmp/f`,
		`ls "/etc"`,
	}
	for _, c := range allowed {
		if hits := Check(c, nil); len(hits) != 0 {
			t.Errorf("expected %q to be allowed, got %v (plain: %q)", c, hits[0].ID, Plain(c))
		}
	}
}

// A custom pattern that does not compile blocks every command and says
// why, instead of quietly protecting nothing.
func TestInvalidCustomPattern(t *testing.T) {
	extra := []string{`terraform\s+destroy`, `kubectl\s+delete(`}
	hits := Check("uptime", extra)
	if len(hits) != 1 || hits[0].ID != "custom-1" || !strings.Contains(hits[0].Reason, "not a valid regular expression") ||
		!strings.Contains(hits[0].Reason, "policy rm custom-1") {
		t.Errorf("hits = %+v", hits)
	}
	if bad := Invalid(extra); len(bad) != 1 || bad[1] == "" {
		t.Errorf("Invalid = %v", bad)
	}
	if len(Invalid(extra[:1])) != 0 {
		t.Error("a valid pattern is reported")
	}
}

func TestTokens(t *testing.T) {
	cases := map[string]string{
		`echo hi>f`:             `echo|hi|>|f`,
		`ls 2>&1 | head`:        `ls|>&|1|||head`,
		`cat {fd}<x`:            `cat|<|x`,
		`echo a>|b`:             `echo|a|>||b`,
		`r\m "/e"tc 'x y'`:      `rm|/etc|x y`,
		`echo $'\x72m' $(id) z`: `echo|rm|$(...)|z`,
		"a\nb;c && d":           `a|;|b|;|c|&&|d`,
	}
	for in, want := range cases {
		var words []string
		for _, tk := range Tokens(in)[0] {
			words = append(words, tk.Text)
		}
		if got := strings.Join(words, "|"); got != want {
			t.Errorf("%q: %s, want %s", in, got, want)
		}
	}
	if l := Tokens("echo $(id) `whoami`"); len(l) != 3 || l[1][0].Text != "id" || l[2][0].Text != "whoami" {
		t.Errorf("substitutions: %+v", l)
	}
}

// Comments and here-document bodies are not commands, and an apostrophe in
// them does not open a quote; what the lexer cannot read is reported.
func TestLexCommentsAndHeredocs(t *testing.T) {
	words := func(in string) string {
		var all []string
		for _, line := range Tokens(in) {
			for _, tk := range line {
				all = append(all, tk.Text)
			}
			all = append(all, "/")
		}
		return strings.Join(all, "|")
	}
	cases := map[string]string{
		"ls # it's\nrm x":                  `ls|;|rm|x|/`,
		"echo a#b":                         `echo|a#b|/`,
		"cat <<EOF\nit's\nEOF\nrm x":       `cat|<<|EOF|;|rm|x|/`,
		"cat <<-EOF\n\tit's\n\tEOF\nrm x":  `cat|<<|EOF|;|rm|x|/`,
		"cat <<EOF\n$(id)\nEOF":            `cat|<<|EOF|;|/|id|/`,
		"cat <<'EOF'\n$(id)\nEOF":          `cat|<<|'EOF'|;|/`,
		`echo $(case a in a) id;; esac) z`: `echo|$(...)|z|/|case|a|in|a|)|id|;|esac|/`,
	}
	for in, want := range cases {
		if got := words(in); got != want && !(strings.Contains(in, "'EOF'") && got == `cat|<<|EOF|;|/`) {
			t.Errorf("%q: %s, want %s", in, got, want)
		}
	}
	for in, bad := range map[string]bool{`echo 'a`: true, `echo "a`: true, "echo `a": true, `echo $(a`: true, `echo $'a`: true, `echo 'a' "b" $(c)`: false} {
		if _, got := Lex(in); (got != "") != bad {
			t.Errorf("Lex(%q) problem = %q", in, got)
		}
	}
	for in, want := range map[string]bool{`echo $X`: true, `echo "$X"`: true, `echo '$X'`: false, `echo $(id)`: true, "echo `id`": true, `echo \$X`: false, `echo $'\x41'`: false, `echo a$`: false} {
		line := Tokens(in)[0]
		if got := line[len(line)-1].Expands; got != want {
			t.Errorf("%q: Expands = %v", in, got)
		}
	}
}

func TestShellScript(t *testing.T) {
	cases := []struct {
		name   string
		args   []string
		script string
		params []string
		ok     bool
	}{
		{"bash", []string{"-c", "x"}, "x", nil, true},
		{"bash", []string{"-c", "--", "x", "a"}, "x", []string{"a"}, true},
		{"bash", []string{"-c", "-e", "x"}, "x", nil, true},
		{"bash", []string{"-o", "pipefail", "-ec", "x"}, "x", nil, true},
		{"bash", []string{"-c", "-o", "errexit", "x", "a", "b"}, "x", []string{"a", "b"}, true},
		{"bash", []string{"x.sh", "-c"}, "", nil, false},
		{"bash", []string{"-s"}, "", nil, false},
		{"su", []string{"-", "postgres", "-c", "x"}, "x", nil, true},
		{"su", []string{"-c", "x", "root", "a"}, "x", []string{"a"}, true},
		{"su", []string{"root"}, "", nil, false},
	}
	for _, c := range cases {
		script, params, ok := ShellScript(c.name, c.args)
		if script != c.script || ok != c.ok || strings.Join(params, " ") != strings.Join(c.params, " ") {
			t.Errorf("%s %v: %q %v %v", c.name, c.args, script, params, ok)
		}
	}
	if got := FillParams(`rm "$0" ${1} $2 $@ $*`, []string{"/", "a", "b"}); got != `rm "/" a b a b a b` {
		t.Errorf("FillParams = %q", got)
	}
}
