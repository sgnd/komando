package cli

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/spf13/cobra"
	"golang.org/x/crypto/ssh"

	"github.com/sgnd/komando/internal/driver"
	"github.com/sgnd/komando/internal/out"
	"github.com/sgnd/komando/internal/store"
)

func TestGateWords(t *testing.T) {
	ok := map[string][]string{
		"komando list":      {"komando", "list"},
		"  komando\tlist  ": {"komando", "list"},
		"komando exec web --read-only -- 'echo a; echo b'": {"komando", "exec", "web", "--read-only", "--", "echo a; echo b"},
		`komando exec web -- "a b" c`:                      {"komando", "exec", "web", "--", "a b", "c"},
		`komando list web-* ~ db-?`:                        {"komando", "list", "web-*", "~", "db-?"}, // nothing is expanded
		`komando x "a\"b\\c\$d" 'e\f'`:                     {"komando", "x", `a"b\c$d`, `e\f`},
		`komando a\ b \;`:                                  {"komando", "a b", ";"},
		`komando '' "" x`:                                  {"komando", "", "", "x"},
		"komando 'line one\nline two'":                     {"komando", "line one\nline two"},
		"komando list\\\n web":                             {"komando", "list", "web"},
		`komando a'b'"c"d`:                                 {"komando", "abcd"},
		`komando x#y`:                                      {"komando", "x#y"},
	}
	for in, want := range ok {
		got, err := gateWords(in)
		if err != nil || !slices.Equal(got, want) {
			t.Errorf("%q: %q %v, want %q", in, got, err, want)
		}
	}
	for _, in := range []string{
		"komando list; id", "komando list | sh", "komando list && id", "komando list || id", "komando list &",
		"komando $(id)", "komando `id`", `komando "$HOME"`, "komando \"`id`\"", "komando $HOME",
		"komando list > /tmp/x", "komando list < /etc/passwd", "komando (list)",
		"komando list\nid", "komando list\rid", "komando list #comment",
		"komando 'open", `komando "open`, `komando list \`,
	} {
		if got, err := gateWords(in); err == nil {
			t.Errorf("%q: accepted as %q", in, got)
		}
	}
}

func TestParseGate(t *testing.T) {
	req, e := parseGate("KOMANDO_AGENT='Komando iPhone' komando list -o json")
	if e != nil || req.agent != "Komando iPhone" || !slices.Equal(req.args, []string{"list", "-o", "json"}) {
		t.Errorf("%+v %v", req, e)
	}
	for in, code := range map[string]string{
		"":                               "SSH_GATE_REFUSED",
		"   ":                            "SSH_GATE_REFUSED",
		"ls -la":                         "SSH_GATE_REFUSED",
		"bash -c 'komando list'":         "SSH_GATE_REFUSED",
		"/usr/local/bin/komando list":    "SSH_GATE_REFUSED",
		"scp -t /tmp":                    "SSH_GATE_REFUSED",
		"/usr/lib/openssh/sftp-server":   "SSH_GATE_REFUSED",
		"PATH=/tmp komando list":         "SSH_GATE_REFUSED",
		"KOMANDO_HOME=/tmp komando list": "SSH_GATE_REFUSED",
		"KOMANDO_AGENT=x KOMANDO_AGENT=y komando list": "SSH_GATE_REFUSED",
		"KOMANDO_AGENT=x":         "SSH_GATE_REFUSED",
		"komando list; sh":        "SSH_GATE_SYNTAX",
		"export PATH=x; komando ": "SSH_GATE_SYNTAX",
	} {
		if _, e := parseGate(in); e == nil || e.Code != code {
			t.Errorf("%q: %+v, want %s", in, e, code)
		} else if want := map[string]int{"SSH_GATE_REFUSED": out.ExitPolicy, "SSH_GATE_SYNTAX": out.ExitUsage}[code]; e.Exit != want {
			t.Errorf("%q: exit %d, want %d", in, e.Exit, want)
		}
	}
}

// gateAnswer runs gateCheck on a command line ("" = allowed).
func gateAnswer(t *testing.T, line string, readOnly bool) string {
	t.Helper()
	words, err := gateWords(line)
	if err != nil {
		t.Fatal(err)
	}
	_, _, e := gateCheck(words, gateKey{readOnly: readOnly, network: true})
	if e == nil {
		return ""
	}
	if e.Exit != out.ExitPolicy || e.Hint == "" {
		t.Errorf("%q: %+v", line, e)
	}
	return e.Code
}

// gateInventory adds the targets the gate tests name: web, pg, c, k8s and
// s3 elsewhere; me, lh, inner and the *local conns on this computer.
func gateInventory(t *testing.T) {
	t.Helper()
	me, _ := os.Hostname()
	hosts := map[string]store.Host{
		"web": {Address: "10.0.0.5"}, "bastion": {Address: "10.0.0.9"}, "behind": {Address: "127.0.0.1", Via: "bastion"},
		"me": {Address: "127.0.0.1"}, "lh": {Address: "localhost"}, "v6": {Address: "::1"}, "short": {Address: "127.1"},
		"any": {Address: "0.0.0.0"}, "named": {Address: me}, "loop": {Address: "127.0.0.1", Via: "me"},
		"vpnd": {Address: "127.0.0.1", Via: "office"},
	}
	conns := map[string]string{
		"pg": "postgres://u@10.0.0.6/x", "c": "redis://10.0.0.7:6379", "k8s": "k8s://api.example.com:6443",
		"s3": "s3://AKID@bucket?endpoint=https://minio.example.com:9000", "reg": "registry://u@ghcr.io",
		"appdb": "sqlite:///home/u/app.db", "pglocal": "postgres://u@127.0.0.1/x", "redislocal": "redis://localhost:6379",
		"k8slocal": "k8s://127.0.0.1:6443", "sftplocal": "sftp://u@[::1]/home/u", "reglocal": "registry://u@localhost:5000",
		"pgbehind": "postgres://u@127.0.0.1/x", "pghostparam": "postgres://u@db.example.com:5432/x?host=127.0.0.1",
		"pghostaddr": "postgres://u@db.example.com/x?hostaddr=127.0.0.1", "pgsocket": "postgres://u@db.example.com/x?host=/var/run/postgresql",
		"pglist": "postgres://u@10.0.0.6,127.0.0.1/x", "mongolist": "mongodb://u@10.0.0.8,localhost:27017/x",
	}
	err := store.Update(store.Save(), func(st *store.State) error {
		for n, h := range hosts {
			h.Name, h.User = n, "u"
			st.Hosts[n] = &h
		}
		for n, u := range conns {
			k, _ := driver.Parse(u)
			st.Conns[n] = &store.Conn{Name: n, Kind: k.Kind.Name, URL: u}
		}
		st.Conns["pgbehind"].Via = "bastion"
		st.Vpns["office"] = &store.Vpn{Name: "office", Kind: "socks", Address: "10.0.0.1:1080"}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestGateCheck(t *testing.T) {
	invHome(t)
	gateInventory(t)
	mustRun(t, "snippet", "create", "my-df", "df -h", "--read-only")
	mustRun(t, "snippet", "create", "my-clean", "rm -rf /tmp/cache")
	setGate(tcl, true, gateYes) // the gate's own flags come back after it read the key's
	defer func() { setGate(tcl, false, gateYes) }()
	const R = "SSH_GATE_REFUSED"
	cases := []struct {
		line           string
		full, readOnly string
	}{
		{"list", "", ""},
		{"", "", ""}, // `komando` alone: first steps
		{"host list -o json", "", ""},
		{"credential password show db --reveal", "SSH_GATE_REFUSED", "SSH_GATE_REFUSED"},
		{"credential password show db --reveal=true", "SSH_GATE_REFUSED", "SSH_GATE_REFUSED"},
		{"credential password show db --reveal=false", "", ""},
		{"--reveal credential password show db", "SSH_GATE_REFUSED", "SSH_GATE_REFUSED"}, // a global flag before the command
		{"-o json --allow-dangerous fs rm web /tmp/x", "SSH_GATE_REFUSED", "SSH_GATE_REFUSED"},
		{"exec web --allow-dangerous -- rm -rf /tmp/x", "SSH_GATE_REFUSED", "SSH_GATE_REFUSED"},
		{"exec web --read-only -- echo --reveal --allow-dangerous", "", ""}, // words for the server
		{"shell web", "SSH_GATE_REFUSED", "SSH_GATE_REFUSED"},
		{"database postgres shell pg", "SSH_GATE_REFUSED", "SSH_GATE_REFUSED"},
		{"cluster kubernetes shell k8s pod/x", "SSH_GATE_REFUSED", "SSH_GATE_REFUSED"},
		{"config vault passphrase", "SSH_GATE_REFUSED", "SSH_GATE_REFUSED"},
		{"secret check db", "SSH_GATE_REFUSED", "SSH_GATE_REFUSED"},
		{"login aws", "SSH_GATE_REFUSED", "SSH_GATE_REFUSED"},
		{"config approval-code", "SSH_GATE_REFUSED", "SSH_GATE_REFUSED"},
		{"ssh-gate --name x", "SSH_GATE_REFUSED", "SSH_GATE_REFUSED"},
		{"ssh-gate line --name x key", "SSH_GATE_REFUSED", "SSH_GATE_REFUSED"},
		{"guide guard", "SSH_GATE_REFUSED", "SSH_GATE_REFUSED"},
		{"__complete exec ''", "SSH_GATE_REFUSED", "SSH_GATE_REFUSED"},
		{"host add x u@10.0.0.9", "SSH_GATE_REFUSED", "SSH_GATE_REFUSED"},
		{"credential password add db", "SSH_GATE_REFUSED", "SSH_GATE_REFUSED"},
		{"cp web:/var/backups/db.gz web:/tmp/db.gz", "", "SSH_GATE_READ_ONLY"}, // between two servers
		{"cp web:/var/backups/db.gz web:/tmp/db.gz --continue", "", "SSH_GATE_READ_ONLY"},
		{"exec web -- uptime", "", "SSH_GATE_READ_ONLY"},
		{"exec web --read-only -- uptime", "", ""},
		{"docker exec web app ls", "", "SSH_GATE_READ_ONLY"},
		{"docker exec web app --read-only ls", "", ""},
		{"database postgres query pg 'select 1'", "", ""},
		{"database postgres query pg --write 'delete from t'", "", "SSH_GATE_READ_ONLY"},
		{"db explain pg --analyze 'delete from t'", "", "SSH_GATE_READ_ONLY"},
		{"cache redis raw c --write SET a b", "", "SSH_GATE_READ_ONLY"},
		{"cluster kubernetes raw k8s --write delete pod x", "", "SSH_GATE_READ_ONLY"},
		{"pkg upgradable web --refresh", "", "SSH_GATE_READ_ONLY"},
		{"pkg security web --refresh", "", "SSH_GATE_READ_ONLY"},
		{"pkg upgrade web --security", "", "SSH_GATE_READ_ONLY"},
		{"pkg security web", "", ""},
		{"snippet exec my-df web", "", ""},
		{"snippet exec my-clean web", "", "SSH_GATE_READ_ONLY"},
		{"snippet exec drop-caches web", "", "SSH_GATE_READ_ONLY"},
		{"snippet exec disk web", "", ""},
		{"credential password remove db --help", "", ""}, // help only
		{"db", "", ""}, // a group: prints its help
		{"no-such-command", "SSH_GATE_REFUSED", "SSH_GATE_REFUSED"}, // names no command: as for a person (cut PR B1)
		{"completion bash", "", ""},
		{"exec web --read-only --dry-run -- uptime", "", ""},
		{"host rm x --dry-run", "SSH_GATE_REFUSED", "SSH_GATE_REFUSED"}, // no key changes komando's inventory, nor previews it
		{"exec web --script ./check.sh", R, "SSH_GATE_READ_ONLY"},       // no key reads a file on the komando computer
		{"exec web --script ./check.sh --read-only", R, R},
		{"exec web --script -", "", "SSH_GATE_READ_ONLY"}, // the key's own input
		{"exec web --script - --read-only", "", ""},
		{"job start web --read-only -- du -sh /var", "", ""},
		{"job start web -- make backup", "", "SSH_GATE_READ_ONLY"},
		{"cluster kubernetes exec k8s pod/x -- ls", "", "SSH_GATE_READ_ONLY"},
		{"cluster kubernetes exec k8s pod/x --read-only -- ls", "", ""},
		{"docker compose web ps", "", "SSH_GATE_READ_ONLY"}, // decided by the subcommand: not for a read key
		{"cp web:/etc/hosts /tmp/hosts", "SSH_GATE_REFUSED", "SSH_GATE_REFUSED"},
		{"download web /etc/hosts", "SSH_GATE_REFUSED", "SSH_GATE_REFUSED"},
		{"download web /etc/hosts --to -", "", ""}, // a stream to the key's own stdout saves nothing here
		{"download s3 backups/db.gz --to -", "", ""},
		{"download web /etc/hosts --to=-", "", ""},
		{"download web /etc/hosts --to ./-", "SSH_GATE_REFUSED", "SSH_GATE_REFUSED"},
		{"upload web - /tmp/app.conf", "", "SSH_GATE_READ_ONLY"}, // from the key's stdin, to a server
		{"storage upload s3 - backups/db.gz", "", "SSH_GATE_READ_ONLY"},
		{"cp - web:/tmp/app.conf", "", "SSH_GATE_READ_ONLY"},
		{"sync - web:/tmp/app", "SSH_GATE_REFUSED", "SSH_GATE_READ_ONLY"},   // to sync, - is a folder here
		{"cp web:/etc/hosts -", "", "SSH_GATE_READ_ONLY"},                   // cp is a change kind: read-only keys use download --to -
		{"sync web:/var/log/app -", "SSH_GATE_REFUSED", "SSH_GATE_REFUSED"}, // sync has no stream: - is a folder here
		{"database postgres backup pg --to /tmp/x.sql", "SSH_GATE_REFUSED", "SSH_GATE_REFUSED"},
		{"storage s3 object link s3 report.pdf", "", "SSH_GATE_READ_ONLY"},
		{"storage s3 object create s3 reports/2026", "", "SSH_GATE_READ_ONLY"},
		{"storage s3 object move s3 a.txt b.txt", "", "SSH_GATE_READ_ONLY"},
		{"storage s3 object move s3 a.txt --mode 0640", "", "SSH_GATE_READ_ONLY"},
		{"cluster kubernetes tunnel start k8s svc/web 8080", "", "SSH_GATE_READ_ONLY"},
		{"export web", "", ""},
		// nothing a key runs writes on the komando computer itself
		{"download web /home/u/.ssh/id_ed25519.pub --to .ssh/authorized_keys --overwrite", R, R},
		{"cp web:/tmp/rc .bashrc", R, R},
		{"cp ./app.tar.gz web:/tmp/app.tar.gz", R, "SSH_GATE_READ_ONLY"},
		{"sync ./site web:/var/www/site", R, "SSH_GATE_READ_ONLY"},
		{"sync web:/var/log/app ./logs", R, R},
		{"storage download s3 a.txt --to .profile", R, R},
		{"storage download s3 a.txt --to -", "", ""},
		{"export --to x.json", R, R},
		{"export", "", ""},
		{"conn add pg postgres://u@db/x", R, R},
		{"conn rm pg", R, R},
		{"host edit web --port 2222", R, R},
		{"host mv web web2", R, R},
		{"import komando x.json", R, R},
		{"host trust web", R, R},
		{"import", R, R},
		{"vpn openvpn add office --config x.ovpn", R, R},
		{"vpn openvpn edit office --notes x", R, R},
		{"vpn openvpn start office", "", "SSH_GATE_READ_ONLY"},
		{"group create web prod", R, R},
		{"rename --starts-with a b", R, R},
		{"config set audit off", R, R},
		{"policy create 'x'", R, R},
		{"policy remove x", R, R},
		{"status --short", "", ""},
		{"credential password remove db", R, R},
		{"config vault keychain", R, R},
		{"credential key create k", R, R},
		{"credential key add k ./id", R, R},
		{"credential key remove k", R, R},
		{"snippet create x 'id'", R, R},
		{"snippet remove my-df", R, R},
		{"agent skill install", R, R},
		{"agent skill uninstall", R, R},
		{"tunnel start web -L 8080:localhost:80", R, R},
		{"exec web --dry-run -- systemctl restart nginx", "", "SSH_GATE_READ_ONLY"},
		{"snippet exec my-clean web", "", "SSH_GATE_READ_ONLY"},
		{"logs web --unit nginx", "", ""},
		{"update", "SSH_GATE_REFUSED", "SSH_GATE_REFUSED"},
	}
	for _, c := range cases {
		if got := gateAnswer(t, c.line, false); got != c.full {
			t.Errorf("%q: %q, want %q", c.line, got, c.full)
		}
		if got := gateAnswer(t, c.line, true); got != c.readOnly {
			t.Errorf("%q --read-only: %q, want %q", c.line, got, c.readOnly)
		}
	}
	if !tcl.yes() || tcl.reveal() {
		t.Errorf("the gate's own flags changed: %+v", tcl.flags)
	}
}

// A read-only key runs a snippet only when the filled-in command reads, so
// the gate reads the blanks as the person typed them: a value with a comma
// or a double quote is one value, and blanks it cannot read are refused.
func TestGateSnippetBlanksAreReadAsTyped(t *testing.T) {
	invHome(t)
	gateInventory(t)
	// stored as a read-only snippet whose blank sits in a verb position;
	// with no --var it reads (the default), so only the values decide
	err := store.Update(store.Save(), func(st *store.State) error {
		st.Snippets["dk"] = &store.Snippet{Name: "dk", Command: "docker {{sub=ps}} ps", ReadOnly: true}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	setGate(tcl, true, gateYes)
	defer func() { setGate(tcl, false, gateYes) }()
	const RO = "SSH_GATE_READ_ONLY"
	for line, want := range map[string]string{
		"snippet exec dk web --var sub=ps":     "",
		"snippet exec dk web --var sub=a,b":    RO, // one value, "a,b": no read
		`snippet exec dk web --var 'sub="rm'`:  RO, // a quote does not drop the blank
		`snippet exec dk web --var 'sub=a,"b'`: RO,
		"snippet exec dk web --var sub":        RO, // no NAME=VALUE: the blanks could not be read
	} {
		if got := gateAnswer(t, line, true); got != want {
			t.Errorf("%q, read-only key: %q, want %q", line, got, want)
		}
	}
	words, _ := gateWords("snippet exec dk web --var sub")
	if _, _, e := gateCheck(words, gateKey{readOnly: true, network: true}); e == nil || !strings.Contains(e.Message, "the blanks could not be read") {
		t.Errorf("refusal: %+v", e)
	}
}

// A command on a target that is this computer runs here: exec on localhost
// is a shell, logs --file and fs cat read any file here, a sqlite conn is a
// file here (VACUUM INTO writes any file), a database, cache or cluster at
// 127.0.0.1 runs programs here. Reads are refused too, for every key.
func TestGateLocalTargets(t *testing.T) {
	invHome(t)
	gateInventory(t)
	t.Chdir(t.TempDir())
	const R = "SSH_GATE_REFUSED"
	for line, want := range map[string]string{
		`database sqlite query appdb --write "VACUUM INTO '/home/u/.ssh/authorized_keys2'"`: R,
		`database sqlite query appdb --write "ATTACH '/home/u/.bashrc' AS x"`:               R,
		"database sqlite restore appdb --from x.sql":                                        R,
		"db explain appdb --analyze 'select 1'":                                             R,
		"db user add appdb x --password-ref secret:x":                                       R,
		"database sqlite query appdb 'select 1'":                                            R, // a read of a file here
		"database postgres query pg --write 'delete from t'":                                "",
		`database postgres query pglocal --write "COPY t TO PROGRAM 'sh'"`:                  R,
		"database postgres query pgbehind --write 'delete from t'":                          "", // 127.0.0.1 of bastion
		"cache redis raw redislocal --write CONFIG SET dir /home/u/.ssh":                    R,
		"cache set redislocal a b":                                                          R,
		"cache redis raw c --write SET a b":                                                 "",
		"cluster apply k8slocal --file pod.yaml":                                            R,
		"cluster kubernetes raw k8slocal --write -- delete pod x":                           R,
		"cluster apply k8s --file pod.yaml":                                                 R, // reads a file here
		"storage upload sftplocal x.txt .ssh/authorized_keys":                               R,
		"storage sftp object create sftplocal x":                                            R, // the storage changes meet the local-target rule too
		"storage sftp object move sftplocal a.txt b.txt":                                    R,
		"storage sftp object move sftplocal a.txt --mode 0600":                              R,
		"registry oci image delete reglocal app:1":                                          R,
		"registry oci image copy reg:app:1 reglocal:app:1":                                  R,
		"registry oci image copy reg:app:1 reg:app:2":                                       "",
		"exec me -- id":                                                      R,
		"exec me --read-only -- uptime":                                      R, // a shell here all the same
		"exec lh -- id":                                                      R,
		"exec v6 -- id":                                                      R,
		"exec short -- id":                                                   R,
		"exec any -- id":                                                     R,
		"exec named -- id":                                                   R,
		"exec u@127.0.0.1 -- id":                                             R, // ad hoc, not in the inventory
		"exec 'u@[::1]:22' -- id":                                            R,
		"exec u@192.0.2.10 -- id":                                            R, // ad hoc: could be this computer's own address
		"exec 192.0.2.10:22 -- id":                                           R,
		"exec u@127.0.0.1.nip.io -- id":                                      R,
		"cp ./k u@192.0.2.10:/home/u/.ssh/authorized_keys":                   R,
		"logs u@192.0.2.10 --file /var/log/x":                                R, // reads too
		"exec web,me -- id":                                                  R,
		"exec @nothing -- id":                                                R, // cannot tell where: refused
		"exec behind -- id":                                                  "",
		"exec loop -- id":                                                    R, // 127.0.0.1 of a server that is this one
		"exec vpnd -- id":                                                    R, // through a VPN: may be this computer
		"exec web -- id":                                                     "",
		"fs write me /home/u/.bashrc":                                        R,
		"fs restore me /home/u/.bashrc":                                      R,
		"fs restore web /etc/nginx/nginx.conf":                               "", // the undo of fs replace --backup
		"docker raw me -- run -v /:/h x":                                     R,
		"cp ./id.pub me:/home/u/.ssh/x":                                      R,
		"cp me:/home/u/.ssh/id_ed25519 web:/tmp/k":                           R, // reads a file here
		"cp web:/tmp/k me:/home/u/.ssh/authorized_keys":                      R,
		"cp web:/tmp/k sftplocal:.ssh/authorized_keys":                       R,
		"cp web:/tmp/k web:/tmp/k2":                                          "",
		"download me /home/u/.ssh/id_ed25519 --to -":                         R, // a stream reads here too
		"storage download sftplocal .ssh/id_ed25519 --to -":                  R,
		"cp ./id_ed25519 -":                                                  R, // SRC on this computer, whatever DST is
		"cp me:/home/u/.ssh/id_ed25519 -":                                    R,
		"sync ./site web:/var/www":                                           R, // reads files here
		"snippet exec disk me":                                               R, // runs its command here
		"snippet exec disk web":                                              "",
		"database postgres query pghostparam --write 'select 1'":             R, // pgx dials ?host=
		"database postgres query pghostaddr --write 'select 1'":              R,
		"database postgres query pgsocket --write 'select 1'":                R, // a socket here
		"database postgres query pglist --write 'select 1'":                  R, // any host of the list
		"database postgres query pghostparam 'select 1'":                     R, // pg_read_file reads here
		"database mongodb query mongolist --write '{}'":                      R,
		"credential key install k me":                                        R,
		"credential key install k web":                                       "",
		"credential key install k web --set-default":                         R, // komando's own setup
		"vpn openvpn start office":                                           "",
		"cluster kubernetes raw k8s --write -- cp ns/pod:/x LOCAL":           R,
		"cluster kubernetes raw k8s --write -- cp ns/pod:/x ./x":             R,
		"cluster kubernetes raw k8s --write -- cp -n ns pod:/x /home/u/.ssh": R,
		"cluster kubernetes raw k8s --write -- cp ./x ns/pod:/x":             R, // reads files here
		"cluster kubernetes raw k8s --write -- cp ns/pod:/tmp/k x:/../.ssh/authorized_keys2": R, // a local path to kctl
		"cluster kubernetes raw k8s --write -- cp ns/pod:/x other/pod:/y":                    R,
		"cluster kubernetes raw k8s -- get pods":                                             "",
	} {
		if got := gateAnswer(t, line, false); got != want {
			t.Errorf("%q: %q, want %q", line, got, want)
		}
	}
	// exec and the like run a shell here for a read-only key too: its
	// --read-only check is a denylist, not a sandbox
	for line, want := range map[string]string{
		"exec u@127.0.0.1 --read-only -- 'socat - EXEC:id'":                 R,
		"exec me --read-only -- 'nc -e /bin/sh h 1'":                        R,
		"exec lh --script ./check.sh --read-only":                           R,
		"job start v6 --read-only -- du -sh /var":                           R,
		"docker exec me app --read-only ls":                                 R,
		"cluster kubernetes exec k8slocal pod/x --read-only -- ls":          R,
		"snippet exec disk me":                                              R,
		"exec web --read-only -- uptime":                                    "",
		"exec me -- id":                                                     "SSH_GATE_READ_ONLY", // not a read: refused before the place
		"database postgres query pglocal 'select 1'":                        R,                    // pg_read_file reads here
		"logs me --file /home/u/.ssh/id_ed25519 --grep '^[A-Za-z0-9+/=]+$'": R,
		"fs cat me /home/u/.ssh/id_ed25519":                                 R,
		"fs ls me /home/u/.ssh":                                             R,
		"fs stat lh /home/u/.ssh/id_ed25519":                                R,
		"cert check me --path /home/u/.ssh/id_ed25519":                      R,
		"cert check https://localhost:8443":                                 R,
		"cert check https://shop.example.com":                               "", // a website, not in the inventory
		"logs u@127.0.0.1":                                                  R,  // ad hoc
		"logs web --file /var/log/syslog":                                   "",
		"logs behind --file /var/log/syslog":                                "", // 127.0.0.1 of bastion
		"cache get redislocal a":                                            R,
		"cluster get k8slocal pods":                                         R,
		"docker ps me":                                                      R,
		"fs cat web /etc/hostname":                                          "",
		"cluster kubernetes raw k8s --write -- cp ./x ns/pod:/x":            "SSH_GATE_READ_ONLY",
	} {
		if got := gateAnswer(t, line, true); got != want {
			t.Errorf("%q --read-only key: %q, want %q", line, got, want)
		}
	}
	// the attack, through the gate as sshd runs it: nothing runs, the audit says why
	ran, _, e := gateRun(t, `komando database sqlite query appdb --write "VACUUM INTO '/home/u/.ssh/authorized_keys2'"`, "--name", "phone")
	if ran != nil || e == nil || e.Code != R || !strings.Contains(e.Message, "appdb is a file on this computer") {
		t.Errorf("VACUUM INTO: ran %q, error %+v", ran, e)
	}
	if a := lastAudit(t); a["blocked"] != R || a["runs"] != "database.sqlite.query" {
		t.Errorf("audit %v", a)
	}
}

func TestGateLocalAddr(t *testing.T) {
	me, _ := os.Hostname()
	for a, want := range map[string]bool{
		"localhost": true, "LocalHost.": true, "x.localhost": true, "127.0.0.1": true, "127.9.9.9:22": true,
		"[::1]:22": true, "::1": true, "0.0.0.0": true, "::": true, "::ffff:127.0.0.1": true, "127.1": true,
		"0x7f000001": true, "2130706433": true, me: true, "fe80::1%lo0": true, "[fe80::1%lo]:22": true,
		"fe80::1%en0": false, "10.0.0.5": false, "db.example.com": false,
		"10.0.0.5:5432": false, "": false, "localhost.example.com": false, "web1": false,
	} {
		if got := gateLocalAddr(a); got != want {
			t.Errorf("%q: %v, want %v", a, got, want)
		}
	}
}

// Every command a read-only key runs exists: a renamed one would silently
// leave the list.
func TestGateReadsExist(t *testing.T) {
	names := map[string]bool{}
	var walk func(c *cobra.Command)
	walk = func(c *cobra.Command) {
		names[commandName(c)] = true
		for _, sub := range c.Commands() {
			walk(sub)
		}
	}
	walk(newRoot(tcl))
	for k := range gateReadForm {
		n := keyID(k)
		if !names[n] {
			t.Errorf("gateReadForm names %q, which is no command", n)
		}
	}
	for k := range gateNotForReadKey {
		n := keyID(k)
		if !names[n] {
			t.Errorf("gateNotForReadKey names %q, which is no command", n)
		}
	}
	for k := range gateNeedsPerson {
		n := keyID(k)
		if !names[n] {
			t.Errorf("gateNeedsPerson names %q, which is no command", n)
		}
	}
	for k := range gateSavesHere {
		n := keyID(k)
		if !names[n] {
			t.Errorf("gateSavesHere names %q, which is no command", n)
		}
	}
	for k := range gateOnServers {
		n := keyID(k)
		k, ok := commandKinds[cmdKeys[n]]
		if !names[n] || !ok || k.Kind == kindRead {
			t.Errorf("gateOnServers names %q, which is no command that changes something (reads run anyway)", n)
		}
	}
}

// A change no list names is refused for every key: a command added later
// writes nothing on the komando computer until someone puts it in
// gateOnServers.
func TestGateFailsClosed(t *testing.T) {
	invHome(t)
	root := newRoot(tcl)
	c := &cobra.Command{Use: "brand-new", Run: func(*cobra.Command, []string) {}}
	root.AddCommand(c)
	fakeKind(t, "brand-new", changes)
	if _, e := gateRule(c, "brand-new", gateKey{network: true}); e == nil || e.Code != "SSH_GATE_REFUSED" || !strings.Contains(e.Message, "not on this computer") {
		t.Errorf("a new change: %+v", e)
	}
	fakeKind(t, "brand-new", reads)
	if _, e := gateRule(c, "brand-new", gateKey{network: true}); e != nil {
		t.Errorf("a new read: %+v", e)
	}
}

// The attack the rule is for: a key that may change things saves a file
// over the account's authorized_keys, and so gets a shell.
func TestSSHGateNoWritesHere(t *testing.T) {
	invHome(t)
	dir := t.TempDir()
	t.Chdir(dir) // sshd runs the gate in the account's home
	for _, line := range []string{
		"komando download web /tmp/k.pub --to .ssh/authorized_keys --overwrite",
		"komando cp web:/tmp/k.pub .ssh/authorized_keys --overwrite",
		"komando host add me u@127.0.0.1",
		"komando config set audit off --yes",
		"komando update",
	} {
		ran, _, e := gateRun(t, line, "--name", "phone")
		if ran != nil || e == nil || e.Code != "SSH_GATE_REFUSED" || !strings.Contains(e.Message, "not on this computer") {
			t.Errorf("%q: ran %q, error %+v", line, ran, e)
			continue
		}
		if a := lastAudit(t); a["ok"] != false || a["blocked"] != "SSH_GATE_REFUSED" {
			t.Errorf("%q: audit %v", line, a)
		}
	}
	if _, err := os.Stat(filepath.Join(dir, ".ssh")); err == nil {
		t.Error(".ssh was made")
	}
}

// With the audit setting off, a key's command is still in the log.
func TestSSHGateAuditAlways(t *testing.T) {
	invHome(t)
	setGate(tcl, true, gateYes)
	mustRun(t, "config", "set", "audit", "off", "--yes")
	setGate(tcl, false, gateYes)
	ran, _, e := gateRun(t, "komando list", "--name", "phone")
	if ran == nil {
		t.Fatalf("did not run: %+v", e)
	}
	if a := lastAudit(t); a == nil || a["command"] != "ssh-gate" || a["ssh_gate"] != "phone" {
		t.Errorf("audit %v", a)
	}
}

// What a key sent comes out escaped in `komando audit list`: a line break or a
// terminal escape in a quoted argument cannot add or hide rows.
func TestSSHGateAuditText(t *testing.T) {
	invHome(t)
	gateRun(t, "komando list 'x\n2026-01-01 00:00:00  alice  host.rm  web  ok\r\x1b[2K'", "--name", "phone")
	gateRun(t, "komando exec web --read-only -- 'a\n\x1b[1Ab'", "--name", "phone")
	d := mustRun(t, "audit", "list")
	var entries []map[string]any
	for _, e := range d["entries"].([]any) {
		entries = append(entries, e.(map[string]any))
	}
	text := auditList{Count: len(entries), Entries: entries}.Text()
	if n := strings.Count(text, "\n"); n != 3 || strings.ContainsAny(text, "\r\x1b") { // a header and two rows
		t.Errorf("%d lines, want 3:\n%q", n, text)
	}
	if got := auditCell("a\nb\x1b[0m\u202ec"); got != `a\nb\x1b[0m\u202ec` {
		t.Errorf("auditCell: %q", got)
	}
}

// gateRun runs `komando ssh-gate` as sshd would, for SSH_ORIGINAL_COMMAND
// line, and returns what it ran (nil when it ran nothing).
func gateRun(t *testing.T, line string, gateArgs ...string) (ran []string, env []string, e *out.Error) {
	t.Helper()
	t.Setenv("SSH_ORIGINAL_COMMAND", line)
	t.Setenv("SSH_CONNECTION", "203.0.113.7 51000 10.0.0.2 22")
	saved := gateExec
	defer func() { gateExec = saved }()
	gateExec = func(path string, argv, envv []string) error {
		ran, env = argv, envv
		return errors.New("stand-in for exec")
	}
	_, e = invRun(t, append([]string{"ssh-gate"}, gateArgs...)...)
	return ran, env, e
}

// lastAudit is the newest record in the audit log.
func lastAudit(t *testing.T) map[string]any {
	t.Helper()
	var last map[string]any
	for _, line := range strings.Split(auditText(t), "\n") {
		last = nil
		_ = json.Unmarshal([]byte(line), &last)
	}
	return last
}

func TestSSHGateRuns(t *testing.T) {
	invHome(t)
	ran, env, e := gateRun(t, "KOMANDO_AGENT=Komando komando list -o json", "--name", "phone")
	if !slices.Equal(ran, []string{"komando", "list", "-o", "json"}) {
		t.Fatalf("ran %q (%+v)", ran, e)
	}
	has := func(kv string) bool { return slices.Contains(env, kv) }
	if !has("KOMANDO_SSH_GATE=phone") || !has("KOMANDO_NO_DIALOG=1") || !has("KOMANDO_VAULT_PASS=test-passphrase-long-enough") {
		t.Errorf("env lacks the gate's variables or the vault passphrase")
	}
	for _, kv := range env {
		if strings.HasPrefix(kv, "SSH_ORIGINAL_COMMAND=") || strings.HasPrefix(kv, "KOMANDO_AGENT=") {
			t.Errorf("env passes %s on", kv)
		}
	}
	a := lastAudit(t)
	for k, want := range map[string]any{"command": "ssh-gate", "ok": true, "ssh_gate": "phone", "agent": "ssh-gate key phone",
		"runs": "list", "client": "203.0.113.7", "client_agent": "Komando", "read_only": false} {
		if a[k] != want {
			t.Errorf("audit %s = %v, want %v", k, a[k], want)
		}
	}
}

func TestSSHGateRefuses(t *testing.T) {
	invHome(t)
	for line, code := range map[string]string{
		"komando credential password show db --reveal": "SSH_GATE_REFUSED",
		"sh -c id":                   "SSH_GATE_REFUSED",
		"":                           "SSH_GATE_REFUSED",
		"komando list; id":           "SSH_GATE_SYNTAX",
		"komando exec web -- reboot": "SSH_GATE_READ_ONLY",
	} {
		ran, _, e := gateRun(t, line, "--name", "phone-read", "--read-only")
		if ran != nil || e == nil || e.Code != code {
			t.Errorf("%q: ran %q, error %+v, want %s", line, ran, e, code)
			continue
		}
		a := lastAudit(t)
		if a["ok"] != false || a["blocked"] != code || a["ssh_gate"] != "phone-read" || a["read_only"] != true || a["reason"] == "" {
			t.Errorf("%q: audit %v", line, a)
		}
	}
	if _, _, e := gateRun(t, "komando list", "--name", "bad name"); e == nil || e.Code != "USAGE" {
		t.Errorf("a bad --name: %+v", e)
	}
}

// A key whose line has no --shell-access opens no shell, also when its call has a
// terminal (pty added to its line by hand), and its audit records say
// nothing of a shell.
func TestSSHGateNoShellWithoutFlag(t *testing.T) {
	invHome(t)
	gateInventory(t)
	t.Setenv("SSH_TTY", "/dev/pts/3")
	saved := tcl.terminal
	t.Cleanup(func() { tcl.terminal = saved })
	tcl.terminal = true
	for _, args := range [][]string{{"--name", "full"}, {"--name", "read", "--read-only"}} {
		for _, line := range []string{"komando shell web", "komando ssh web", "komando database postgres shell pg", "komando cluster kubernetes shell k8s pod/x"} {
			ran, _, e := gateRun(t, line, args...)
			if ran != nil || e == nil || e.Code != "SSH_GATE_REFUSED" || !strings.Contains(e.Message, "needs a person at a terminal on this computer") {
				t.Errorf("%v %q: ran %q, error %+v", args, line, ran, e)
				continue
			}
			a := lastAudit(t)
			if _, has := a["shell_access"]; has || a["blocked"] != "SSH_GATE_REFUSED" {
				t.Errorf("%v %q: audit %v", args, line, a)
			}
		}
	}
	ran, _, e := gateRun(t, "komando list -o json", "--name", "full")
	if !slices.Equal(ran, []string{"komando", "list", "-o", "json"}) {
		t.Errorf("list with a terminal: ran %q, error %+v", ran, e)
	}
	if _, has := lastAudit(t)["shell_access"]; has {
		t.Errorf("audit of a key without --shell-access names a shell")
	}
}

// What a key sent is kept in the audit log with secret-looking values
// hidden, as other records are.
func TestSSHGateAuditHidesSecrets(t *testing.T) {
	invHome(t)
	gateRun(t, "komando conn add pg postgres://app:S3cretPw@db.lan/shop", "--name", "phone")
	a := lastAudit(t)
	if s, _ := a["ssh_command"].(string); strings.Contains(s, "S3cretPw") || !strings.Contains(s, "conn add pg") {
		t.Errorf("ssh_command %q", s)
	}
}

// The komando a key runs is an agent named after the key; a name ssh-gate
// could not have set is not shown as it is.
func TestGateAgentName(t *testing.T) {
	setCallerEnv(t, gateEnv, "phone")
	if got := tcl.caller().Agent; got != "ssh-gate key phone" {
		t.Errorf("agent %q", got)
	}
	setCallerEnv(t, "CLAUDECODE", "1") // set in the account's shell files, say
	if got := tcl.caller().Agent; got != "ssh-gate key phone" {
		t.Errorf("with CLAUDECODE too: agent %q", got)
	}
	os.Unsetenv("CLAUDECODE") // t.Setenv puts it back afterwards
	setCallerEnv(t, gateEnv, "x\n\nkomando list wants")
	if got := tcl.caller().Agent; got != "An SSH key through ssh-gate" {
		t.Errorf("agent %q", got)
	}
}

func TestSSHGateLine(t *testing.T) {
	unixOnly(t, "ssh-gate line writes an authorized_keys command= for a Unix shell; on Windows komando refuses it (SSH_GATE_PATH)")
	invHome(t)
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	sp, _ := ssh.NewPublicKey(pub)
	key := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(sp)))
	d := mustRun(t, "ssh-gate", "line", "--name", "phone", key+" my phone")
	line, _ := d["line"].(string)
	self := komandoPath()
	want := `restrict,command="` + gateShellQuote(self) + ` ssh-gate --name phone" ` + key + " my phone"
	if line != want || !filepath.IsAbs(self) {
		t.Errorf("line\n%s\nwant\n%s", line, want)
	}
	// the line is one sshd reads: restrict and the command, the same key
	got, _, opts, _, err := ssh.ParseAuthorizedKey([]byte(line))
	if err != nil || !slices.Equal(opts, []string{"restrict", `command="` + gateShellQuote(self) + ` ssh-gate --name phone"`}) || string(got.Marshal()) != string(sp.Marshal()) {
		t.Errorf("sshd would read %v %v", opts, err)
	}

	pf := filepath.Join(t.TempDir(), "phone.pub")
	os.WriteFile(pf, []byte(key+" from a file\n"), 0o600)
	d = mustRun(t, "ssh-gate", "line", "--name", "phone-read", "--read-only", pf)
	if l, _ := d["line"].(string); !strings.Contains(l, ` ssh-gate --name phone-read --read-only" `+key+" from a file") {
		t.Errorf("from a file, read-only: %s", l)
	}

	wantCode(t, "USAGE", "ssh-gate", "line", "--name", "phone", `restrict,command="sh" `+key)
	wantCode(t, "USAGE", "ssh-gate", "line", "--name", "phone", "not a key")
	wantCode(t, "USAGE", "ssh-gate", "line", "--name", "a b", key)
	if _, e := invRun(t, "ssh-gate", "line", key); e == nil {
		t.Error("no --name: accepted")
	}
}

// --shell-access: the line lets sshd give the key a terminal (pty), and the gate
// knows the key may open a shell. Only for a key that may change things.
func TestSSHGateLineShell(t *testing.T) {
	unixOnly(t, "ssh-gate line writes an authorized_keys command= for a Unix shell")
	invHome(t)
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	sp, _ := ssh.NewPublicKey(pub)
	key := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(sp)))
	d := mustRun(t, "ssh-gate", "line", "--name", "ops", "--shell-access", key+" ops key")
	command := `command="` + gateShellQuote(komandoPath()) + ` ssh-gate --name ops --shell-access"`
	if line, _ := d["line"].(string); line != "restrict,pty,"+command+" "+key+" ops key" || d["shell_access"] != true || d["read_only"] != false {
		t.Errorf("line %v", d)
	}
	line, _ := d["line"].(string)
	if _, _, opts, _, err := ssh.ParseAuthorizedKey([]byte(line)); err != nil || !slices.Equal(opts, []string{"restrict", "pty", command}) {
		t.Errorf("sshd would read %v %v", opts, err)
	}
	d = mustRun(t, "ssh-gate", "line", "--name", "phone", key)
	if l, _ := d["line"].(string); strings.Contains(l, "pty") || strings.Contains(l, "--shell") || d["shell_access"] != false {
		t.Errorf("without --shell-access: %v", d)
	}
	for _, args := range [][]string{{"--read-only"}, {"--read-only", "--network"}} {
		e := wantCode(t, "USAGE", append(append([]string{"ssh-gate", "line", "--name", "ops", "--shell-access"}, args...), key)...)
		if !strings.Contains(e.Message, "--read-only") {
			t.Errorf("--shell-access %v: %+v", args, e)
		}
	}
}

func TestGateShellQuote(t *testing.T) {
	for in, want := range map[string]string{
		"/usr/local/bin/komando":       "/usr/local/bin/komando",
		"/Users/Jo Doe/go/bin/komando": "'/Users/Jo Doe/go/bin/komando'",
		"/opt/it's/komando":            `'/opt/it'\''s/komando'`,
	} {
		if got := gateShellQuote(in); got != want {
			t.Errorf("%q: %q, want %q", in, got, want)
		}
	}
}

// ssh-gate typed by a person (no sshd around it) shows how to set it up:
// no safety stop, no audit record of a key named "key".
func TestSSHGateBareAtATerminal(t *testing.T) {
	invHome(t)
	t.Setenv("SSH_ORIGINAL_COMMAND", "")
	t.Setenv("SSH_CONNECTION", "")
	_, e := invRun(t, "ssh-gate")
	if e == nil || e.Code != "USAGE" || !strings.Contains(e.Message, "ssh-gate line") {
		t.Fatalf("bare ssh-gate: %+v", e)
	}
	if _, err := os.Stat(store.Path("audit.jsonl")); err == nil {
		if a := lastAudit(t); a["command"] == "ssh-gate" {
			t.Errorf("audited: %v", a)
		}
	}
	// run by sshd for a key that asked for nothing: refused and audited
	_, _, e = gateRun(t, "", "--name", "phone")
	if e == nil || e.Code != "SSH_GATE_REFUSED" || lastAudit(t)["ssh_gate"] != "phone" {
		t.Errorf("sshd, no command: %+v", e)
	}
}

// A synonym (cluster info, tunnel show) gets the
// gate's answer of the command it names, for a full key and a read-only
// one: it carries that command's ID, so it is not refused as plumbing
// (review F12).
func TestGateSynonyms(t *testing.T) {
	invHome(t)
	gateInventory(t)
	for syn, now := range map[string]string{
		"cluster info k8s": "cluster status k8s",
		"tunnel show t1":   "tunnel list",
	} {
		for _, ro := range []bool{false, true} {
			if got, want := gateAnswer(t, syn, ro), gateAnswer(t, now, ro); got != want {
				t.Errorf("%q (read-only %v): %q, want %q as for %q", syn, ro, got, want, now)
			}
		}
	}
}

// A line that names no command is refused as for a person (cut plan, PR
// B1): komando would run nothing either way, and once the paths change an
// old path must not slip through as "unknown, so harmless".
func TestGateRefusesUnknownLine(t *testing.T) {
	invHome(t)
	gateInventory(t)
	for _, line := range []string{"frobnicate web", "hots list", "host frobnicate web", "db user frobnicate pg"} {
		for _, key := range []gateKey{readKey, netReadKey, fullKey} {
			words, _ := gateWords(line)
			_, _, e := gateCheck(words, key)
			if e == nil || e.Code != "SSH_GATE_REFUSED" || !strings.Contains(e.Hint, "a person") {
				t.Errorf("%q %+v: %+v, want SSH_GATE_REFUSED for a person", line, key, e)
			}
		}
	}
	// a group alone, or with --help, still prints its help
	for _, line := range []string{"host", "db user", "host --help"} {
		words, _ := gateWords(line)
		if _, _, e := gateCheck(words, fullKey); e != nil {
			t.Errorf("%q: %+v, want its help", line, e)
		}
	}
}
