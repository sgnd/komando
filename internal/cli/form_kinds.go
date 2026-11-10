package cli

import (
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/sgnd/komando/internal/sshx"
	"github.com/sgnd/komando/internal/store"
)

// formGroups is the first list of Add: what it is, in plain words, with
// the products it covers beside it.
func formGroups() []formGroup {
	return []formGroup{
		{"Server", "a Linux or Windows machine you log in to", []formKind{{"Server", "", serverForm}}, ""},
		{"Databases", "PostgreSQL, MySQL, SQL Server, Oracle, MongoDB, ClickHouse, Snowflake, BigQuery, SQLite", dbForms(), "Which database?"},
		{"Caches", "Redis, Valkey, Memcached", cacheForms(), "Which cache?"},
		{"Queues", "Kafka, RabbitMQ, NATS, Amazon SQS, Google Pub/Sub", queueForms(), "Which message queue?"},
		{"File storage", "a cloud bucket (S3, R2, Google, Azure) or a file server (SFTP, FTP, WebDAV, Windows share)", storageForms(), "A cloud bucket or a file server?"},
		{"Clusters", "Kubernetes or Docker Swarm", clusterForms(), "Kubernetes or Docker Swarm?"},
		{"Images (registries)", "Docker Hub, GitHub, GitLab, AWS, Azure, Google, your own", registryForms(), "Which container registry?"},
		{"VPN", "your company's VPN app, WireGuard, OpenVPN, Tailscale", vpnForms(), "Which VPN app does your company use?"},
	}
}

// formGroupsFor is the groups `komando KIND add` offers when typed alone:
// host add asks for a server, vpn add for a VPN, conn add for the rest.
func formGroupsFor(kind string) []formGroup {
	var gs []formGroup
	for _, g := range formGroups() {
		switch {
		case kind == "host" && g.label == "Server",
			kind == "vpn" && g.label == "VPN",
			kind == "conn" && g.label != "Server" && g.label != "VPN":
			gs = append(gs, g)
		}
	}
	return gs
}

// formFamilyAdd is each `komando FAMILY add` and its Add group.
var formFamilyAdd = map[string]string{
	"db add": "Databases", "cache add": "Caches", "queue add": "Queues",
	"storage add": "File storage", "cluster add": "Clusters", "registry add": "Images (registries)",
}

// formGroupNamed is the one Add group with this label.
func formGroupNamed(label string) []formGroup {
	for _, g := range formGroups() {
		if g.label == label {
			return []formGroup{g}
		}
	}
	return nil
}

// Questions every kind shares.

// formNameQ asks the name komando will know it by.
func formNameQ(kind, what, example string) formQ {
	return formQ{key: "name", label: "Name", ask: "What do you want to call this " + what + "?",
		help:    "A short name you type later, like komando test " + example + ". Letters, digits, dot, dash, underscore.",
		example: example,
		check:   func(st *store.State, _ formAnswers, v string) string { return formNameProblem(st, kind, v) }}
}

// formNameProblem is what is wrong with a new name: its letters, "all", or
// a server, service or VPN that has it already (names are shared, any case).
func formNameProblem(st *store.State, kind, v string) string {
	if err := validName(kind, v); err != nil {
		if strings.EqualFold(v, "all") {
			return `"all" means everything in komando; pick another name`
		}
		return "use letters, digits, dot, dash and underscore, starting with a letter or digit (at most 63)"
	}
	if k, existing, ok := st.FindName(v); ok {
		return fmt.Sprintf("%s is already a %s; pick another name, like %s", existing, formKindWord(k), formFreeName(st, v))
	}
	return ""
}

func formKindWord(k string) string {
	return map[string]string{"host": "server", "conn": "service", "vpn": "VPN"}[k]
}

// formFreeName is base with the first number after it that no server,
// conn or VPN uses: web1 gives web2.
func formFreeName(st *store.State, base string) string {
	stem := strings.TrimRight(base, "0123456789")
	if stem == "" {
		stem = base + "-"
	}
	for n := 2; ; n++ {
		c := stem + strconv.Itoa(n)
		if _, _, ok := st.FindName(c); !ok && validName("host", c) == nil {
			return c
		}
	}
}

// formProtectQ asks whether mistakes there would hurt: yes protects it, so
// every change needs a person's yes (an AI agent's too). Yes comes first:
// a test box asked once too often costs a keypress, a production server
// left open can cost an outage.
func formProtectQ(what string) formQ {
	return formQ{key: "protected", label: "Production", ask: "Can a mistake on this " + what + " hurt real users or real data?",
		help: "Production: komando asks you before every change, and an AI agent needs your yes in a window.",
		def:  func(*store.State, formAnswers) string { return "yes" },
		choices: func(*store.State, formAnswers) []menuRow {
			return []menuRow{{label: "Yes, protect it", detail: "komando asks you before every change", value: "yes"},
				{label: "No", detail: "a test machine, or only mine", value: "no"}}
		}}
}

// formViaQ asks how this computer reaches it: directly, or through one of
// the servers or VPNs komando knows (--via). It is not asked while komando
// knows none.
func formViaQ(what string, advanced bool) formQ {
	return formQ{key: "via", label: "Reached", advanced: advanced,
		ask:  "How does this computer reach the " + what + "?",
		help: "Pick a server when the " + what + " only answers on that server or inside its network.",
		def:  func(*store.State, formAnswers) string { return "" },
		choices: func(st *store.State, _ formAnswers) []menuRow {
			rows := []menuRow{{label: "Directly", detail: "it answers on the network from here", value: ""}}
			for _, n := range menuNames(st.Hosts, "host") {
				rows = append(rows, menuRow{label: "Through " + n, detail: "the server " + n, value: n})
			}
			for _, n := range menuNames(st.Vpns, "vpn") {
				rows = append(rows, menuRow{label: "Through " + n, detail: "the VPN " + n, value: n})
			}
			return rows
		}}
}

// formHasVia: komando knows a server or VPN to go through.
func formHasVia(st *store.State) bool { return len(st.Hosts)+len(st.Vpns) > 0 }

// formYesNoQ is a question answered with yes or no.
func formYesNoQ(key, label, ask, help, def, yes, no string) formQ {
	return formQ{key: key, label: label, ask: ask, help: help,
		def: func(*store.State, formAnswers) string { return def },
		choices: func(*store.State, formAnswers) []menuRow {
			return []menuRow{{label: "Yes", detail: yes, value: "yes"}, {label: "No", detail: no, value: "no"}}
		}}
}

// formMore moves q under More options.
func formMore(q formQ) formQ {
	q.advanced = true
	return q
}

// formGroupQ and formNotesQ are More options every kind has.
func formGroupQ() formQ {
	return formQ{key: "group", label: "Group", ask: "Put it in a group?", advanced: true, optional: true,
		help: "A group lets one command reach many, like komando test @web. Empty for none.", example: "web",
		check: func(_ *store.State, _ formAnswers, v string) string {
			if validName("group", v) != nil {
				return "use letters, digits, dot, dash and underscore"
			}
			return ""
		}}
}

func formNotesQ() formQ {
	return formQ{key: "notes", label: "Notes", ask: "Any notes for later?", advanced: true, optional: true,
		help: "Free text, shown in komando show and to AI agents. Never put a password here."}
}

// formAddressProblem checks a host name or IP: no URL, no user, no
// spaces. A port after it (host:port, [IPv6]:port) is left to the caller,
// as a list of Sentinels has one; formServiceHostQ refuses it.
func formAddressProblem(v string) string {
	switch {
	case strings.Contains(v, "://"):
		return "type only the address, like db.example.com, without http:// or another scheme"
	case strings.ContainsAny(v, " \t/@"):
		return "type only the address, like 10.0.0.5 or db.example.com"
	case strings.HasPrefix(v, "-"):
		return "an address cannot start with -"
	case strings.Count(v, "[") != strings.Count(v, "]") || strings.Count(v, "[") > 1:
		return "an IPv6 address goes in [ ] only with a port after it, like [fd00::5]:6379"
	}
	return ""
}

// formPortProblem checks a port number.
func formPortProblem(_ *store.State, _ formAnswers, v string) string {
	if p, err := strconv.Atoi(v); err != nil || p < 1 || p > 65535 {
		return "a port is a number from 1 to 65535"
	}
	return ""
}

// formFileProblem checks a file on this computer.
func formFileProblem(v string) string {
	fi, err := os.Stat(expandHome(v))
	switch {
	case err != nil:
		return "there is no file at " + v + "; check the path (~/ means your home folder)"
	case fi.IsDir():
		return v + " is a folder; give the file in it"
	}
	return ""
}

// formAbs is a path as komando should store it: ~ expanded, absolute.
func formAbs(p string) string {
	if abs, err := filepath.Abs(expandHome(p)); err == nil {
		return abs
	}
	return p
}

// formHostPort joins an address and a port, leaving out the usual one.
func formHostPort(host, port, usual string) string {
	if port == "" || port == usual {
		if strings.Contains(host, ":") { // IPv6
			return "[" + host + "]"
		}
		return host
	}
	return net.JoinHostPort(host, port)
}

// formFlags adds the More options every kind shares and --protected.
func formFlags(args []string, a formAnswers) []string {
	if a["via"] != "" {
		args = append(args, "--via", a["via"])
	}
	if a["protected"] == "yes" {
		args = append(args, "--protected")
	}
	if a["group"] != "" {
		args = append(args, "-g", a["group"])
	}
	if a["notes"] != "" {
		args = append(args, "--notes", a["notes"])
	}
	return args
}

// formIsLocal: an address on the same machine.
func formIsLocal(host string) bool {
	return host == "localhost" || host == "127.0.0.1" || host == "::1"
}

// Server.

// serverForm asks for a server in the order people think of it: a name,
// the address, the user, what it runs, then how to log in. A Windows
// server is reached over OpenSSH or WinRM (form_winserver.go).
func serverForm() formSpec {
	ssh := func(a formAnswers) bool { return !serverWinRM(a) }
	return formSpec{title: "Add a server", qs: []formQ{
		formNameQ("host", "server", "web1"),
		{key: "address", label: "Address", ask: "What is the server's address?", addr: true,
			help:    "Its IP address or host name, from your hosting panel or cloud console.",
			example: "203.0.113.20 or vps.example.com", check: serverAddressProblem},
		{key: "user", label: "User", ask: "Which user do you log in as?",
			help:    "The login name on the server. Many VPS use root; Ubuntu cloud servers use ubuntu; Windows uses Administrator, or user@domain for a domain user.",
			example: "root", def: serverUserDefault, check: serverUserProblem},
		serverOSQ(), serverTransportQ(),
		formWhen(formQ{key: "port", label: "Port", ask: "Which SSH port does it use?",
			help: "Almost always 22. Change it only if your provider gave you another number.",
			def: func(_ *store.State, a formAnswers) string {
				if h, err := sshx.ParseAdhoc(a["address"]); err == nil && h.Port != 0 {
					return strconv.Itoa(h.Port)
				}
				return "22"
			}, check: formPortProblem}, ssh),
		serverWinRMTLSQ(), serverWinRMPortQ(),
		formWhen(formQ{key: "login", label: "Login", ask: "How do you log in?", def: serverLoginDefault, choices: serverLoginChoices,
			help: "Not sure? Pick the first: komando tries your keys and asks for a password if none works."}, ssh),
		formWhen(formQ{key: "identity", label: "Key file", ask: "Where is the key file?",
			help:    "The private key file, often ending in .pem. Not the .pub file.",
			example: "~/Downloads/my-vps.pem", show: func(a formAnswers) bool { return a["login"] == "file" },
			check: func(_ *store.State, _ formAnswers, v string) string {
				if strings.HasSuffix(v, ".pub") {
					return "that is the public half (.pub); give the private key file next to it"
				}
				return formFileProblem(v)
			}}, ssh),
		formWhen(formQ{key: "key", label: "Key", ask: "Which of your komando keys?", show: func(a formAnswers) bool { return a["login"] == "keylist" },
			choices: func(st *store.State, _ formAnswers) []menuRow {
				var rows []menuRow
				for _, n := range menuNames(st.Keys, "key") {
					rows = append(rows, menuRow{label: n, value: n})
				}
				return rows
			}}, ssh),
		formMore(formProtectQ("server")),
		serverJumpQ(),
		formWhen(formMore(formYesNoQ("code", "One-time code", "Does it also ask for a one-time code when you log in?",
			"A 6-digit code from an app like Google Authenticator. Most servers do not.", "no",
			"after adding, komando login keeps one login for 8 hours", "after adding, komando tests it")), ssh),
		formGroupQ(), formNotesQ(),
	}, build: serverBuild}
}

// serverJumpQ is the server's via question: another server it is reached
// through (a jump host), or a VPN.
func serverJumpQ() formQ {
	q := formViaQ("server", true)
	q.label, q.ask = "Jump host", "Through another server (a jump host)?"
	q.help = "Pick a server or VPN when this server only answers from inside that network."
	return q
}

// serverUserDefault is the user in a pasted address (root@...), else
// Administrator on Windows.
func serverUserDefault(_ *store.State, a formAnswers) string {
	if h, err := sshx.ParseAdhoc(a["address"]); err == nil && strings.Contains(a["address"], "@") {
		return h.User
	}
	if a["os"] == "windows" {
		return "Administrator"
	}
	return ""
}

func serverUserProblem(_ *store.State, _ formAnswers, v string) string {
	if i := strings.Index(v, `\`); i > 0 {
		return "write a domain user as user@domain with the domain's full name, like " + v[i+1:] + "@corp.example.com"
	}
	if validUser(v) != nil {
		return "a user name has letters, digits, dot, dash and underscore, and no spaces or colon"
	}
	return ""
}

// serverAddressProblem accepts what people paste: 10.0.0.5, a host name,
// root@10.0.0.5 or 10.0.0.5:2222 (the user and port become the next
// answers' defaults), and says what to do with a URL.
func serverAddressProblem(_ *store.State, _ formAnswers, v string) string {
	if strings.Contains(v, "://") {
		if strings.HasPrefix(strings.ToLower(v), "winrm://") {
			return "type it without winrm://; komando adds it when you pick WinRM (Esc goes back to that question)"
		}
		if strings.HasPrefix(v, "ssh://") {
			return "type it without ssh://, like root@vps.example.com"
		}
		return "this looks like a web address or a database URL; for a server type only its address. A database: Esc back to the list, then Database"
	}
	if strings.HasPrefix(v, "-") || strings.ContainsAny(v, " \t/") {
		return "type only the address, like 203.0.113.20 or vps.example.com"
	}
	h, err := sshx.ParseAdhoc(v)
	if err != nil || h.Address == "" {
		return "type only the address, like 203.0.113.20 or vps.example.com"
	}
	return ""
}

// serverLoginDefault is "usual" when this computer has an SSH key or an
// agent, else "password".
func serverLoginDefault(*store.State, formAnswers) string {
	if os.Getenv("SSH_AUTH_SOCK") != "" {
		return "usual"
	}
	home, _ := os.UserHomeDir()
	for _, k := range []string{"id_ed25519", "id_ecdsa", "id_rsa"} {
		if _, err := os.Stat(filepath.Join(home, ".ssh", k)); err == nil {
			return "usual"
		}
	}
	return "password"
}

func serverLoginChoices(st *store.State, _ formAnswers) []menuRow {
	rows := []menuRow{
		{label: "My SSH key", detail: "the key in ~/.ssh or ssh-agent, as ssh uses it", value: "usual"},
		{label: "A password", detail: "you type it next, hidden; komando keeps it as a saved password", value: "password"},
		{label: "A key file", detail: "a file somewhere else, like a .pem from your cloud provider", value: "file"},
	}
	if len(st.Keys) > 0 {
		rows = append(rows, menuRow{label: "A komando key", detail: "one from komando key list", value: "keylist"})
	}
	return rows
}

func serverBuild(_ *store.State, a formAnswers) [][]string {
	if serverWinRM(a) {
		return serverWinRMBuild(a)
	}
	addr := a["address"]
	if h, err := sshx.ParseAdhoc(addr); err == nil {
		addr = h.Address
	}
	if strings.Contains(addr, ":") {
		addr = "[" + addr + "]"
	}
	args := []string{"host", "add", a["name"], a["user"] + "@" + addr}
	if a["port"] != "" && a["port"] != "22" {
		args = append(args, "--port", a["port"])
	}
	if a["os"] == "windows" {
		args = append(args, "--os", "windows")
	}
	switch a["login"] {
	case "password":
		args = append(args, "--ask-password")
	case "file":
		args = append(args, "--identity", formAbs(a["identity"]))
	case "keylist":
		args = append(args, "--key", a["key"])
	}
	next := []string{"test", a["name"]}
	if a["code"] == "yes" {
		next = []string{"login", a["name"]}
	}
	return [][]string{formFlags(args, a), next}
}

// Databases.

func dbForms() []formKind {
	return []formKind{
		{"PostgreSQL", "also Amazon RDS, Supabase, Neon, Cloud SQL", func() formSpec { return sqlForm("postgres", "PostgreSQL", "5432") }},
		{"MySQL or MariaDB", "also Amazon RDS, PlanetScale", func() formSpec { return sqlForm("mysql", "MySQL", "3306") }},
		{"SQL Server", "also Azure SQL Managed Instance", sqlServerForm},
		{"Oracle Database", "19c and later, also Oracle Database Free", oracleForm},
		{"MongoDB", "also MongoDB Atlas", mongoForm},
		{"ClickHouse", "also ClickHouse Cloud", clickhouseForm},
		{"Snowflake", "a cloud data warehouse", snowflakeForm},
		{"Google BigQuery", "a cloud data warehouse, with your Google login", bigqueryForm},
		{"SQLite", "a database file on this computer", sqliteForm},
	}
}

// sqlForm is PostgreSQL and MySQL: the same questions, a different scheme
// and port.
func sqlForm(scheme, product, port string) formSpec {
	return formSpec{title: "Add a " + product + " database", qs: []formQ{
		formNameQ("conn", "database", "app-db"),
		formReachQ("database"),
		formServiceHostQ("database server", "10.0.0.5 or db.example.com"),
		{key: "port", label: "Port", ask: "Which port does it listen on?", help: "The usual " + product + " port is " + port + ".",
			def: func(*store.State, formAnswers) string { return port }, check: formPortProblem},
		{key: "user", label: "User", ask: "Which database user do you log in with?", example: "app",
			help: "The user name the database knows you by, not your SSH user."},
		{key: "database", label: "Database", ask: "Which database inside the server?", optional: true, example: "app",
			help: "One server holds several databases. Empty uses the server's default."},
		formYesNoQ("password", "Password", "Does this user log in with a password?",
			"Almost always yes. komando asks for it after this, hidden, and keeps it as a saved password.", "yes",
			"you type it next, hidden", "no password (trust or peer login)"),
		formProtectQ("database"),
		dbTLSQ(),
		formGroupQ(), formNotesQ(),
	}, build: func(_ *store.State, a formAnswers) [][]string {
		u := url.URL{Scheme: scheme, User: url.User(a["user"]), Host: formHostPort(a["host"], a["port"], port)}
		if a["database"] != "" {
			u.Path = "/" + a["database"]
		}
		q := url.Values{}
		switch {
		case scheme == "postgres" && a["tls"] == "nocheck":
			q.Set("sslmode", "require")
		case scheme == "postgres" && a["tls"] == "off":
			q.Set("sslmode", "disable")
		case scheme == "mysql" && a["tls"] == "nocheck":
			q.Set("tls", "skip-verify")
		case scheme == "mysql" && a["tls"] == "off":
			q.Set("tls", "false")
		}
		u.RawQuery = q.Encode()
		return formConnBuild(a, u.String(), a["password"] == "yes")
	}}
}

// dbTLSQ asks, under More options, how a database connection is
// encrypted: "" lets conn add choose (checked TLS over a network),
// "nocheck" encrypts without checking, "off" sends it unencrypted.
func dbTLSQ() formQ {
	return formQ{key: "tls", label: "Encryption", ask: "How should the connection be encrypted?", advanced: true,
		help: "Leave it to komando unless the server has no TLS or a certificate it made itself.",
		def:  func(*store.State, formAnswers) string { return "" },
		choices: func(*store.State, formAnswers) []menuRow {
			return []menuRow{{label: "komando decides", detail: "checked TLS over a network, none on the same machine", value: ""},
				{label: "Encrypt, do not check", detail: "for a certificate the server made itself", value: "nocheck"},
				{label: "No encryption", detail: "only inside a network you trust", value: "off"}}
		}}
}

// formConnBuild is conn add for the answers, then a test.
func formConnBuild(a formAnswers, rawURL string, askPassword bool) [][]string {
	args := []string{"conn", "add", a["name"], rawURL}
	if askPassword {
		args = append(args, "--ask-password")
	}
	return [][]string{formFlags(args, a), {"test", a["name"]}}
}

// formReachQ asks how this computer reaches a service: directly, or
// through a server it runs on (most databases only listen there). It is
// asked only while komando knows a server or VPN.
func formReachQ(what string) formQ {
	q := formViaQ(what, false)
	q.help = "Many " + what + "s only answer on their own server: then pick that server."
	q.when = formHasVia
	return q
}

// formServiceHostQ asks a service's address alone: the port is the next
// question. Through a server, the usual answer is that server itself
// (127.0.0.1); through a VPN there is no usual answer.
func formServiceHostQ(what, example string) formQ {
	return formQ{key: "host", label: "Address", ask: "What is the " + what + "'s address?", addr: true, example: example,
		help: "Through a server, 127.0.0.1 means that server itself. Through a VPN, type its address inside the VPN's network.",
		def: func(st *store.State, a formAnswers) string {
			if st != nil && st.Hosts[a["via"]] != nil {
				return "127.0.0.1"
			}
			return ""
		},
		check: func(_ *store.State, a formAnswers, v string) string { return formServiceHostProblem(a, v) }}
}

func mongoForm() formSpec {
	atlas := func(a formAnswers) bool { return a["flavor"] == "atlas" }
	self := func(a formAnswers) bool { return !atlas(a) }
	return formSpec{title: "Add a MongoDB database", qs: []formQ{
		formNameQ("conn", "database", "shop-db"),
		{key: "flavor", label: "Kind", ask: "Where does it run?",
			def: func(*store.State, formAnswers) string { return "self" },
			choices: func(*store.State, formAnswers) []menuRow {
				return []menuRow{{label: "On a server", detail: "your own MongoDB, or one in Docker", value: "self"},
					{label: "MongoDB Atlas", detail: "an address like cluster0.abcde.mongodb.net", value: "atlas"}}
			}},
		formWhen(formReachQ("database"), self),
		formServiceHostQ("database", "10.0.0.5 or cluster0.abcde.mongodb.net"),
		formWhen(formQ{key: "port", label: "Port", ask: "Which port does it listen on?", help: "The usual MongoDB port is 27017.",
			def: func(*store.State, formAnswers) string { return "27017" }, check: formPortProblem}, self),
		{key: "user", label: "User", ask: "Which database user do you log in with?", optional: true, example: "app",
			help: "Empty when the database needs no login."},
		{key: "database", label: "Database", ask: "Which database should commands use?", optional: true, example: "shop"},
		formWhen(formYesNoQ("password", "Password", "Does this user log in with a password?",
			"komando asks for it after this, hidden, and keeps it as a saved password.", "yes",
			"you type it next, hidden", "no password"), func(a formAnswers) bool { return a["user"] != "" }),
		formWhen(formQ{key: "authsource", label: "User's database", ask: "In which database was this user created?",
			help: "Usually admin. Wrong here, and the login fails with a clear message.",
			def:  func(*store.State, formAnswers) string { return "admin" }},
			func(a formAnswers) bool { return self(a) && a["user"] != "" && a["database"] != "" }),
		formWhen(formYesNoQ("tls", "Encryption", "Does the server use TLS (encryption)?",
			"Over the internet it should. Inside a private network or on the same server, often not.", "yes",
			"encrypted and checked", "not encrypted"), self),
		formProtectQ("database"),
		formGroupQ(), formNotesQ(),
	}, build: mongoBuild}
}

// formWhen asks q only while ok says so (and while its own show does).
func formWhen(q formQ, ok func(formAnswers) bool) formQ {
	show := q.show
	q.show = func(a formAnswers) bool { return ok(a) && (show == nil || show(a)) }
	return q
}

func mongoBuild(_ *store.State, a formAnswers) [][]string {
	u := url.URL{Scheme: "mongodb", Host: formHostPort(a["host"], a["port"], "27017")}
	if a["flavor"] == "atlas" {
		u.Scheme, u.Host = "mongodb+srv", a["host"]
	}
	if a["user"] != "" {
		u.User = url.User(a["user"])
	}
	if a["database"] != "" {
		u.Path = "/" + a["database"]
	}
	q := url.Values{}
	if a["authsource"] != "" && a["flavor"] != "atlas" && a["user"] != "" && a["database"] != "" {
		q.Set("authSource", a["authsource"])
	}
	if a["tls"] == "yes" && a["flavor"] != "atlas" {
		q.Set("tls", "true")
	}
	u.RawQuery = q.Encode()
	return formConnBuild(a, u.String(), a["user"] != "" && a["password"] != "no")
}

func sqliteForm() formSpec {
	return formSpec{title: "Add a SQLite database", qs: []formQ{
		formNameQ("conn", "database", "app-db"),
		{key: "path", label: "File", ask: "Where is the database file on this computer?", example: "~/projects/app/data.db",
			help:  "The .db or .sqlite file. ~/ means your home folder.",
			check: func(_ *store.State, _ formAnswers, v string) string { return formFileProblem(v) }},
		formProtectQ("database"),
		formGroupQ(), formNotesQ(),
	}, build: func(_ *store.State, a formAnswers) [][]string {
		return formConnBuild(a, "sqlite://"+filepath.ToSlash(formAbs(a["path"])), false)
	}}
}

// The add commands use the hand-made forms above from every menu path.
func init() {
	addFormHints(map[string]formHint{
		"host add": {form: func() []formGroup { return formGroupsFor("host") }},
		"conn add": {form: func() []formGroup { return formGroupsFor("conn") }},
		"vpn add":  {form: func() []formGroup { return formGroupsFor("vpn") }},
	})
	// db add, cache add, ...: conn add for one family, asked the same way.
	for cmd, label := range formFamilyAdd {
		addFormHints(map[string]formHint{cmd: {form: func() []formGroup { return formGroupNamed(label) }}})
	}
}
