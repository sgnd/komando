package cli

import (
	"net"
	"net/url"
	"slices"
	"strconv"
	"strings"

	"github.com/sgnd/komando/internal/store"
	"github.com/sgnd/komando/internal/vault"
)

// cacheForms are the Add forms for caches. The usual path is short: a
// name, how it is reached, the address, the port, TLS only when it is
// reached directly over the network, and the password. Cluster, Sentinel,
// a database number, an ACL user and a private CA are under More options.
func cacheForms() []formKind {
	return []formKind{
		{"Redis or Valkey", "also Amazon ElastiCache, Upstash, Azure Cache", redisForm},
		{"Memcached", "a memory cache, often next to a website", memcachedForm},
	}
}

func redisForm(_ *call) formSpec {
	sentinel := func(a formAnswers) bool { return a["setup"] == "sentinel" }
	return formSpec{title: "Add a Redis cache", qs: []formQ{
		formNameQ("conn", "cache", "shop-cache"),
		formReachQ("cache"),
		cacheHostQ(),
		{key: "port", label: "Port", ask: "Which port does it listen on?",
			help: "The usual Redis port is 6379. Change it only if your provider shows another (Azure uses 6380).",
			def:  func(*store.State, formAnswers) string { return "6379" }, check: formPortProblem},
		cacheTLSQ("redis"),
		cachePasswordQ("Does the cache need a password?",
			"The requirepass or ACL password, from your provider or redis.conf.", "ask", false),
		cacheSecretQ(false),
		formProtectQ("cache"),
		cacheTLSViaQ(),
		formMore(formQ{key: "user", label: "User", ask: "Which user do you log in as?", optional: true, example: "app",
			help:  "Only for Redis 6 or newer with ACL users. Empty when you only have a password.",
			check: cacheUserProblem}),
		{key: "setup", label: "Setup", ask: "How is Redis set up?", advanced: true,
			def: func(*store.State, formAnswers) string { return "single" },
			choices: func(*store.State, formAnswers) []pickRow {
				return []pickRow{{label: "One server", detail: "the usual case", value: "single"},
					{label: "Redis Cluster", detail: "data spread over several nodes; Address is any one node", value: "cluster"},
					{label: "Behind Sentinels", detail: "Address is a Sentinel; port 26379 unless you set another", value: "sentinel"}}
			}},
		formWhen(formMore(formQ{key: "db", label: "Database number", ask: "Which database number?", optional: true,
			help: "Redis has numbered databases, 0 to 15. Apps almost always use 0.",
			def:  func(*store.State, formAnswers) string { return "0" },
			check: func(_ *store.State, _ formAnswers, v string) string {
				if n, err := strconv.Atoi(v); err != nil || n < 0 {
					return "a database number is 0 or more, like 0 or 1"
				}
				return ""
			}}), func(a formAnswers) bool { return a["setup"] != "cluster" }),
		formWhen(formMore(formQ{key: "master", label: "Master name", ask: "What is the master's name at the Sentinels?",
			example: "mymaster", help: "The name in sentinel.conf, on the line sentinel monitor NAME ...",
			check: func(_ *store.State, _ formAnswers, v string) string {
				if strings.ContainsAny(v, " \t,/@&?=#") {
					return "type only the name, like mymaster"
				}
				return ""
			}}), sentinel),
		formWhen(formMore(formQ{key: "sentinels", label: "Other Sentinels", optional: true,
			ask: "Other Sentinel addresses?", example: "10.0.0.8, 10.0.0.9:26379",
			help: "Comma separated, tried when the first one does not answer. Empty for none.", check: cacheSentinelsProblem}), sentinel),
		formWhen(formMore(formYesNoQ("sentinelauth", "Sentinel login", "Do the Sentinels need the same login as Redis?",
			"Only when the Sentinels themselves have a password.", "no",
			"komando sends the same user and password to them", "the Sentinels need no login")),
			func(a formAnswers) bool { return sentinel(a) && a["password"] != "none" }),
		cacheCAQ(),
		formGroupQ(), formNotesQ(),
	}, build: redisBuild}
}

func memcachedForm(_ *call) formSpec {
	return formSpec{title: "Add a Memcached cache", qs: []formQ{
		formNameQ("conn", "cache", "memcache"),
		formReachQ("cache"),
		cacheHostQ(),
		{key: "port", label: "Port", ask: "Which port does it listen on?",
			help: "The usual Memcached port is 11211.",
			def:  func(*store.State, formAnswers) string { return "11211" }, check: formPortProblem},
		cacheTLSQ("memcached"),
		formProtectQ("cache"),
		cacheTLSViaQ(),
		cachePasswordQ("Does the cache need a login?",
			"Only for Memcached started with -Y (a file of users), version 1.5.15 or newer. Most have none.", "none", true),
		cacheSecretQ(true),
		formWhen(formMore(formQ{key: "user", label: "User", ask: "Which user do you log in as?", example: "app",
			help: "A user name from the file Memcached was started with (-Y).", check: cacheUserProblem}), cacheLogin),
		cacheCAQ(),
		formGroupQ(), formNotesQ(),
	}, build: memcachedBuild}
}

// cacheLogin: a password was chosen (typed or saved).
func cacheLogin(a formAnswers) bool { return a["password"] == "ask" || a["password"] == "secret" }

// cacheHostQ is the address question (formServiceHostQ), with the help of
// a cache.
func cacheHostQ() formQ {
	q := formServiceHostQ("cache", "10.0.0.7 or cache.example.com")
	q.help = "Through a server, 127.0.0.1 means that server itself. Through a VPN, type its address inside the VPN's network. " +
		"On this computer, type 127.0.0.1."
	return q
}

// formServiceHostProblem checks the address of a database or cache, which
// is asked without its port (formServiceHostQ). A bare IPv6 address is
// fine; [ ] around it are not, as the command line gets them added once.
func formServiceHostProblem(a formAnswers, v string) string {
	if p := formAddressProblem(v); p != "" {
		return p
	}
	if h, port, err := net.SplitHostPort(v); err == nil {
		switch {
		case h == "":
			return "type only the address, like 10.0.0.5 or db.example.com"
		case a["flavor"] == "atlas" || port == "":
			return "type only the address, like " + h + ", without a port"
		case formPortProblem(nil, nil, port) != "": // not a port: maybe a password, never shown
			return "type only the address, like 10.0.0.5 or db.example.com; the port is the next question"
		}
		return "type only the address, like " + h + "; the port " + port + " is the next question"
	}
	if strings.ContainsAny(v, "[]") {
		if ip := net.ParseIP(strings.Trim(v, "[]")); ip != nil {
			return "type the IPv6 address without [ ], like " + ip.String()
		}
		return "type only the address, like 10.0.0.5 or db.example.com"
	}
	if strings.Contains(v, ":") && net.ParseIP(v) == nil {
		return "type only the address, like 10.0.0.5 or db.example.com; the port is the next question"
	}
	return ""
}

// cacheDirect: reached over the network without a server in between, so
// the connection needs TLS, or a clear choice to go without.
func cacheDirect(a formAnswers) bool { return a["via"] == "" && !formIsLocal(a["host"]) }

// cacheTLSQ asks about TLS when the cache is reached directly over the
// network.
func cacheTLSQ(scheme string) formQ {
	return formQ{key: "tls", label: "Encryption", ask: "Does the cache use TLS (an encrypted connection)?",
		help: "Cloud caches usually do: their connection string starts with " + scheme + "s://. Not sure? Ask your provider.",
		show: cacheDirect,
		def:  func(*store.State, formAnswers) string { return "yes" },
		choices: func(*store.State, formAnswers) []pickRow {
			return []pickRow{{label: "Yes", detail: "encrypted, and its certificate is checked", value: "yes"},
				{label: "No, send it unencrypted",
					detail: "only on a network you trust: the password and data can be read on the way", value: "no"}}
		}}
}

// cacheTLSViaQ is the same question through a server or on this computer,
// under More options: the SSH connection is encrypted already, so TLS
// there is rare (Amazon ElastiCache with encryption in transit has it).
func cacheTLSViaQ() formQ {
	q := formMore(formYesNoQ("tlsvia", "Encryption", "Does the cache use TLS (an encrypted connection)?",
		"Usually not through a server. Yes only when the cache itself asks for TLS.", "no",
		"encrypted, and its certificate is checked", "the usual case"))
	q.show = func(a formAnswers) bool { return !cacheDirect(a) }
	return q
}

// cacheTLS: the URL uses TLS.
func cacheTLS(a formAnswers) bool {
	if cacheDirect(a) {
		return a["tls"] != "no"
	}
	return a["tlsvia"] == "yes"
}

// cachePasswordQ asks whether there is a password, and how komando gets
// it: typed by the person when the command runs (hidden), or a secret
// komando keeps already.
func cachePasswordQ(ask, help, def string, advanced bool) formQ {
	return formQ{key: "password", label: "Password", ask: ask, help: help, advanced: advanced,
		def: func(*store.State, formAnswers) string { return def },
		choices: func(*store.State, formAnswers) []pickRow {
			rows := []pickRow{
				{label: "Yes, I type it next", detail: "hidden; komando keeps it as a saved password", value: "ask"},
				{label: "No password", detail: "common for a cache inside a private network", value: "none"},
			}
			if def == "none" {
				rows[0], rows[1] = rows[1], rows[0]
			}
			if len(secretNames()) > 0 {
				rows = append(rows, pickRow{label: "Yes, I saved it in komando before", detail: "pick it from your saved passwords", value: "secret"})
			}
			return rows
		}}
}

// cacheSecretQ asks which saved secret holds the password.
func cacheSecretQ(advanced bool) formQ {
	return formWhen(formQ{key: "secret", label: "Saved password", ask: "Which saved secret holds the password?",
		advanced: advanced, free: true, help: "A name from komando secret list, or where it is kept, like secret:NAME or env:VAR.",
		choices: cacheSecretRows, check: cacheSecretProblem},
		func(a formAnswers) bool { return a["password"] == "secret" })
}

// cacheCAQ asks for the CA certificate a private certificate authority
// signed the cache's TLS certificate with.
func cacheCAQ() formQ {
	return formWhen(formMore(formQ{key: "ca", label: "CA certificate", optional: true, free: true,
		ask:     "Which saved CA certificate should komando trust?",
		help:    "Only for a certificate from your own CA. Save it first: komando secret set NAME < ca.crt. Empty for none.",
		choices: cacheSecretRows, check: cacheCAProblem}), cacheTLS)
}

func cacheSecretRows(*store.State, formAnswers) []pickRow {
	var rows []pickRow
	for _, n := range secretNames() {
		rows = append(rows, pickRow{label: n, value: n})
	}
	return rows
}

func cacheSecretProblem(_ *store.State, _ formAnswers, v string) string {
	return formSavedSecretProblem(v, true)
}

// cacheCAProblem is cacheSecretProblem for a CA certificate, which only
// komando's own vault keeps (?ca=secret:NAME).
func cacheCAProblem(_ *store.State, _ formAnswers, v string) string {
	return formSavedSecretProblem(v, false)
}

// formSavedSecretProblem checks the answer to "which saved secret": a name
// komando secret list has, or a reference to where it is kept (secret:NAME,
// env:VAR, op://...; only secret:NAME without anyRef). Anything else may
// be the token itself, pasted: it is refused, and the message never
// repeats it.
func formSavedSecretProblem(v string, anyRef bool) string {
	msg := "pick a name from komando secret list, or type where it is kept, like secret:NAME or env:VAR; never the secret itself"
	if !anyRef {
		msg = "pick a name from komando secret list, or type secret:NAME; save it first with komando secret set NAME < ca.crt"
	}
	switch {
	case strings.ContainsAny(v, " \t"):
		return msg
	case slices.Contains(secretNames(), v):
		return ""
	case !vault.ValidRef(v), !anyRef && !strings.HasPrefix(v, "secret:"):
		return msg
	}
	if n, ok := strings.CutPrefix(v, "secret:"); ok && validName("secret", n) != nil {
		return msg
	}
	return ""
}

// formSecretRef is a picked or typed saved secret as a reference: a name
// becomes secret:NAME, a reference stays as it is.
func formSecretRef(v string) string {
	if vault.ValidRef(v) {
		return v
	}
	return "secret:" + v
}

// cacheRef is a saved secret as a reference.
func cacheRef(v string) string { return formSecretRef(v) }

func cacheUserProblem(_ *store.State, _ formAnswers, v string) string {
	if strings.Contains(v, ":") {
		return "type only the user name; komando asks for the password itself, hidden"
	}
	if strings.ContainsAny(v, " \t@/") {
		return "a user name has no spaces, @ or /"
	}
	return ""
}

func cacheSentinelsProblem(_ *store.State, _ formAnswers, v string) string {
	for _, s := range strings.Split(v, ",") {
		s = strings.TrimSpace(s)
		if s == "" || formAddressProblem(s) != "" || strings.ContainsAny(s, "&?=#") {
			return "type addresses separated by commas, like 10.0.0.8, 10.0.0.9:26379"
		}
	}
	return ""
}

func redisBuild(_ *store.State, a formAnswers) [][]string {
	u := url.URL{Scheme: "redis", Host: formHostPort(a["host"], a["port"], "6379")}
	if a["setup"] == "sentinel" && a["port"] == "6379" {
		u.Host = formHostPort(a["host"], "", "") // komando uses the Sentinel port, 26379
	}
	if a["user"] != "" {
		u.User = url.User(a["user"])
	}
	if a["db"] != "" && a["db"] != "0" && a["setup"] != "cluster" {
		u.Path = "/" + a["db"]
	}
	q := url.Values{}
	switch a["setup"] {
	case "cluster":
		q.Set("cluster", "1")
	case "sentinel":
		q.Set("sentinel", a["master"])
		if s := strings.ReplaceAll(a["sentinels"], " ", ""); s != "" {
			q.Set("sentinels", s)
		}
		if a["sentinelauth"] == "yes" && a["password"] != "none" {
			q.Set("sentinel_auth", "same")
		}
	}
	return cacheBuild(a, &u, q)
}

func memcachedBuild(_ *store.State, a formAnswers) [][]string {
	u := url.URL{Scheme: "memcached", Host: formHostPort(a["host"], a["port"], "11211")}
	if cacheLogin(a) && a["user"] != "" {
		u.User = url.User(a["user"])
	}
	return cacheBuild(a, &u, url.Values{})
}

// cacheBuild adds what both caches share: TLS (the scheme with an s), the
// clear choice to go without it over the network, a CA, and the password.
func cacheBuild(a formAnswers, u *url.URL, q url.Values) [][]string {
	switch {
	case cacheTLS(a):
		u.Scheme += "s"
		if a["ca"] != "" {
			q.Set("ca", cacheRef(a["ca"]))
		}
	case cacheDirect(a):
		q.Set("insecure", "1")
	}
	// : and , read better unescaped, and mean the same in a query
	u.RawQuery = strings.NewReplacer("%3A", ":", "%2C", ",").Replace(q.Encode())
	cmds := formConnBuild(a, u.String(), a["password"] == "ask")
	if a["password"] == "secret" && a["secret"] != "" {
		add := cmds[0][:4:4]
		cmds[0] = append(append(add, "--password-ref", cacheRef(a["secret"])), cmds[0][4:]...)
	}
	return cmds
}
