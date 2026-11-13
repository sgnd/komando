package cli

import (
	"net"
	"net/url"
	"regexp"
	"strings"

	"github.com/sgnd/komando/internal/store"
)

// The Add forms for message queues: Kafka, RabbitMQ, NATS, Amazon SQS and
// Google Pub/Sub. Over the network the usual answer is TLS; going without
// it is a clear choice (?insecure=1), as conn add asks. Passwords are asked
// hidden by the command (--ask-password) or picked from the vault.

func queueForms() []formKind {
	return []formKind{
		{"Apache Kafka", "also Redpanda, Amazon MSK, Confluent Cloud, Aiven", kafkaForm},
		{"RabbitMQ", "also Amazon MQ for RabbitMQ, CloudAMQP", rabbitForm},
		{"NATS JetStream", "also Synadia Cloud (NGS)", natsForm},
		{"Amazon SQS", "the queues of one AWS region, with your AWS login", sqsForm},
		{"Google Cloud Pub/Sub", "the topics of one project, with your Google login", pubsubForm},
	}
}

var (
	queueAccountRe = regexp.MustCompile(`^[0-9]{12}$`)
	queueRegionRe  = regexp.MustCompile(`^[a-z]{2}(-[a-z0-9]+)+-[0-9]+$`)
)

// What the forms share.

// queueServersQ asks one or more server addresses, comma separated, each
// with an optional port.
func queueServersQ(what, example, help string) formQ {
	return formQ{key: "servers", label: "Address", ask: "What is the " + what + "'s address?", addr: true,
		example: example, help: help + " Through a server, 127.0.0.1 means that server itself.",
		def: func(st *store.State, a formAnswers) string {
			if st != nil && st.Hosts[a["via"]] != nil {
				return "127.0.0.1"
			}
			return ""
		},
		check: func(_ *store.State, _ formAnswers, v string) string { return queueServersProblem(v) }}
}

func queueServersProblem(v string) string {
	for _, s := range queueServers(v) {
		if p := formAddressProblem(s); p != "" {
			return p
		}
		if strings.ContainsAny(s, "?#&=") {
			return "type only addresses, like b1.example.com:9093, separated by commas"
		}
		if h, port, err := net.SplitHostPort(s); err == nil && (h == "" || formPortProblem(nil, nil, port) != "") {
			return "type an address and a port, like b1.example.com:9093"
		}
	}
	if len(queueServers(v)) == 0 {
		return "type at least one address"
	}
	return ""
}

// queueServers is the comma-separated list, trimmed.
func queueServers(v string) []string {
	var out []string
	for _, s := range strings.Split(v, ",") {
		if s = strings.TrimSpace(s); s != "" {
			out = append(out, s)
		}
	}
	return out
}

// queueDirect: reached over the network, not through a server or VPN and
// not on this computer, so it needs TLS or a clear choice to go without.
func queueDirect(a formAnswers) bool {
	if a["via"] != "" {
		return false
	}
	for _, s := range queueServers(a["servers"] + "," + a["host"]) {
		h := s
		if hh, _, err := net.SplitHostPort(s); err == nil {
			h = hh
		}
		if !formIsLocal(h) {
			return true
		}
	}
	return false
}

// queueTLSQ asks about TLS while reached over the network (yes first),
// queueTLSViaQ the same through a server, under More options.
func queueTLSQ(help string) formQ {
	q := cacheTLSQ("")
	q.ask, q.help, q.show = "Does it use TLS (an encrypted connection)?", help, queueDirect
	return q
}

func queueTLSViaQ() formQ {
	q := cacheTLSViaQ()
	q.help = "Usually not through a server. Yes only when the server itself asks for TLS."
	q.show = func(a formAnswers) bool { return !queueDirect(a) }
	return q
}

func queueTLS(a formAnswers) bool {
	if queueDirect(a) {
		return a["tls"] != "no"
	}
	return a["tlsvia"] == "yes"
}

// queueCAQ asks for a CA certificate in the vault, under More options.
func queueCAQ() formQ {
	q := cacheCAQ()
	q.show = queueTLS
	return q
}

// queuePasswordQ asks how komando gets a password: typed next (hidden),
// or a secret in the vault.
func queuePasswordQ(show func(formAnswers) bool) formQ {
	return formWhen(formQ{key: "password", label: "Password", ask: "How does komando get the password?",
		help: "Either way it never shows here. With Confluent Cloud the password is the API secret.",
		def:  func(*store.State, formAnswers) string { return "ask" },
		choices: func(*store.State, formAnswers) []pickRow {
			rows := []pickRow{{label: "I type it next", detail: "hidden; komando keeps it as a saved password", value: "ask"}}
			if len(secretNames()) > 0 {
				rows = append(rows, pickRow{label: "I saved it in komando before", detail: "pick it from your saved passwords", value: "secret"})
			}
			return rows
		}}, show)
}

// queueBuild adds what the queue forms share: TLS options, the choice to
// go without TLS, a CA, and the password.
func queueBuild(a formAnswers, rawURL string, q url.Values, login bool) [][]string {
	if queueTLS(a) && a["ca"] != "" {
		q.Set("ca", formSecretRef(a["ca"]))
	}
	if !queueTLS(a) && queueDirect(a) {
		q.Set("insecure", "1")
	}
	if enc := strings.NewReplacer("%3A", ":", "%2C", ",").Replace(q.Encode()); enc != "" {
		rawURL += "?" + enc
	}
	cmds := formConnBuild(a, rawURL, login && a["password"] == "ask")
	if login && a["password"] == "secret" && a["secret"] != "" {
		cmds[0] = append(cmds[0], "--password-ref", formSecretRef(a["secret"]))
	}
	return cmds
}

// queueUser is user@ for a URL, or "".
func queueUser(u string) string {
	if u == "" {
		return ""
	}
	return url.User(u).String() + "@"
}

// Kafka.

func kafkaForm() formSpec {
	sasl := func(a formAnswers) bool { return a["login"] == "sasl" }
	return formSpec{title: "Add a Kafka cluster", qs: []formQ{
		formNameQ("conn", "Kafka cluster", "events"),
		formReachQ("Kafka cluster"),
		queueServersQ("broker", "b1.example.com:9093, b2.example.com:9093",
			"One broker is enough: komando asks it for the others. Several: separate them with commas. Without a port: 9092."),
		queueTLSQ("Cloud Kafka (Confluent Cloud, MSK, Aiven) does. Not sure? Ask whoever runs it."),
		queueTLSViaQ(),
		{key: "login", label: "Login", ask: "Does it need a login (SASL)?",
			help: "Cloud Kafka does: a user (Confluent Cloud: the API key) and a password.",
			def: func(_ *store.State, a formAnswers) string {
				if queueDirect(a) {
					return "sasl"
				}
				return "none"
			},
			choices: func(*store.State, formAnswers) []pickRow {
				return []pickRow{{label: "Yes, a user and a password", detail: "SASL", value: "sasl"},
					{label: "No login", detail: "common inside a private network", value: "none"}}
			}},
		formWhen(formQ{key: "user", label: "User", ask: "Which user do you log in as?", example: "app",
			help: "The SASL user. With Confluent Cloud: the API key.", check: cacheUserProblem}, sasl),
		formWhen(formQ{key: "sasl", label: "Login method", ask: "Which login method do the brokers want?",
			help: "Shown in the cluster's client settings as sasl.mechanism. Confluent Cloud uses PLAIN.",
			def:  func(*store.State, formAnswers) string { return "scram-sha-512" },
			choices: func(*store.State, formAnswers) []pickRow {
				return []pickRow{{label: "SCRAM-SHA-512", detail: "the usual for MSK, Aiven, Redpanda", value: "scram-sha-512"},
					{label: "SCRAM-SHA-256", value: "scram-sha-256"},
					{label: "PLAIN", detail: "Confluent Cloud; only with TLS", value: "plain"}}
			}}, sasl),
		queuePasswordQ(sasl),
		cacheSecretQ(false),
		formProtectQ("Kafka cluster"),
		queueCAQ(),
		formGroupQ(), formNotesQ(),
	}, build: func(_ *store.State, a formAnswers) [][]string {
		q := url.Values{}
		if queueTLS(a) {
			q.Set("tls", "true")
		}
		user := ""
		if sasl(a) {
			user = queueUser(a["user"])
			q.Set("sasl", a["sasl"])
		}
		raw := "kafka://" + user + strings.Join(queueServers(a["servers"]), ",")
		return queueBuild(a, raw, q, sasl(a))
	}}
}

// RabbitMQ.

func rabbitForm() formSpec {
	login := func(a formAnswers) bool { return a["user"] != "" }
	return formSpec{title: "Add a RabbitMQ server", qs: []formQ{
		formNameQ("conn", "RabbitMQ server", "jobs"),
		formReachQ("RabbitMQ server"),
		formServiceHostQ("RabbitMQ server", "10.0.0.5 or rabbit.example.com"),
		queueTLSQ("Cloud RabbitMQ does: its link starts with amqps://. Not sure? Ask whoever runs it."),
		queueTLSViaQ(),
		{key: "port", label: "Port", ask: "Which AMQP port does it listen on?",
			help: "5671 with TLS, 5672 without.",
			def: func(_ *store.State, a formAnswers) string {
				if queueTLS(a) {
					return "5671"
				}
				return "5672"
			}, check: formPortProblem},
		{key: "vhost", label: "Virtual host", ask: "Which virtual host (vhost)?", example: "/",
			help: "One server holds several vhosts. Most use the default, /.",
			def:  func(*store.State, formAnswers) string { return "/" }},
		{key: "user", label: "User", ask: "Which user do you log in as?", optional: true, example: "app",
			help: "Empty logs in as guest, which RabbitMQ lets in only from the server itself.", check: cacheUserProblem},
		queuePasswordQ(login),
		cacheSecretQ(false),
		{key: "management", label: "Management port", ask: "Which port does the management plugin use?", optional: true,
			help: "queue list and queue peek need it: peek reads a queue's type and delivery limit there, so it never makes a quorum queue drop a message. Usually 15671 with TLS, 15672 without; empty when the plugin is off.",
			def: func(_ *store.State, a formAnswers) string {
				if queueTLS(a) {
					return "15671"
				}
				return "15672"
			}, check: formPortProblem},
		formProtectQ("RabbitMQ server"),
		queueCAQ(),
		formGroupQ(), formNotesQ(),
	}, build: func(_ *store.State, a formAnswers) [][]string {
		scheme, usual := "amqp", "5672"
		if queueTLS(a) {
			scheme, usual = "amqps", "5671"
		}
		host := a["host"]
		vhost := strings.TrimPrefix(a["vhost"], "/")
		if a["vhost"] == "/" || a["vhost"] == "" {
			vhost = "%2F"
		} else {
			vhost = url.PathEscape(vhost)
		}
		q := url.Values{}
		if a["management"] != "" {
			q.Set("management", a["management"])
		}
		raw := scheme + "://" + queueUser(a["user"]) + formHostPort(host, a["port"], usual) + "/" + vhost
		return queueBuild(a, raw, q, login(a))
	}}
}

// NATS.

func natsForm() formSpec {
	login := func(v string) func(formAnswers) bool { return func(a formAnswers) bool { return a["login"] == v } }
	pw := func(a formAnswers) bool { return a["login"] == "user" || a["login"] == "token" }
	return formSpec{title: "Add a NATS server", qs: []formQ{
		formNameQ("conn", "NATS server", "stream"),
		formReachQ("NATS server"),
		queueServersQ("NATS server", "nats1.example.com, nats2.example.com",
			"Several servers of a cluster: separate them with commas. Without a port: 4222."),
		queueTLSQ("Synadia Cloud does: its link starts with tls://. Not sure? Ask whoever runs it."),
		queueTLSViaQ(),
		{key: "login", label: "Login", ask: "How do you log in?",
			help: "Whoever runs the server gave you one of these.",
			def:  func(*store.State, formAnswers) string { return "user" },
			choices: func(*store.State, formAnswers) []pickRow {
				rows := []pickRow{{label: "A user and a password", value: "user"},
					{label: "A token", detail: "one secret without a user", value: "token"}}
				if len(secretNames()) > 0 {
					rows = append(rows, pickRow{label: "A .creds file I saved in komando before", detail: "from nsc or Synadia Cloud", value: "creds"})
				}
				return append(rows, pickRow{label: "No login", value: "none"})
			}},
		formWhen(formQ{key: "user", label: "User", ask: "Which user do you log in as?", example: "app", check: cacheUserProblem}, login("user")),
		queuePasswordQ(pw),
		cacheSecretQ(false),
		formWhen(formQ{key: "creds", label: "Creds file", ask: "Which saved secret holds the .creds file?", free: true,
			help:    "Save it first with komando secret set NAME < user.creds, then pick it here.",
			choices: cacheSecretRows, check: natsCredsProblem}, login("creds")),
		formProtectQ("NATS server"),
		formMore(formQ{key: "domain", label: "JetStream domain", ask: "Which JetStream domain?", optional: true, example: "hub",
			help: "Only for a leaf node with its own JetStream. Empty for the usual one.", check: dbNameProblem}),
		queueCAQ(),
		formGroupQ(), formNotesQ(),
	}, build: func(_ *store.State, a formAnswers) [][]string {
		scheme := "nats"
		if queueTLS(a) {
			scheme = "tls"
		}
		q := url.Values{}
		if a["login"] == "creds" {
			q.Set("creds", formSecretRef(a["creds"]))
		}
		if a["domain"] != "" {
			q.Set("domain", a["domain"])
		}
		user := ""
		if a["login"] == "user" {
			user = queueUser(a["user"])
		}
		raw := scheme + "://" + user + strings.Join(queueServers(a["servers"]), ",")
		return queueBuild(a, raw, q, pw(a))
	}}
}

// Amazon SQS.

func sqsForm() formSpec {
	return formSpec{title: "Add Amazon SQS queues", qs: []formQ{
		formNameQ("conn", "SQS region", "sqs"),
		{key: "region", label: "Region", ask: "Which AWS region are the queues in?", example: "eu-west-1",
			help:  "Shown at the top right of the AWS console. One entry covers all the queues of one region.",
			check: sqsRegionProblem},
		{key: "login", label: "Login", ask: "How does komando log in to AWS?",
			help: "No aws CLI needed. Safest is a login that can reach only these queues.",
			def:  func(*store.State, formAnswers) string { return "profile" },
			choices: func(*store.State, formAnswers) []pickRow {
				return []pickRow{
					{label: "A profile from ~/.aws/config", detail: "SSO, a role or keys, as the aws CLI uses them", value: "profile"},
					{label: "The usual AWS login", detail: "AWS_* variables, the default profile, or this server's role", value: "chain"},
					{label: "An access key of an IAM user", detail: "an ID and a secret; the secret is asked hidden", value: "key"},
				}
			}},
		formWhen(formQ{key: "profile", label: "AWS profile", ask: "Which AWS profile?", example: "default",
			help: "A profile name from ~/.aws/config. An SSO login that runs out: komando login aws renews it.",
			def:  func(*store.State, formAnswers) string { return "default" }, check: s3ProfileProblem},
			func(a formAnswers) bool { return a["login"] == "profile" }),
		formWhen(formQ{key: "keyid", label: "Access key ID", ask: "What is the access key ID?", example: "AKIAIOSFODNN7EXAMPLE",
			help:  "The public half of the key. When the command asks \"Password for\" with the name you gave, paste the secret half; it stays hidden.",
			check: s3KeyIDProblem}, func(a formAnswers) bool { return a["login"] == "key" }),
		formProtectQ("queues"),
		formMore(formQ{key: "account", label: "Account ID", ask: "Use queues of another AWS account?", optional: true,
			example: "123456789012", help: "Only for queues another account shared with you: its 12-digit ID. Empty for your own.",
			check: func(_ *store.State, _ formAnswers, v string) string {
				if !queueAccountRe.MatchString(v) {
					return "an AWS account ID is 12 digits, like 123456789012"
				}
				return ""
			}}),
		queueEndpointQ("http://localhost:4566", "Only for a VPC endpoint or an emulator such as LocalStack. Empty uses AWS."),
		storeViaQ("queues"),
		formGroupQ(), formNotesQ(),
	}, build: func(_ *store.State, a formAnswers) [][]string {
		u := url.URL{Scheme: "sqs", Host: a["region"],
			RawQuery: storeQuery("account", a["account"], "endpoint", storeEndpoint(a["endpoint"]))}
		if a["login"] == "key" {
			u.User = url.User(a["keyid"])
		}
		cmds := formConnBuild(a, u.String(), a["login"] == "key")
		if a["login"] == "profile" {
			cmds[0] = append(cmds[0], "--option", "aws_profile="+a["profile"])
		}
		return cmds
	}}
}

func sqsRegionProblem(_ *store.State, _ formAnswers, v string) string {
	if !queueRegionRe.MatchString(v) {
		return "a region is a code like eu-west-1 or us-east-1"
	}
	return ""
}

// queueEndpointQ asks another server address (an emulator) under More
// options. http:// is only taken on this computer or through a server:
// across the network the messages would travel unencrypted.
func queueEndpointQ(example, help string) formQ {
	return formMore(formQ{key: "endpoint", label: "Address", ask: "Use an emulator or another address?", optional: true,
		example: example, help: help,
		check: func(_ *store.State, a formAnswers, v string) string {
			if p := storeEndpointProblem(v, false); p != "" {
				return p
			}
			if u, err := url.Parse(storeEndpoint(v)); err == nil && u.Scheme == "http" && !formIsLocal(u.Hostname()) && a["via"] == "" {
				return "http:// across the network is unencrypted; use https://, or reach it through a server"
			}
			return ""
		}})
}

// Google Pub/Sub.

func pubsubForm() formSpec {
	return formSpec{title: "Add Google Cloud Pub/Sub", qs: []formQ{
		formNameQ("conn", "Pub/Sub project", "pubsub"),
		{key: "project", label: "Project", ask: "Which Google Cloud project are the topics in?", example: "my-project",
			help:  "The project ID (not its name), from the project picker in the Google Cloud console.",
			check: func(_ *store.State, _ formAnswers, v string) string { return gcpProjectProblem(v) }},
		gcpLoginQ(),
		gcpKeyFileQ(),
		formProtectQ("project"),
		queueEndpointQ("http://localhost:8085", "Only for the emulator, a regional or a private endpoint. Empty uses Google Cloud."),
		storeViaQ("project"),
		formGroupQ(), formNotesQ(),
	}, build: func(_ *store.State, a formAnswers) [][]string {
		u := url.URL{Scheme: "pubsub", Host: a["project"], RawQuery: storeQuery("endpoint", storeEndpoint(a["endpoint"]))}
		return gcpKeyBuild(a, formConnBuild(a, u.String(), false))
	}}
}

// natsCredsProblem: a .creds file is kept in komando's own vault
// (?creds=secret:NAME).
func natsCredsProblem(_ *store.State, _ formAnswers, v string) string {
	n := strings.TrimPrefix(v, "secret:")
	if strings.ContainsAny(v, " \t") || validName("secret", n) != nil {
		return "pick a name from komando secret list, or type secret:NAME; save the file first with komando secret set NAME < user.creds"
	}
	return ""
}
