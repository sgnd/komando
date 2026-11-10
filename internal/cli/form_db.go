package cli

import (
	"net/url"
	"os"
	"regexp"
	"strings"

	"github.com/sgnd/komando/internal/store"
)

// The Add forms for SQL Server, Oracle, ClickHouse, Snowflake and BigQuery.
// Like the PostgreSQL form they build a conn URL from plain answers; a
// password or a token is never typed here (--ask-password asks it hidden
// when the command runs), and a key stays in its file (--password-ref
// file:PATH).

var (
	dbOracleNameRe = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_.$#-]{0,127}$`)
	dbSFAccountRe  = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,254}$`)
	dbBQProjectRe  = regexp.MustCompile(`^[a-z][a-z0-9-]{4,28}[a-z0-9]$`)
	dbBQDatasetRe  = regexp.MustCompile(`^[A-Za-z0-9_]{1,1000}$`)
	dbBQLocationRe = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9-]{0,62}$`)
)

// dbPortQ is the port question of a database with its usual port.
func dbPortQ(usual, help string) formQ {
	return formQ{key: "port", label: "Port", ask: "Which port does it listen on?", help: help,
		def: func(*store.State, formAnswers) string { return usual }, check: formPortProblem}
}

// dbUserQ is the database user question.
func dbUserQ(example, help string) formQ {
	return formQ{key: "user", label: "User", ask: "Which database user do you log in with?", example: example, help: help,
		check: cacheUserProblem}
}

// dbNameProblem checks a database, schema, warehouse or role name typed
// into a URL path or option.
func dbNameProblem(_ *store.State, _ formAnswers, v string) string {
	if strings.ContainsAny(v, " \t/?#&=@:") {
		return "type only the name, without spaces or / ? # & = @ :"
	}
	return ""
}

// SQL Server.

func sqlServerForm() formSpec {
	host := formServiceHostQ("database server", "10.0.0.5 or db.example.com")
	check := host.check
	host.check = func(st *store.State, a formAnswers, v string) string {
		if i := strings.Index(v, `\`); i > 0 {
			return "a named instance (" + v + ") is reached by its port: type " + v[:i] + " here and the instance's port next"
		}
		return check(st, a, v)
	}
	return formSpec{title: "Add a SQL Server database", qs: []formQ{
		formNameQ("conn", "database", "sales-db"),
		formReachQ("database"),
		host,
		dbPortQ("1433", "The usual SQL Server port is 1433. A named instance (like SQLEXPRESS) has its own: SQL Server Configuration Manager shows it."),
		dbUserQ("app", "A SQL Server login (user and password), not your Windows user: Windows and Entra ID logins are not supported. komando asks for the password after this, hidden."),
		{key: "database", label: "Database", ask: "Which database inside the server?", optional: true, example: "sales",
			help: "Empty uses the login's default database.", check: dbNameProblem},
		formProtectQ("database"),
		dbTLSQ(),
		formGroupQ(), formNotesQ(),
	}, build: func(_ *store.State, a formAnswers) [][]string {
		u := url.URL{Scheme: "sqlserver", User: url.User(a["user"]), Host: formHostPort(a["host"], a["port"], "1433")}
		if a["database"] != "" {
			u.Path = "/" + a["database"]
		}
		switch a["tls"] {
		case "nocheck":
			u.RawQuery = "encrypt=true&tls=skip-verify"
		case "off":
			u.RawQuery = "encrypt=disable"
		}
		return formConnBuild(a, u.String(), true)
	}}
}

// Oracle.

func oracleForm() formSpec {
	oracleName := func(_ *store.State, _ formAnswers, v string) string {
		if !dbOracleNameRe.MatchString(v) {
			return "type only the name, like ORCLPDB1: letters, digits, dot, _ and -, starting with a letter"
		}
		return ""
	}
	return formSpec{title: "Add an Oracle database", qs: []formQ{
		formNameQ("conn", "database", "erp-db"),
		formReachQ("database"),
		formServiceHostQ("database server", "10.0.0.5 or db.example.com"),
		dbPortQ("1521", "The usual Oracle port is 1521. Encrypted connections (TCPS) often have their own, like 2484."),
		{key: "by", label: "Named by", ask: "How is the database named?",
			help: "Oracle 12c and later use a service name. Only old databases without services have just a SID.",
			def:  func(*store.State, formAnswers) string { return "service" },
			choices: func(*store.State, formAnswers) []menuRow {
				return []menuRow{{label: "A service name", detail: "the usual case, like ORCLPDB1 or FREEPDB1", value: "service"},
					{label: "A SID", detail: "an old database without services, like ORCL", value: "sid"}}
			}},
		formWhen(formQ{key: "service", label: "Service name", ask: "What is the service name?", example: "ORCLPDB1",
			help:  "Often a pluggable database. lsnrctl status on the database server lists the services.",
			check: oracleName}, func(a formAnswers) bool { return a["by"] != "sid" }),
		formWhen(formQ{key: "sid", label: "SID", ask: "What is the SID?", example: "ORCL",
			help:  "The instance name, as ORACLE_SID on the database server.",
			check: oracleName}, func(a formAnswers) bool { return a["by"] == "sid" }),
		dbUserQ("app", "In Oracle a user is also a schema. komando asks for the password after this, hidden."),
		formProtectQ("database"),
		dbTLSQ(),
		formGroupQ(), formNotesQ(),
	}, build: func(_ *store.State, a formAnswers) [][]string {
		u := url.URL{Scheme: "oracle", User: url.User(a["user"]), Host: formHostPort(a["host"], a["port"], "1521")}
		q := url.Values{}
		if a["by"] == "sid" {
			q.Set("sid", a["sid"])
		} else {
			u.Path = "/" + a["service"]
		}
		switch a["tls"] {
		case "nocheck":
			q.Set("tls", "skip-verify")
		case "off":
			q.Set("tls", "false")
		}
		u.RawQuery = q.Encode()
		return formConnBuild(a, u.String(), true)
	}}
}

// ClickHouse.

// clickhouseTLSDefault: no TLS through a server or on this computer (the
// SSH connection is encrypted already), checked TLS over the network.
func clickhouseTLSDefault(st *store.State, a formAnswers) string {
	if (st != nil && st.Hosts[a["via"]] != nil) || formIsLocal(a["host"]) {
		return "false"
	}
	return "true"
}

func clickhouseForm() formSpec {
	return formSpec{title: "Add a ClickHouse database", qs: []formQ{
		formNameQ("conn", "database", "events"),
		formReachQ("database"),
		formServiceHostQ("ClickHouse server", "10.0.0.5 or abc123.eu-west-1.aws.clickhouse.cloud"),
		{key: "tls", label: "Encryption", ask: "Does the server use HTTPS (an encrypted connection)?",
			help: "ClickHouse Cloud always does. Through a server, plain HTTP is usual: the SSH connection is encrypted already.",
			def:  clickhouseTLSDefault,
			choices: func(*store.State, formAnswers) []menuRow {
				return []menuRow{{label: "Yes", detail: "HTTPS, port 8443, and its certificate is checked", value: "true"},
					{label: "Yes, do not check", detail: "HTTPS with a certificate the server made itself", value: "skip-verify"},
					{label: "No", detail: "plain HTTP, port 8123; only inside a network you trust", value: "false"}}
			}},
		{key: "port", label: "Port", ask: "Which port does it listen on?",
			help: "komando speaks ClickHouse's HTTP interface: 8443 with HTTPS, 8123 without. Not 9000 or 9440, the native ports.",
			def: func(_ *store.State, a formAnswers) string {
				if a["tls"] == "false" {
					return "8123"
				}
				return "8443"
			},
			check: func(st *store.State, a formAnswers, v string) string {
				if v == "9000" || v == "9440" {
					return v + " is ClickHouse's native protocol, which komando does not speak; use the HTTP port, 8443 or 8123"
				}
				return formPortProblem(st, a, v)
			}},
		dbUserQ("default", "ClickHouse's own first user is called default; your provider may have given you another."),
		{key: "database", label: "Database", ask: "Which database should commands use?", optional: true, example: "analytics",
			help: "Empty uses the user's default database.", check: dbNameProblem},
		formYesNoQ("password", "Password", "Does this user log in with a password?",
			"Almost always yes. komando asks for it after this, hidden, and keeps it as a saved password.", "yes",
			"you type it next, hidden", "no password"),
		formProtectQ("database"),
		formGroupQ(), formNotesQ(),
	}, build: func(_ *store.State, a formAnswers) [][]string {
		u := url.URL{Scheme: "clickhouse", User: url.User(a["user"]), Host: formHostPort(a["host"], a["port"], ""),
			RawQuery: "tls=" + a["tls"]}
		if a["database"] != "" {
			u.Path = "/" + a["database"]
		}
		return formConnBuild(a, u.String(), a["password"] == "yes")
	}}
}

// Snowflake.

func snowflakeForm() formSpec {
	login := func(v string) func(formAnswers) bool { return func(a formAnswers) bool { return a["login"] == v } }
	return formSpec{title: "Add a Snowflake database", qs: []formQ{
		formNameQ("conn", "database", "analytics"),
		{key: "account", label: "Account", ask: "What is the account identifier?", example: "myorg-myaccount",
			help:  "In Snowsight: your name at the bottom left, Account, View account details. It is also the first part of your link, before .snowflakecomputing.com.",
			check: snowflakeAccountProblem},
		{key: "user", label: "User", ask: "Which Snowflake user do you log in as?", example: "APP_RO",
			help:  "A user for komando that may only read is safest. Names are usually in capitals.",
			check: func(_ *store.State, _ formAnswers, v string) string { return snowflakeUserProblem(v) }},
		{key: "login", label: "Login", ask: "How does this user log in?",
			help: "Snowflake takes no passwords here: a key pair or a programmatic access token. Browser sign-in (SSO) does not work.",
			def:  func(*store.State, formAnswers) string { return "keyfile" },
			choices: func(*store.State, formAnswers) []menuRow {
				rows := []menuRow{
					{label: "A private key file", detail: "key-pair login; Snowflake knows its public half (RSA_PUBLIC_KEY)", value: "keyfile"},
					{label: "A programmatic access token", detail: "you paste it next, hidden; komando keeps it as a saved password", value: "token"},
				}
				if len(secretNames()) > 0 {
					rows = append(rows, menuRow{label: "A key or token I saved in komando before", detail: "pick it from your saved passwords", value: "secret"})
				}
				return rows
			}},
		formWhen(formQ{key: "keyfile", label: "Key file", ask: "Where is the private key file?", example: "~/keys/rsa_key.p8",
			help:  "A .p8 or .pem file without a passphrase. komando reads it each time, so leave it where it is.",
			check: func(_ *store.State, _ formAnswers, v string) string { return snowflakeKeyProblem(v) }}, login("keyfile")),
		formWhen(formQ{key: "secret", label: "Saved key", ask: "Which saved secret holds the key or the token?", free: true,
			help:    "A name from komando secret list, or where it is kept, like secret:NAME or env:VAR.",
			choices: cacheSecretRows, check: cacheSecretProblem}, login("secret")),
		{key: "warehouse", label: "Warehouse", ask: "Which warehouse runs the queries?", optional: true, example: "REPORTING",
			help: "Most queries need one. Empty is fine for a first test.", check: dbNameProblem},
		{key: "database", label: "Database", ask: "Which database should commands use?", optional: true, example: "ANALYTICS",
			help: "Empty for none: then write DATABASE.SCHEMA.TABLE in queries.", check: dbNameProblem},
		formWhen(formQ{key: "schema", label: "Schema", ask: "Which schema inside it?", optional: true, example: "PUBLIC",
			help: "Empty for none.", check: dbNameProblem}, func(a formAnswers) bool { return a["database"] != "" }),
		{key: "role", label: "Role", ask: "Which role should komando use?", optional: true, example: "ANALYST_RO",
			help: "Best a role that may only read. Empty uses the user's default role.", check: dbNameProblem},
		formProtectQ("database"),
		storeViaQ("database"),
		formGroupQ(), formNotesQ(),
	}, build: snowflakeBuild}
}

func snowflakeAccountProblem(_ *store.State, _ formAnswers, v string) string {
	acct := strings.TrimSuffix(strings.ToLower(v), ".snowflakecomputing.com")
	switch {
	case strings.Contains(v, "://") || strings.Contains(v, "/"):
		return "type only the identifier, like myorg-myaccount, without https:// and the rest of the link"
	case !dbSFAccountRe.MatchString(acct) || strings.Contains(acct, "..") || strings.HasSuffix(acct, "."):
		return "an account identifier is like myorg-myaccount, or a locator like xy12345.eu-central-1"
	}
	return ""
}

func snowflakeUserProblem(v string) string {
	if strings.ContainsAny(v, " \t:/") {
		return "type only the user name, without spaces, : or /"
	}
	return ""
}

// snowflakeKeyProblem checks that a file is a private key without a
// passphrase, reading only its first line.
func snowflakeKeyProblem(v string) string {
	if strings.HasSuffix(v, ".pub") {
		return "that is the public half (.pub); give the private key file"
	}
	if p := formFileProblem(v); p != "" {
		return p
	}
	b, err := os.ReadFile(expandHome(v))
	if err != nil {
		return "komando cannot read this file; check that it is yours"
	}
	first, _, _ := strings.Cut(strings.TrimSpace(string(b)), "\n")
	switch {
	case strings.Contains(first, "ENCRYPTED"):
		return "this key has a passphrase; save one without: openssl pkcs8 -topk8 -nocrypt -in KEY -out rsa_key.p8"
	case !strings.Contains(first, "PRIVATE KEY"):
		return "this is not a private key in PEM form (-----BEGIN PRIVATE KEY-----)"
	}
	return ""
}

func snowflakeBuild(_ *store.State, a formAnswers) [][]string {
	u := url.URL{Scheme: "snowflake", User: url.User(a["user"]), Host: a["account"]}
	if a["database"] != "" {
		u.Path = "/" + a["database"]
		if a["schema"] != "" {
			u.Path += "/" + a["schema"]
		}
	}
	u.RawQuery = storeQuery("warehouse", a["warehouse"], "role", a["role"])
	cmds := formConnBuild(a, u.String(), a["login"] == "token")
	switch a["login"] {
	case "keyfile":
		cmds[0] = append(cmds[0], "--password-ref", "file:"+formAbs(a["keyfile"]))
	case "secret":
		cmds[0] = append(cmds[0], "--password-ref", formSecretRef(a["secret"]))
	}
	return cmds
}

// BigQuery.

func bigqueryForm() formSpec {
	return formSpec{title: "Add a Google BigQuery database", qs: []formQ{
		formNameQ("conn", "database", "warehouse"),
		{key: "project", label: "Project", ask: "Which Google Cloud project runs the queries?", example: "my-project",
			help:  "The project ID (not its name), from the project picker in the Google Cloud console. Queries are billed to it.",
			check: func(_ *store.State, _ formAnswers, v string) string { return gcpProjectProblem(v) }},
		{key: "dataset", label: "Dataset", ask: "Which dataset should table names use?", optional: true, example: "analytics",
			help: "Then orders means analytics.orders. Empty: write DATASET.TABLE in queries.",
			check: func(_ *store.State, _ formAnswers, v string) string {
				if !dbBQDatasetRe.MatchString(v) {
					return "a dataset name has letters, digits and _ only, like analytics"
				}
				return ""
			}},
		{key: "location", label: "Location", ask: "Where is the data kept?", optional: true, example: "EU",
			help: "EU, US or a region like europe-west1, as the dataset's details show. Empty lets BigQuery find it from the tables.",
			check: func(_ *store.State, _ formAnswers, v string) string {
				if !dbBQLocationRe.MatchString(v) {
					return "a location is like EU, US or europe-west1"
				}
				return ""
			}},
		gcpLoginQ(),
		gcpKeyFileQ(),
		formProtectQ("database"),
		storeViaQ("database"),
		formGroupQ(), formNotesQ(),
	}, build: func(_ *store.State, a formAnswers) [][]string {
		u := url.URL{Scheme: "bigquery", Host: a["project"], RawQuery: storeQuery("location", a["location"])}
		if a["dataset"] != "" {
			u.Path = "/" + a["dataset"]
		}
		return gcpKeyBuild(a, formConnBuild(a, u.String(), false))
	}}
}

// gcpProjectProblem checks a Google Cloud project ID.
func gcpProjectProblem(v string) string {
	switch {
	case strings.Contains(v, "://") || strings.Contains(v, "/"):
		return "type only the project ID, like my-project"
	case !dbBQProjectRe.MatchString(v):
		return "a project ID has 6 to 30 small letters, digits and dashes, starting with a letter, like my-project"
	}
	return ""
}

// gcpLoginQ asks how komando logs in to Google Cloud: like gcloud, or
// with a service account key file (BigQuery and Pub/Sub).
func gcpLoginQ() formQ {
	return formQ{key: "login", label: "Login", ask: "How does komando log in to Google Cloud?",
		help: "No password: your Google login. A service account is a login for programs; its key is a JSON file you download once.",
		def:  func(*store.State, formAnswers) string { return "gcloud" },
		choices: func(*store.State, formAnswers) []menuRow {
			return []menuRow{
				{label: "Like gcloud on this computer", detail: "after gcloud auth application-default login", value: "gcloud"},
				{label: "With a service account key file", detail: "the JSON file from IAM, Service accounts, Keys", value: "keyfile"},
			}
		}}
}

func gcpKeyFileQ() formQ {
	return formWhen(formQ{key: "keyfile", label: "Key file", ask: "Where is the key file?", example: "~/keys/komando-sa.json",
		help:  "The JSON file from IAM, Service accounts, Keys. komando reads it each time, so leave it where it is.",
		check: func(_ *store.State, _ formAnswers, v string) string { return gcsKeyProblem(v) }},
		func(a formAnswers) bool { return a["login"] == "keyfile" })
}

// gcpKeyBuild adds the key file to conn add when one was picked.
func gcpKeyBuild(a formAnswers, cmds [][]string) [][]string {
	if a["login"] == "keyfile" {
		cmds[0] = append(cmds[0], "--password-ref", "file:"+formAbs(a["keyfile"]))
	}
	return cmds
}
