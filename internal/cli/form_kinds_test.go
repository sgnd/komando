package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sgnd/komando/internal/driver"
	"github.com/sgnd/komando/internal/store"
)

// formCheckLine parses one line an Add form built: the command and its
// flags, the conn URL as the drivers read it, a host's address as host add
// reads it; and no approval flag is ever in it.
func formCheckLine(t *testing.T, source string, line []string) {
	t.Helper()
	for _, w := range line {
		if w == "--yes" || w == "--allow-dangerous" || w == "--reveal" {
			t.Errorf("%s: `komando %s` has %s", source, menuCommandLine(line), w)
		}
	}
	cmd := formParse(t, source, line)
	if cmd == nil {
		return
	}
	switch commandKey(cmd) {
	case "conn add":
		if _, err := driver.Parse(cmd.Flags().Arg(1)); err != nil {
			t.Errorf("%s: URL %q: %v", source, cmd.Flags().Arg(1), err)
		}
	case "host add":
		if _, err := parseAddressArg(cmd.Flags().Arg(1)); err != nil {
			t.Errorf("%s: address %q: %v", source, cmd.Flags().Arg(1), err)
		}
	}
}

// Every choice of every list question, one at a time (the other answers
// as formSample gives them), builds lines komando takes.
func TestFormAddEveryChoiceBuilds(t *testing.T) {
	for _, st := range []*store.State{testState(), {Hosts: map[string]*store.Host{}}} {
		for _, g := range formGroups() {
			for _, k := range g.kinds {
				sp := k.spec()
				for i, q := range sp.qs {
					if q.choices == nil {
						continue
					}
					for _, row := range q.choices(st, formAnswers{}) {
						a := formAnswers{}
						for j, qq := range sp.qs {
							switch {
							case j == i:
								a[qq.key] = row.value
							case qq.visible(st, a):
								a[qq.key] = formSample(st, qq, a)
							}
						}
						shown := formAnswers{}
						for _, qq := range sp.qs {
							if v, ok := a[qq.key]; ok && qq.visible(st, a) {
								shown[qq.key] = v
							}
						}
						for _, line := range sp.build(st, shown) {
							formCheckLine(t, g.label+"/"+k.label+"/"+q.key+"="+row.value, line)
						}
					}
				}
			}
		}
	}
}

// formKindSpec finds one kind's form by its group and label.
func formKindSpec(t *testing.T, group, label string) formSpec {
	t.Helper()
	for _, g := range formGroups() {
		for _, k := range g.kinds {
			if g.label == group && k.label == label {
				return k.spec()
			}
		}
	}
	t.Fatalf("no form %s/%s", group, label)
	return formSpec{}
}

// The Windows, registry, database, queue and SMB kinds build the lines their
// docs show, from plain answers.
func TestFormKindLines(t *testing.T) {
	key := filepath.Join(t.TempDir(), "rsa_key.p8")
	if err := os.WriteFile(key, []byte("-----BEGIN PRIVATE KEY-----\nMIIB\n-----END PRIVATE KEY-----\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	st := &store.State{Hosts: map[string]*store.Host{"web1": {Name: "web1"}}}
	cases := []struct {
		group, kind string
		a           formAnswers
		want        string
	}{
		{"Server", "Server", formAnswers{"name": "win1", "os": "windows", "transport": "ssh", "address": "10.0.0.9",
			"user": "Administrator", "port": "22", "login": "password", "protected": "no"},
			"host add win1 Administrator@10.0.0.9 --os windows --ask-password"},
		{"Server", "Server", formAnswers{"name": "win2", "os": "windows", "transport": "winrm", "address": "10.0.0.9",
			"user": "deploy@corp.local", "winrmtls": "", "winrmport": "5986", "protected": "yes"},
			"host add win2 winrm://deploy@corp.local@10.0.0.9 --ask-password --protected"},
		{"Server", "Server", formAnswers{"name": "win3", "os": "windows", "transport": "winrm", "address": "win3.lan",
			"user": "Administrator", "winrmtls": "off", "winrmport": "5985", "protected": "no"},
			"host add win3 winrm://Administrator@win3.lan?tls=off --ask-password"},
		{"Database", "SQL Server", formAnswers{"name": "sales", "host": "db.internal", "port": "1433", "user": "app",
			"database": "sales", "protected": "no", "tls": "nocheck"},
			"conn add sales sqlserver://app@db.internal/sales?encrypt=true&tls=skip-verify --ask-password"},
		{"Database", "Oracle Database", formAnswers{"name": "erp", "host": "db.internal", "port": "1521", "by": "service",
			"service": "ERPPDB", "user": "app", "protected": "no"},
			"conn add erp oracle://app@db.internal/ERPPDB --ask-password"},
		{"Database", "Oracle Database", formAnswers{"name": "old", "host": "db", "port": "1521", "by": "sid",
			"sid": "ORCL", "user": "app", "protected": "no"},
			"conn add old oracle://app@db?sid=ORCL --ask-password"},
		{"Database", "ClickHouse", formAnswers{"name": "events", "via": "web1", "host": "127.0.0.1", "tls": "false", "port": "8123",
			"user": "default", "database": "analytics", "password": "yes", "protected": "no"},
			"conn add events clickhouse://default@127.0.0.1:8123/analytics?tls=false --ask-password --via web1"},
		{"Database", "Snowflake", formAnswers{"name": "analytics", "account": "myorg-myaccount", "user": "APP_RO", "login": "keyfile",
			"keyfile": key, "warehouse": "REPORTING", "database": "ANALYTICS", "schema": "PUBLIC", "role": "ANALYST_RO", "protected": "no"},
			"conn add analytics snowflake://APP_RO@myorg-myaccount/ANALYTICS/PUBLIC?warehouse=REPORTING&role=ANALYST_RO --password-ref file:" + key},
		{"Database", "Google BigQuery", formAnswers{"name": "warehouse", "project": "my-project", "dataset": "analytics",
			"location": "EU", "login": "gcloud", "protected": "no"},
			"conn add warehouse bigquery://my-project/analytics?location=EU"},
		{"Message queues", "Apache Kafka", formAnswers{"name": "events", "servers": "b1.example.com:9093, b2.example.com:9093",
			"tls": "yes", "login": "sasl", "user": "app", "sasl": "scram-sha-512", "password": "ask", "protected": "no"},
			"conn add events kafka://app@b1.example.com:9093,b2.example.com:9093?sasl=scram-sha-512&tls=true --ask-password"},
		{"Message queues", "Apache Kafka", formAnswers{"name": "local", "via": "web1", "servers": "broker1.internal:9092",
			"tlsvia": "no", "login": "none", "protected": "no"},
			"conn add local kafka://broker1.internal:9092 --via web1"},
		{"Message queues", "RabbitMQ", formAnswers{"name": "jobs", "host": "rabbit.example.com", "tls": "yes", "port": "5671",
			"vhost": "/", "user": "app", "password": "ask", "management": "15671", "protected": "no"},
			"conn add jobs amqps://app@rabbit.example.com/%2F?management=15671 --ask-password"},
		{"Message queues", "NATS JetStream", formAnswers{"name": "stream", "servers": "nats1.example.com:4222,nats2.example.com:4222",
			"tls": "yes", "login": "user", "user": "app", "password": "ask", "protected": "no"},
			"conn add stream tls://app@nats1.example.com:4222,nats2.example.com:4222 --ask-password"},
		{"Message queues", "NATS JetStream", formAnswers{"name": "lab", "servers": "nats.lab", "tls": "no", "login": "token",
			"password": "ask", "protected": "no"},
			"conn add lab nats://nats.lab?insecure=1 --ask-password"},
		{"Message queues", "Amazon SQS", formAnswers{"name": "aws", "region": "eu-west-1", "login": "profile", "profile": "prod", "protected": "no"},
			"conn add aws sqs://eu-west-1 --option aws_profile=prod"},
		{"Message queues", "Amazon SQS", formAnswers{"name": "aws3", "region": "eu-west-1", "login": "key", "keyid": "AKIAIOSFODNN7EXAMPLE", "protected": "no"},
			"conn add aws3 sqs://AKIAIOSFODNN7EXAMPLE@eu-west-1 --ask-password"},
		{"Message queues", "Google Cloud Pub/Sub", formAnswers{"name": "gcp", "project": "my-project", "login": "gcloud", "protected": "no"},
			"conn add gcp pubsub://my-project"},
		{"File storage", "Windows share (SMB)", formAnswers{"name": "team", "host": "fileserver.corp.lan", "share": "team",
			"folder": "reports", "user": "alice", "domain": "CORP", "protected": "no", "port": "445"},
			"conn add team smb://alice@fileserver.corp.lan/team/reports?domain=CORP --ask-password"},
		{"Container registry", "Azure Container Registry", formAnswers{"name": "acr", "host": "myregistry.azurecr.io", "protected": "no"},
			"conn add acr registry://myregistry.azurecr.io"},
		{"Container registry", "Google Artifact Registry", formAnswers{"name": "gar", "host": "europe-west1-docker.pkg.dev", "protected": "no"},
			"conn add gar registry://europe-west1-docker.pkg.dev"},
	}
	for _, c := range cases {
		sp := formKindSpec(t, c.group, c.kind)
		for _, q := range sp.qs {
			v, ok := c.a[q.key]
			if !ok || !q.visible(st, c.a) || q.check == nil {
				continue
			}
			if p := q.check(st, c.a, v); p != "" {
				t.Errorf("%s: %s %q: %s", c.kind, q.key, v, p)
			}
		}
		lines := formBuild(st, sp, c.a)
		if got := strings.Join(lines[0], " "); got != c.want {
			t.Errorf("%s:\n got %s\nwant %s", c.kind, got, c.want)
		}
		formCheckLine(t, c.kind, lines[0])
	}
}

func TestFormNewKindChecks(t *testing.T) {
	cases := []struct {
		problem func(string) string
		v, want string
	}{
		{func(v string) string { return serverUserProblem(nil, nil, v) }, `CORP\deploy`, "deploy@corp.example.com"},
		{func(v string) string { return serverUserProblem(nil, nil, v) }, "deploy@corp.local", ""},
		{func(v string) string { return serverAddressProblem(nil, nil, v) }, "winrm://10.0.0.9", "without winrm://"},
		{func(v string) string { return snowflakeAccountProblem(nil, nil, v) }, "https://myorg-myaccount.snowflakecomputing.com", "type only"},
		{func(v string) string { return snowflakeAccountProblem(nil, nil, v) }, "xy12345.eu-central-1", ""},
		{gcpProjectProblem, "My Project", "project ID"},
		{queueServersProblem, "b1:9093, b2:x", "port"},
		{queueServersProblem, "b1.example.com:9093, b2.example.com", ""},
		{func(v string) string { return sqsRegionProblem(nil, nil, v) }, "EU-West", "region"},
		{func(v string) string { return smbUserQ().check(nil, nil, v) }, `CORP\alice`, "domain CORP"},
	}
	for _, c := range cases {
		if p := c.problem(c.v); (c.want == "") != (p == "") || !strings.Contains(p, c.want) {
			t.Errorf("%q: %q, want %q", c.v, p, c.want)
		}
	}
	sp := clickhouseForm()
	for _, q := range sp.qs {
		if q.key == "port" && !strings.Contains(q.check(nil, formAnswers{}, "9000"), "native") {
			t.Error("ClickHouse port 9000 is taken")
		}
	}
	host := sqlServerForm().qs[2]
	if p := host.check(nil, formAnswers{}, `db\SQLEXPRESS`); !strings.Contains(p, "named instance") {
		t.Errorf("named instance: %q", p)
	}
}
