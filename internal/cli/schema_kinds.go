package cli

import (
	"slices"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"

	"github.com/sgnd/komando/internal/driver"
)

// The kinds `conn add` takes, with the flags that go with each. The table
// feeds the add_kinds list of `komando schema conn add`, from which an app
// builds its add forms. A VPN has no such list: its kind is a word of the
// path (`vpn wireguard add`), and the options of that path are the leaf's.

// connKindTitles are the names people know the conn kinds by.
var connKindTitles = map[string]string{
	"postgres": "PostgreSQL", "mysql": "MySQL or MariaDB", "sqlserver": "SQL Server", "oracle": "Oracle Database",
	"clickhouse": "ClickHouse", "snowflake": "Snowflake", "bigquery": "Google BigQuery", "sqlite": "SQLite", "mongodb": "MongoDB",
	"redis": "Redis or Valkey", "memcached": "Memcached",
	"kafka": "Apache Kafka", "rabbitmq": "RabbitMQ", "nats": "NATS JetStream", "sqs": "Amazon SQS", "pubsub": "Google Cloud Pub/Sub",
	"k8s": "Kubernetes", "registry": "Container registry",
	"s3": "S3 or S3-compatible storage", "ftps": "FTPS", "ftp": "FTP", "sftp": "SFTP", "gcs": "Google Cloud Storage",
	"azblob": "Azure Blob Storage", "webdav": "WebDAV", "smb": "SMB share",
}

// connKindNeeds are the flags `komando FAMILY add` needs for kind k
// (family "" is conn add): a Kubernetes cluster logs in with a whole
// kubeconfig, which only --password-ref gives.
func connKindNeeds(family string, k driver.Kind) []string {
	if family == "cluster" && k.Name == "k8s" {
		return []string{"password-ref"}
	}
	return []string{}
}

// connKindSchema is one conn kind in `komando schema conn add` (and db
// add, cache add, ...).
type connKindSchema struct {
	ID          string     `json:"id"`
	DisplayName string     `json:"display_name"`
	Family      string     `json:"family"`
	URLSchemes  []string   `json:"url_schemes"`
	URLExample  string     `json:"url_example"`
	URLNote     string     `json:"url_note,omitempty"`
	DefaultPort int        `json:"default_port,omitempty"`
	File        bool       `json:"file"`
	Required    []string   `json:"required"`
	OneOf       [][]string `json:"one_of"`
	Optional    []string   `json:"optional"`
}

// connKindSchemas are the kinds c (conn add, or `komando FAMILY add`
// for family) takes, with c's own flags.
func connKindSchemas(c *cobra.Command, family string) []connKindSchema {
	var res []connKindSchema
	for _, k := range driver.Kinds() {
		if family != "" && k.Family != family {
			continue
		}
		need := connKindNeeds(family, k)
		var opt []string
		ownFlags(c).VisitAll(func(f *pflag.Flag) {
			switch {
			case f.Hidden, f.Name == "help", slices.Contains(need, f.Name):
			case f.Name == "via" && k.File: // a file on this computer
			case f.Name == "ask-password" && slices.Contains(need, "password-ref"): // a kubeconfig is not typed
			default:
				opt = append(opt, f.Name)
			}
		})
		example, note, _ := strings.Cut(k.Example, " (")
		res = append(res, connKindSchema{ID: k.Name, DisplayName: connKindTitles[k.Name], Family: k.Family, URLSchemes: k.Schemes,
			URLExample: example, URLNote: strings.TrimSuffix(note, ")"), DefaultPort: k.DefaultPort, File: k.File,
			Required: need, OneOf: [][]string{}, Optional: opt})
	}
	return res
}

// addKindsOf is the add_kinds list of c in `komando schema`, or nil for
// a command that adds no kind.
func addKindsOf(c *cobra.Command) any {
	switch id := cmdID(c); {
	case id == "conn.add":
		return connKindSchemas(c, "")
	case strings.HasSuffix(id, ".add") && connAddKinds[strings.TrimSuffix(id, ".add")].what != "":
		return connKindSchemas(c, strings.TrimSuffix(id, ".add"))
	}
	return nil
}
