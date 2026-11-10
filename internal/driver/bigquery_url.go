package driver

import (
	"net/url"
	"regexp"
	"strings"

	"github.com/sgnd/komando/internal/out"
)

// BigQuery is reached over its REST API (HTTPS, bigquery.googleapis.com).
// The conn URL names the Google Cloud project the jobs run (and are billed)
// in, and optionally a default dataset:
//
//	bigquery://PROJECT[/DATASET]?location=EU
//
// The login is Google's, as for gs:// conns: a service account key (JSON)
// in --password-ref, or else the application default credentials
// (gcloud auth application-default login, or the metadata server).
// ?endpoint= points it at an emulator or a Private Service Connect address.

// BigQueryEndpoint is Google's address for the BigQuery API.
const BigQueryEndpoint = "https://bigquery.googleapis.com"

// BigQueryConn is what a bigquery:// URL says, beyond the Target.
type BigQueryConn struct {
	Project  string
	Dataset  string // the default dataset for names without one; may be ""
	Location string // where jobs run: EU, US, europe-west1, ...; "" lets BigQuery pick
	Endpoint string // https://bigquery.googleapis.com, or ?endpoint=
}

var (
	bqProject  = regexp.MustCompile(`^[a-z][a-z0-9-]{4,28}[a-z0-9]$`)
	bqDataset  = regexp.MustCompile(`^[A-Za-z0-9_]{1,1000}$`)
	bqLocation = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9-]{0,62}$`)
)

// ParseBigQueryURL reads a bigquery:// conn URL.
func ParseBigQueryURL(raw string) (BigQueryConn, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return BigQueryConn{}, out.Usage("invalid conn URL: %v", err)
	}
	if u.User != nil {
		return BigQueryConn{}, out.Usage("bigquery URL has no user: the login is gcloud's, or a service account key in --password-ref (%s)", kinds["bigquery"].Example)
	}
	if u.Port() != "" || !bqProject.MatchString(u.Hostname()) {
		return BigQueryConn{}, out.Errf(out.ExitUsage, "USAGE",
			"write the project ID as the console shows it (6 to 30 lower-case letters, digits and -), e.g. "+kinds["bigquery"].Example,
			"bigquery project %q is not a project ID", u.Host)
	}
	b := BigQueryConn{Project: u.Hostname(), Endpoint: BigQueryEndpoint}
	if path := strings.Trim(u.Path, "/"); path != "" {
		if !bqDataset.MatchString(path) {
			return BigQueryConn{}, out.Usage("bigquery URL path is one dataset (letters, digits and _), not %q", u.Path)
		}
		b.Dataset = path
	}
	q := u.Query()
	for key := range q {
		switch key {
		case "location", "endpoint", "ca":
		case "tls":
			return BigQueryConn{}, out.Usage("bigquery conns are always HTTPS with the certificate checked: drop tls= (a private CA, such as a proxy's: ?ca=secret:NAME)")
		default:
			return BigQueryConn{}, out.Usage("unknown bigquery URL option %q (known: location, endpoint, ca (secret:NAME))", key)
		}
	}
	if b.Location = q.Get("location"); b.Location != "" && !bqLocation.MatchString(b.Location) {
		return BigQueryConn{}, out.Usage("bigquery location %q is not a location (EU, US, europe-west1, ...)", b.Location)
	}
	if e := q.Get("endpoint"); e != "" {
		b.Endpoint = strings.TrimRight(e, "/")
	}
	return b, nil
}

// parseBigQuery fills t from a bigquery:// URL: HTTPS to Google unless
// ?endpoint= names another address (an http:// one, for an emulator, is
// what doctor and conn add warn about).
func parseBigQuery(u *url.URL, t Target) (Target, error) {
	b, err := ParseBigQueryURL(u.String())
	if err != nil {
		return Target{}, err
	}
	if err := endpointOf(url.Values{"endpoint": {b.Endpoint}}, "bigquery", BigQueryEndpoint, &t); err != nil {
		return Target{}, err
	}
	t.Database = b.Dataset
	if err := parseCA(u.Query(), &t); err != nil {
		return Target{}, err
	}
	return t, nil
}
