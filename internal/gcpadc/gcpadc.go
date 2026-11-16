// Package gcpadc finds Google application-default credentials for every
// komando client that uses them (Secret Manager, GKE, registries, Cloud
// Storage, BigQuery, Pub/Sub), after checking where the file found would
// send what.
package gcpadc

import (
	"context"
	"encoding/json"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"

	"golang.org/x/oauth2/google"

	"github.com/sgnd/komando/internal/out"
	"github.com/sgnd/komando/internal/transport"
)

// CheckLocalFile is asked before a file of this computer is read to be
// sent as a login (what names the setting that points at it). The cli sets
// it: for an AI agent it refuses a file the agent may not send.
var CheckLocalFile = func(what, path string) error { return nil }

// FileError is a refusal of komando's own (CheckLocalFile's, or a file
// that would send a login elsewhere); Err is komando's error, to show as
// it is and not as a missing login.
type FileError struct{ Err error }

func (e *FileError) Error() string { return e.Err.Error() }
func (e *FileError) Unwrap() error { return e.Err }

// Find is google.FindDefaultCredentials, after a look at the file it
// would use. Some kinds of file name a file of this computer, a program
// to run or an address, and the Google library follows them as written:
// an AI agent that sets GOOGLE_APPLICATION_CREDENTIALS on its command
// line would have komando read a private key and send it to a listener
// of its own. So:
//
//   - every address in the file (also inside source_credentials) has to
//     be one of Google's token services;
//   - a file the contents of which are sent is put to CheckLocalFile;
//   - in an AI agent's environment only a gcloud login and a service
//     account key are used, made from the bytes that were checked.
func Find(ctx context.Context, scopes ...string) (*google.Credentials, error) {
	path := File()
	b, err := os.ReadFile(path)
	if err != nil {
		// no file: the metadata server on Google Cloud, or no login
		return google.FindDefaultCredentials(ctx, scopes...)
	}
	var f credFile
	if json.Unmarshal(b, &f) != nil {
		return google.FindDefaultCredentials(ctx, scopes...) // the library says what is wrong with it
	}
	if transport.EnvDistrusted() {
		var kind google.CredentialsType
		switch f.Type {
		case "authorized_user":
			kind = google.AuthorizedUser
		case "service_account":
			kind = google.ServiceAccount
		default:
			return nil, &FileError{Err: out.Errf(out.ExitPolicy, "SENSITIVE_FILE", "the user sets up this Google login in their own terminal; for an AI agent komando uses a gcloud login (`gcloud auth application-default login`) or a service account key",
				"%s is a Google login file of the kind %q, which names files, programs or addresses of its own; komando does not follow it for an AI agent", path, f.Type).NoFlag()}
		}
		return google.CredentialsFromJSONWithType(ctx, b, kind, scopes...)
	}
	if err := f.check(path); err != nil {
		return nil, err
	}
	return google.FindDefaultCredentials(ctx, scopes...)
}

// File is the credentials file the Google library reads: the one
// GOOGLE_APPLICATION_CREDENTIALS names, else the file `gcloud auth
// application-default login` writes.
func File() string {
	if p := os.Getenv("GOOGLE_APPLICATION_CREDENTIALS"); p != "" {
		return p
	}
	if runtime.GOOS == "windows" {
		return filepath.Join(os.Getenv("APPDATA"), "gcloud", "application_default_credentials.json")
	}
	home := os.Getenv("HOME")
	if home == "" {
		home, _ = os.UserHomeDir()
	}
	return filepath.Join(home, ".config", "gcloud", "application_default_credentials.json")
}

// credFile is what komando reads of a Google credentials file.
type credFile struct {
	Type          string `json:"type"`
	TokenURL      string `json:"token_url"`
	TokenInfoURL  string `json:"token_info_url"`
	Impersonation string `json:"service_account_impersonation_url"`
	Source        struct {
		File string `json:"file"`
	} `json:"credential_source"`
	Inner *credFile `json:"source_credentials"`
}

// Google's token services: where a login file may send what it holds.
var (
	stsHost = regexp.MustCompile(`^sts(\.mtls|\.[a-z0-9-]+\.rep)?\.googleapis\.com$`)
	iamHost = regexp.MustCompile(`^iamcredentials(\.mtls|\.[a-z0-9-]+\.rep)?\.googleapis\.com$`)
)

// check checks the addresses and the file a credentials file names, and
// those of the credentials inside it.
func (f *credFile) check(path string) error {
	for depth := 0; f != nil; f, depth = f.Inner, depth+1 {
		if depth > 4 {
			return refuse("%s nests logins too deep", path)
		}
		for _, a := range []struct {
			name, url string
			host      *regexp.Regexp
			ok        func(p string) bool
		}{
			{"token_url", f.TokenURL, stsHost, func(p string) bool { return p == "/v1/token" || p == "/v1/oauthtoken" }},
			{"token_info_url", f.TokenInfoURL, stsHost, func(p string) bool { return p == "/v1/introspect" }},
			{"service_account_impersonation_url", f.Impersonation, iamHost, func(p string) bool { return strings.HasPrefix(p, "/v1/projects/-/serviceAccounts/") }},
		} {
			if !strings.HasPrefix(f.Type, "external_account") && a.name != "service_account_impersonation_url" {
				continue // token_uri of a key or a gcloud login belongs to that file's own secret
			}
			if a.url == "" {
				continue
			}
			u, err := url.Parse(a.url)
			if err != nil || u.Scheme != "https" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || !a.host.MatchString(strings.ToLower(u.Host)) || !a.ok(u.Path) {
				return refuse("%s: %s is %q, which is not one of Google's token services (https://sts.googleapis.com/v1/token, https://iamcredentials.googleapis.com/...); komando sends a login only there", path, a.name, a.url)
			}
		}
		if f.Source.File != "" {
			if err := CheckLocalFile("credential_source.file of "+path, f.Source.File); err != nil {
				return &FileError{Err: err}
			}
		}
	}
	return nil
}

// refuse is a stop of komando's own, not a login a person fixes by
// signing in again.
func refuse(format string, a ...any) error {
	return &FileError{Err: out.Usage(format, a...)}
}
