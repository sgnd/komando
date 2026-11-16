// Package gcpadc finds Google application-default credentials for every
// komando client that uses them (Secret Manager, GKE, registries, Cloud
// Storage, BigQuery, Pub/Sub), after checking where the file found would
// send what.
package gcpadc

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"golang.org/x/oauth2/google"
)

// CheckLocalFile is asked before a file of this computer is read to be
// sent as a login (what names the setting that points at it). The cli sets
// it: for an AI agent it refuses a file the agent may not send.
var CheckLocalFile = func(what, path string) error { return nil }

// FileError is CheckLocalFile's refusal; Err is its error, unchanged.
type FileError struct{ Err error }

func (e *FileError) Error() string { return e.Err.Error() }
func (e *FileError) Unwrap() error { return e.Err }

// Find is google.FindDefaultCredentials, after a look at the file it
// would use. A workload or workforce identity file (external_account)
// names a file of this computer and the address its contents go to, and
// the Google library follows both as written: an AI agent that sets
// GOOGLE_APPLICATION_CREDENTIALS on its command line would have komando
// read a private key and send it to a listener of its own. So the
// addresses have to be Google's over https, and the file is put to
// CheckLocalFile first.
func Find(ctx context.Context, scopes ...string) (*google.Credentials, error) {
	if err := checkFile(File()); err != nil {
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

// checkFile checks an external_account file; any other file, and one that
// is missing or does not parse, is the Google library's to judge.
func checkFile(path string) error {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var f struct {
		Type          string `json:"type"`
		TokenURL      string `json:"token_url"`
		TokenInfoURL  string `json:"token_info_url"`
		Impersonation string `json:"service_account_impersonation_url"`
		Source        struct {
			File string `json:"file"`
		} `json:"credential_source"`
	}
	if json.Unmarshal(b, &f) != nil || !strings.HasPrefix(f.Type, "external_account") {
		return nil
	}
	for _, a := range []struct{ name, url string }{{"token_url", f.TokenURL}, {"token_info_url", f.TokenInfoURL}, {"service_account_impersonation_url", f.Impersonation}} {
		if a.url != "" && !googleURL(a.url) {
			return fmt.Errorf("%s: %s is %q, which is not an https address of googleapis.com; komando sends a login only to Google", path, a.name, a.url)
		}
	}
	if f.Source.File != "" {
		if err := CheckLocalFile("credential_source.file of "+path, f.Source.File); err != nil {
			return &FileError{Err: err}
		}
	}
	return nil
}

// googleURL reports an https address on googleapis.com, with no user part
// (https://sts.googleapis.com@other.example is other.example).
func googleURL(s string) bool {
	u, err := url.Parse(s)
	if err != nil || u.Scheme != "https" || u.User != nil {
		return false
	}
	h := strings.ToLower(u.Hostname())
	return h == "googleapis.com" || strings.HasSuffix(h, ".googleapis.com")
}
