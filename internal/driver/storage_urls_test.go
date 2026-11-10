package driver

import (
	"strings"
	"testing"

	"github.com/sgnd/komando/internal/out"
)

func TestCloudStorageURLs(t *testing.T) {
	for raw, want := range map[string]string{
		"gs://media/site/assets":                                             "gcs media site/assets/ storage.googleapis.com:443 true ",
		"gcs://media?endpoint=http://gcs:4443":                               "gcs media  gcs:4443 false ",
		"azblob://acct@uploads/2026":                                         "azblob uploads 2026/ acct.blob.core.windows.net:443 true ",
		"azure://dev@media?endpoint=http://127.0.0.1:10000/devstoreaccount1": "azblob media  127.0.0.1:10000 false devstoreaccount1",
		"webdavs://alice@cloud.example.com/remote.php/dav/files/alice":       "webdav  remote.php/dav/files/alice/ cloud.example.com:443 true ",
		"webdav://bob@nas.lan:8080/share?insecure=1":                         "webdav  share/ nas.lan:8080 false ",
	} {
		tg, err := Parse(raw)
		if err != nil {
			t.Errorf("%s: %v", raw, err)
			continue
		}
		got := strings.Join([]string{tg.Kind.Name, tg.Bucket, tg.Prefix, tg.Address, map[bool]string{true: "true", false: "false"}[tg.Secure], tg.Path}, " ")
		if got != want {
			t.Errorf("%s:\n got %q\nwant %q", raw, got, want)
		}
	}
	for raw, code := range map[string]string{
		"gs://user@media":                     "USAGE",
		"gs://media?region=eu":                "USAGE",
		"gs://media?endpoint=ftp://x":         "USAGE",
		"azblob://uploads":                    "USAGE", // no account
		"azblob://acct@uploads?sas=x":         "USAGE",
		"webdav://bob@nas.lan/share":          "INSECURE_PROTOCOL",
		"webdavs://bob@nas.lan/share?tls=yes": "USAGE",
		"webdavs://bob@nas.lan:99999/":        "USAGE",
		"webdavs:///share":                    "USAGE",
	} {
		_, err := Parse(raw)
		if oe, ok := err.(*out.Error); !ok || oe.Code != code {
			t.Errorf("%s: %v, want %s", raw, err, code)
		}
	}
	if tg, _ := Parse("webdavs://nas.lan/x?tls=skip-verify"); tg.TLS != "skip-verify" || tg.User != "" {
		t.Errorf("skip-verify, no user: %+v", tg)
	}
}

func TestSMBURLs(t *testing.T) {
	for raw, want := range map[string]string{
		"smb://alice@fs.corp.lan/team/reports/2026?domain=CORP": "smb alice CORP team reports/2026/ fs.corp.lan:445 fs.corp.lan:445/team/reports/2026",
		"cifs://CORP;alice@fs.corp.lan:1445/team":               "smb alice CORP team  fs.corp.lan:1445 fs.corp.lan:1445/team",
		"smb://corp;alice@fs/team/?domain=CORP":                 "smb alice corp team  fs:445 fs:445/team",
		"smb://bob@10.0.0.5/Public":                             "smb bob  Public  10.0.0.5:445 10.0.0.5:445/Public",
	} {
		tg, err := Parse(raw)
		if err != nil {
			t.Errorf("%s: %v", raw, err)
			continue
		}
		where := strings.ReplaceAll(tg.Where(), " @ ", "@")
		share, addr, _ := strings.Cut(where, "@")
		got := strings.Join([]string{tg.Kind.Name, tg.User, tg.Domain, tg.Bucket, tg.Prefix, tg.Address, addr + "/" + share}, " ")
		if got != want {
			t.Errorf("%s:\n got %q\nwant %q", raw, got, want)
		}
		if tg.Secure { // Secure means TLS; `cert check` would try a TLS handshake on port 445
			t.Errorf("%s: marked as TLS", raw)
		}
	}
	for raw, code := range map[string]string{
		"smb://fs.corp.lan/team":                    "USAGE", // no user: guests cannot sign
		"smb://alice@fs.corp.lan":                   "USAGE", // no share
		"smb://alice@fs.corp.lan/te:am":             "USAGE",
		"smb://alice@fs.corp.lan/team?tls=1":        "USAGE",
		"smb://A;alice@fs.corp.lan/team?domain=B":   "USAGE",
		"smb://alice@fs.corp.lan:0/team":            "USAGE",
		"smb:///team":                               "USAGE",
		"smb://alice@fs.corp.lan/team?password=x":   "URL_HAS_PASSWORD",
		"smb://alice:pw@fs.corp.lan/team":           "URL_HAS_PASSWORD",
		"smb://CORP;alice:pw@fs.corp.lan/team/a/b/": "URL_HAS_PASSWORD",
	} {
		_, err := Parse(raw)
		if oe, ok := err.(*out.Error); !ok || oe.Code != code {
			t.Errorf("%s: %v, want %s", raw, err, code)
		}
	}
}
