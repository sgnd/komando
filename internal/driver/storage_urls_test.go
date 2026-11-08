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
