package cli

import (
	"strings"
	"testing"

	"github.com/sgnd/komando/internal/store"
)

// An s3, gs or azblob conn with an http:// endpoint that crosses the
// network sends the files (and for S3 the AWS session token) unencrypted:
// it needs ?insecure=1 or --via, as sqs and pubsub do. Loopback is fine.
func TestStorageHTTPEndpointNeedsInsecure(t *testing.T) {
	invHome(t)
	for _, u := range []string{
		"s3://backups?endpoint=http://minio.example.com:9000",
		"gs://media?endpoint=http://gcs.example.com:4443",
		"azblob://acct@media?endpoint=http://blob.example.com:10000/acct",
	} {
		e := wantCode(t, "INSECURE_PROTOCOL", "conn", "add", "plain", u)
		if !strings.Contains(e.Message, "without TLS") || !strings.Contains(e.Hint, "?insecure=1") {
			t.Errorf("%s: %+v", u, e)
		}
	}
	mustRun(t, "host", "add", "office", "u@10.0.0.1")
	mustRun(t, "conn", "add", "s3-via", "s3://backups?endpoint=http://minio:9000", "--via", "office")
	mustRun(t, "conn", "add", "s3-local", "s3://backups?endpoint=http://127.0.0.1:9000")
	mustRun(t, "conn", "add", "az-local", "azblob://devstoreaccount1@media?endpoint=http://localhost:10000/devstoreaccount1")
	for i, u := range []string{
		"s3://backups?endpoint=http://minio.example.com:9000&insecure=1",
		"gs://media?endpoint=http://gcs.example.com:4443&insecure=1",
		"azblob://acct@media?endpoint=http://blob.example.com:10000/acct&insecure=1",
	} {
		name := []string{"s3-plain", "gcs-plain", "az-plain"}[i]
		mustRun(t, "conn", "add", name, u)
		if got := plainConn(&store.Conn{Name: name, URL: u}); !strings.Contains(got, "https endpoint") {
			t.Errorf("doctor %s: %q", name, got)
		}
	}
	mustRun(t, "conn", "edit", "s3-local", "--url", "s3://backups?endpoint=https://minio.example.com")
	wantCode(t, "INSECURE_PROTOCOL", "conn", "edit", "s3-local", "--url", "s3://backups?endpoint=http://minio.example.com")
}
