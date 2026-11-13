package driver

import (
	"net/url"
	"regexp"
	"strings"

	"github.com/sgnd/komando/internal/out"
)

// gcpProject is a Google Cloud project ID: 6 to 30 lowercase letters,
// digits and hyphens, starting with a letter and not ending in a hyphen.
var gcpProject = regexp.MustCompile(`^[a-z][a-z0-9-]{4,28}[a-z0-9]$`)

// parsePubsub reads pubsub://PROJECT for Google Cloud Pub/Sub
// (docs/features/queues.md). The conn is one project; topics and
// subscriptions are given to each command. The login is gcloud's
// application default credentials, or a service account key from
// --password-ref, as for gs:// storage. Options:
//
//	?endpoint=URL   another Pub/Sub endpoint: a regional one
//	                (https://europe-west1-pubsub.googleapis.com), a private
//	                one, or the emulator (http://localhost:8085)
//	?insecure=1     accept an http:// endpoint across the network
func parsePubsub(u *url.URL, t Target) (Target, error) {
	t.Project = u.Host
	if u.User != nil {
		return Target{}, out.Usage("a pubsub URL has no user: the login is gcloud's, or a service account key in --password-ref")
	}
	if !gcpProject.MatchString(t.Project) {
		return Target{}, out.Usage("pubsub URL is pubsub://PROJECT, such as pubsub://my-project (the Google Cloud project ID: 6 to 30 lowercase letters, digits and hyphens), not %q", u.Host)
	}
	if p := strings.Trim(u.Path, "/"); p != "" {
		return Target{}, out.Usage("a pubsub URL names a project only: drop %q from it (topics and subscriptions are given to each command)", "/"+p)
	}
	q := u.Query()
	if err := onlyOptions(q, "pubsub", "endpoint", "insecure"); err != nil {
		return Target{}, err
	}
	if err := endpointOf(q, "pubsub", "https://pubsub.googleapis.com", &t); err != nil {
		return Target{}, err
	}
	if t.Path != "" {
		return Target{}, out.Usage("the pubsub endpoint is a server only, such as http://localhost:8085: drop %q from it", "/"+t.Path)
	}
	if v := q.Get("insecure"); v != "" && v != "1" {
		return Target{}, out.Usage("pubsub insecure option can only be 1")
	}
	return t, nil
}
