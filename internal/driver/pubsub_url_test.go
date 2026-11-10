package driver

import (
	"strings"
	"testing"
)

func TestParsePubsub(t *testing.T) {
	cases := []struct {
		raw, addr, project string
		secure             bool
	}{
		{raw: "pubsub://my-project", addr: "pubsub.googleapis.com:443", project: "my-project", secure: true},
		{raw: "pubsub://my-project/", addr: "pubsub.googleapis.com:443", project: "my-project", secure: true},
		{raw: "pubsub://my-project?endpoint=https://europe-west1-pubsub.googleapis.com", addr: "europe-west1-pubsub.googleapis.com:443", project: "my-project", secure: true},
		{raw: "pubsub://test-project?endpoint=http://localhost:8085", addr: "localhost:8085", project: "test-project"},
		{raw: "pubsub://test-project?endpoint=http://pubsub:8085&insecure=1", addr: "pubsub:8085", project: "test-project"},
	}
	for _, c := range cases {
		tg, err := Parse(c.raw)
		if err != nil {
			t.Errorf("%s: %v", c.raw, err)
			continue
		}
		if tg.Kind.Name != "pubsub" || tg.Kind.Family != "queue" || tg.Address != c.addr || tg.Project != c.project || tg.Secure != c.secure {
			t.Errorf("%s: got %+v", c.raw, tg)
		}
	}
	if tg, _ := Parse("pubsub://my-project"); tg.Describe() != "pubsub project my-project at pubsub.googleapis.com:443" {
		t.Errorf("describe: %q", tg.Describe())
	}
}

func TestParsePubsubRefuses(t *testing.T) {
	for raw, want := range map[string]string{
		"pubsub://":                                "pubsub://PROJECT",
		"pubsub://My-Project":                      "pubsub://PROJECT",
		"pubsub://proj":                            "pubsub://PROJECT",
		"pubsub://my-project-":                     "pubsub://PROJECT",
		"pubsub://my-project:443":                  "pubsub://PROJECT",
		"pubsub://me@my-project":                   "has no user",
		"pubsub://my-project/topics/orders":        "drop \"/topics/orders\"",
		"pubsub://my-project?topic=orders":         "unknown pubsub URL option",
		"pubsub://my-project?endpoint=ftp://x":     "endpoint must be a URL",
		"pubsub://my-project?endpoint=http://x/v1": "server only",
		"pubsub://my-project?insecure=yes":         "only be 1",
		"pubsub://my-project?password=abc":         "must not contain a password",
	} {
		_, err := Parse(raw)
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: %v, want %q", raw, err, want)
		}
	}
}
