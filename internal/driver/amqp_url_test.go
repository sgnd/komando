package driver

import (
	"strings"
	"testing"
)

func TestParseAMQP(t *testing.T) {
	ResolveSecret = nil
	cases := []struct {
		raw, addr, user, vhost, tls, ca, mgmt string
		secure                                bool
	}{
		{raw: "amqp://rabbit.internal", addr: "rabbit.internal:5672", vhost: "/"},
		{raw: "amqp://app@rabbit.internal:5673/", addr: "rabbit.internal:5673", user: "app", vhost: "/"},
		{raw: "amqp://app@rabbit.internal/%2F", addr: "rabbit.internal:5672", user: "app", vhost: "/"},
		{raw: "amqp://app@rabbit.internal/prod?management=15672", addr: "rabbit.internal:5672", user: "app", vhost: "prod", mgmt: "rabbit.internal:15672"},
		{raw: "amqps://app@rabbit.example.com/a%2Fb", addr: "rabbit.example.com:5671", user: "app", vhost: "a/b", secure: true},
		{raw: "amqps://app@r.example.com:5671?ca=secret:rmq-ca&management=15671", addr: "r.example.com:5671", user: "app", vhost: "/", secure: true, ca: "secret:rmq-ca", mgmt: "r.example.com:15671"},
		{raw: "AMQPS://r.example.com?tls=skip-verify", addr: "r.example.com:5671", vhost: "/", secure: true, tls: "skip-verify"},
		{raw: "amqp://r.example.com?insecure=1", addr: "r.example.com:5672", vhost: "/"},
	}
	for _, c := range cases {
		tg, err := Parse(c.raw)
		if err != nil {
			t.Errorf("%s: %v", c.raw, err)
			continue
		}
		if tg.Kind.Name != "rabbitmq" || tg.Kind.Family != "queue" || tg.Address != c.addr || tg.User != c.user || tg.Database != c.vhost ||
			tg.Secure != c.secure || tg.TLS != c.tls || tg.CA != c.ca || tg.Management != c.mgmt {
			t.Errorf("%s: got %+v", c.raw, tg)
		}
	}
	if tg, _ := Parse("amqp://app@rabbit:5672/prod"); tg.Describe() != "rabbitmq app@rabbit:5672 vhost prod" {
		t.Errorf("describe: %q", tg.Describe())
	}
}

func TestParseAMQPRefuses(t *testing.T) {
	for raw, want := range map[string]string{
		"amqp://app:secret@rabbit":                   "password",
		"amqp://rabbit/a/b":                          "one virtual host",
		"amqp://rabbit?tls=skip-verify":              "for amqps",
		"amqps://rabbit?tls=true":                    "can only be skip-verify",
		"amqp://rabbit?ca=secret:x":                  "use amqps",
		"amqps://rabbit?tls=skip-verify&ca=secret:x": "do not go together",
		"amqp://rabbit?management=http://x":          "takes a port",
		"amqp://rabbit?heartbeat=10":                 "unknown rabbitmq URL option",
		"amqp://rabbit:0":                            "is not a number from 1 to 65535",
		"amqp:///vhost":                              "needs a host",
	} {
		_, err := Parse(raw)
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: %v, want %q", raw, err, want)
		}
	}
}
