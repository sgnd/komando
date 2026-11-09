package driver

import (
	"strings"
	"testing"
)

func TestParseNATS(t *testing.T) {
	ResolveSecret = nil
	cases := []struct {
		raw, addr, user, tls, ca, creds, domain string
		servers                                 int
		secure                                  bool
	}{
		{raw: "nats://nats.internal", addr: "nats.internal:4222", servers: 1},
		{raw: "nats://app@nats.internal:4223/", addr: "nats.internal:4223", user: "app", servers: 1},
		{raw: "nats://n1.internal:4222,n2.internal,n3.internal:5222", addr: "n1.internal:4222", servers: 3},
		{raw: "tls://app@nats.example.com?ca=secret:nats-ca", addr: "nats.example.com:4222", user: "app", secure: true, ca: "secret:nats-ca", servers: 1},
		{raw: "TLS://nats.example.com?tls=skip-verify&domain=hub", addr: "nats.example.com:4222", secure: true, tls: "skip-verify", domain: "hub", servers: 1},
		{raw: "tls://connect.ngs.global?creds=secret:ngs", addr: "connect.ngs.global:4222", secure: true, creds: "secret:ngs", servers: 1},
		{raw: "nats://nats.example.com?insecure=1", addr: "nats.example.com:4222", servers: 1},
	}
	for _, c := range cases {
		tg, err := Parse(c.raw)
		if err != nil {
			t.Errorf("%s: %v", c.raw, err)
			continue
		}
		if tg.Kind.Name != "nats" || tg.Kind.Family != "queue" || tg.Address != c.addr || tg.User != c.user || len(tg.Brokers) != c.servers ||
			tg.Secure != c.secure || tg.TLS != c.tls || tg.CA != c.ca || tg.Creds != c.creds || tg.Domain != c.domain {
			t.Errorf("%s: got %+v", c.raw, tg)
		}
	}
	if tg, _ := Parse("nats://app@n1:4222,n2:4222"); tg.Describe() != "nats app@n1:4222 (+1 server)" {
		t.Errorf("describe: %q", tg.Describe())
	}
}

func TestParseNATSRefuses(t *testing.T) {
	for raw, want := range map[string]string{
		"nats://app:secret@nats":                 "password",
		"nats://nats/ORDERS":                     "servers only",
		"nats://nats?tls=skip-verify":            "for tls://",
		"tls://nats?tls=true":                    "can only be skip-verify",
		"nats://nats?ca=secret:x":                "use tls://",
		"tls://nats?tls=skip-verify&ca=secret:x": "do not go together",
		"nats://nats?creds=/home/me/user.creds":  "secret:NAME",
		"nats://app@nats?creds=secret:x":         "not both",
		"nats://nats?token=abc":                  "unknown nats URL option",
		"nats://nats:0":                          "invalid port",
		"nats:///":                               "needs a server",
	} {
		_, err := Parse(raw)
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: %v, want %q", raw, err, want)
		}
	}
}
