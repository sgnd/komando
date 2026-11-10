package driver

import (
	"strings"
	"testing"
)

func TestParseSQS(t *testing.T) {
	cases := []struct {
		raw, addr, region, user, account string
		secure                           bool
	}{
		{raw: "sqs://eu-west-1", addr: "sqs.eu-west-1.amazonaws.com:443", region: "eu-west-1", secure: true},
		{raw: "sqs://AKIAEXAMPLE@us-east-1/", addr: "sqs.us-east-1.amazonaws.com:443", region: "us-east-1", user: "AKIAEXAMPLE", secure: true},
		{raw: "sqs://cn-north-1?account=123456789012", addr: "sqs.cn-north-1.amazonaws.com.cn:443", region: "cn-north-1", account: "123456789012", secure: true},
		{raw: "sqs://us-gov-west-1", addr: "sqs.us-gov-west-1.amazonaws.com:443", region: "us-gov-west-1", secure: true},
		{raw: "sqs://us-east-1?endpoint=http://localhost:4566", addr: "localhost:4566", region: "us-east-1"},
		{raw: "sqs://us-east-1?endpoint=http://moto:5000&insecure=1", addr: "moto:5000", region: "us-east-1"},
	}
	for _, c := range cases {
		tg, err := Parse(c.raw)
		if err != nil {
			t.Errorf("%s: %v", c.raw, err)
			continue
		}
		if tg.Kind.Name != "sqs" || tg.Kind.Family != "queue" || tg.Address != c.addr || tg.Region != c.region || tg.User != c.user ||
			tg.Account != c.account || tg.Secure != c.secure {
			t.Errorf("%s: got %+v", c.raw, tg)
		}
	}
	if tg, _ := Parse("sqs://AKIA@eu-west-1"); tg.Describe() != "sqs eu-west-1 at AKIA@sqs.eu-west-1.amazonaws.com:443" {
		t.Errorf("describe: %q", tg.Describe())
	}
}

func TestParseSQSRefuses(t *testing.T) {
	for raw, want := range map[string]string{
		"sqs://":                              "sqs://REGION",
		"sqs://eu-west-1:443":                 "sqs://REGION",
		"sqs://EU-WEST-1":                     "sqs://REGION",
		"sqs://eu-west-1/orders":              "drop \"/orders\"",
		"sqs://eu-west-1?queue=orders":        "unknown sqs URL option",
		"sqs://eu-west-1?account=12":          "12-digit",
		"sqs://eu-west-1?endpoint=ftp://x":    "endpoint must be a URL",
		"sqs://eu-west-1?endpoint=http://x/a": "server only",
		"sqs://eu-west-1?insecure=yes":        "only be 1",
		"sqs://AKIA@eu-west-1?secret_key=abc": "must not contain a password",
		"sqs://AKIA:secret@eu-west-1":         "must not contain a password",
	} {
		_, err := Parse(raw)
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: %v, want %q", raw, err, want)
		}
	}
}
