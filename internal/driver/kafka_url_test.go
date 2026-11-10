package driver

import (
	"slices"
	"strings"
	"testing"
)

func TestParseKafka(t *testing.T) {
	ResolveSecret = nil
	cases := []struct {
		raw     string
		brokers []string
		user    string
		sasl    string
		secure  bool
		tls     string
		ca      string
	}{
		{raw: "kafka://broker1.internal", brokers: []string{"broker1.internal:9092"}},
		{raw: "kafka://b1:9093,b2,b3:9094", brokers: []string{"b1:9093", "b2:9092", "b3:9094"}},
		{raw: "kafka://app@b1.example.com:9093,b2.example.com:9093?tls=true&sasl=scram-sha-512",
			brokers: []string{"b1.example.com:9093", "b2.example.com:9093"}, user: "app", sasl: "scram-sha-512", secure: true},
		{raw: "kafka://app@k.internal:9093?tls=true&ca=secret:kafka-ca&sasl=PLAIN",
			brokers: []string{"k.internal:9093"}, user: "app", sasl: "plain", secure: true, ca: "secret:kafka-ca"},
		{raw: "kafka://k.internal?tls=skip-verify", brokers: []string{"k.internal:9092"}, secure: true, tls: "skip-verify"},
		{raw: "kafka://[2001:db8::1]:9092,10.0.0.2", brokers: []string{"[2001:db8::1]:9092", "10.0.0.2:9092"}},
		{raw: "kafka://k.example.com:9092?insecure=1", brokers: []string{"k.example.com:9092"}},
	}
	for _, c := range cases {
		tg, err := Parse(c.raw)
		if err != nil {
			t.Errorf("%s: %v", c.raw, err)
			continue
		}
		if tg.Kind.Family != "queue" || tg.Kind.Name != "kafka" {
			t.Errorf("%s: kind %+v", c.raw, tg.Kind)
		}
		if !slices.Equal(tg.Brokers, c.brokers) || tg.Address != c.brokers[0] {
			t.Errorf("%s: brokers %v address %s, want %v", c.raw, tg.Brokers, tg.Address, c.brokers)
		}
		if tg.User != c.user || tg.SASL != c.sasl || tg.Secure != c.secure || tg.TLS != c.tls || tg.CA != c.ca {
			t.Errorf("%s: got user=%q sasl=%q secure=%v tls=%q ca=%q", c.raw, tg.User, tg.SASL, tg.Secure, tg.TLS, tg.CA)
		}
	}
}

func TestParseKafkaRefuses(t *testing.T) {
	for raw, want := range map[string]string{
		"kafka://app:secret@b1:9092?sasl=plain":       "password",
		"kafka://b1:9092/topic":                       "brokers only",
		"kafka://b1:9092?sasl=plain":                  "logs in as a user",
		"kafka://app@b1:9092":                         "no sasl=",
		"kafka://app@b1:9092?sasl=gssapi":             "sasl option",
		"kafka://b1:9092?tls=maybe":                   "tls option",
		"kafka://b1:9092?ca=secret:x":                 "add tls=true",
		"kafka://b1:9092?tls=skip-verify&ca=secret:x": "do not go together",
		"kafka://b1:9092?ca=plain":                    "secret:NAME",
		"kafka://b1:99999":                            "invalid port",
		"kafka://b1:9092?group=x":                     "unknown kafka URL option",
		"kafka://":                                    "needs a broker",
	} {
		_, err := Parse(raw)
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: got %v, want an error with %q", raw, err, want)
		}
	}
}

func TestSplitHostList(t *testing.T) {
	for raw, want := range map[string]string{
		"kafka://a@h1:1,h2:2/?x=1": "kafka://a@h1:1/?x=1",
		"KAFKA://h1,h2":            "KAFKA://h1",
		"redis://h1:6379/0":        "redis://h1:6379/0",
	} {
		if got, _ := splitHostList(raw); got != want {
			t.Errorf("%s: got %s, want %s", raw, got, want)
		}
	}
}

func TestKafkaDescribe(t *testing.T) {
	tg, err := Parse("kafka://app@b1:9092,b2:9092?sasl=plain")
	if err != nil {
		t.Fatal(err)
	}
	if got := tg.Describe(); got != "kafka app@b1:9092 (+1 broker)" {
		t.Errorf("Describe = %q", got)
	}
	if err := tg.Need("queue"); err != nil {
		t.Error(err)
	}
	if err := tg.Need("cache"); err == nil || !strings.Contains(err.Error(), "komando cache") {
		t.Errorf("Need(cache) = %v", err)
	}
}
