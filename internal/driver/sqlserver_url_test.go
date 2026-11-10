package driver

import (
	"testing"

	"github.com/sgnd/komando/internal/out"
)

func TestParseSQLServer(t *testing.T) {
	cases := []struct {
		in, where, user, db, tls string
		secure                   bool
	}{
		{"sqlserver://app@db.internal/sales", "db.internal:1433", "app", "sales", "", false},
		{"sqlserver://app@db.internal:14330/sales?encrypt=true", "db.internal:14330", "app", "sales", "", true},
		{"mssql://app@10.0.0.9?database=sales&Encrypt=Strict", "10.0.0.9:1433", "app", "sales", "", true},
		{"sqlserver://app@db/sales?encrypt=true&tls=skip-verify", "db:1433", "app", "sales", "skip-verify", true},
		{"sqlserver://app@db/sales?encrypt=true&ca=secret:corp-ca", "db:1433", "app", "sales", "", true},
		{"sqlserver://app@db?ApplicationIntent=ReadOnly&encrypt=disable", "db:1433", "app", "", "", false},
	}
	for _, c := range cases {
		tg, err := Parse(c.in)
		if err != nil {
			t.Errorf("%s: %v", c.in, err)
			continue
		}
		if tg.Kind.Name != "sqlserver" || tg.Address != c.where || tg.User != c.user || tg.Database != c.db || tg.TLS != c.tls || tg.Secure != c.secure {
			t.Errorf("%s: got %+v", c.in, tg)
		}
	}
	for in, code := range map[string]string{
		"sqlserver://app:pw@db/sales":                                       "URL_HAS_PASSWORD",
		"sqlserver://app@db/sales?Password=x":                               "URL_HAS_PASSWORD",
		"sqlserver://db/sales":                                              "USAGE",
		"sqlserver://app@/sales":                                            "USAGE",
		"sqlserver://app@db/SQLEXPRESS/sales":                               "USAGE",
		"sqlserver://app@db/sales?database=other":                           "USAGE",
		"sqlserver://app@db/sales?encrypt=maybe":                            "USAGE",
		"sqlserver://app@db/sales?tls=false":                                "USAGE",
		"sqlserver://app@db/sales?TrustServerCertificate=true":              "USAGE",
		"sqlserver://app@db/sales?encrypt=disable&tls=skip-verify":          "USAGE",
		"sqlserver://app@db/sales?encrypt=strict&tls=skip-verify":           "USAGE",
		"sqlserver://app@db/sales?ca=secret:x":                              "USAGE",
		"sqlserver://app@db/sales?encrypt=true&CA=secret:x":                 "USAGE",
		"sqlserver://app@db/sales?encrypt=true&ca=x":                        "USAGE",
		"sqlserver://app@db/sales?encrypt=true&tls=skip-verify&ca=secret:x": "USAGE",
		"sqlserver://app@db/sales?applicationintent=fast":                   "USAGE",
		"sqlserver://app@db/sales?packet+size=4096":                         "USAGE",
		"sqlserver://app@db:0/sales":                                        "USAGE",
		"sqlserver://app@db/sales?encrypt=true&Encrypt=disable":             "USAGE",
		"sqlserver://app@db/sales?encrypt=true&encrypt=disable":             "USAGE",
		"sqlserver://app@db?database=a&DATABASE=b":                          "USAGE",
	} {
		_, err := Parse(in)
		if e, ok := err.(*out.Error); !ok || e.Code != code {
			t.Errorf("%s: want %s, got %v", in, code, err)
		}
	}
}
