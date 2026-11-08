package driver

import "testing"

func TestMongoURLs(t *testing.T) {
	for raw, want := range map[string][3]string{
		"mongodb://app@db1.internal:27017,db2.internal/shop?replicaSet=rs0": {"db1.internal:27017", "app", "shop"},
		"mongodb://db.internal":                                      {"db.internal:27017", "", ""},
		"mongodb+srv://app@cluster0.abcde.mongodb.net/shop":          {"cluster0.abcde.mongodb.net:27017", "app", "shop"},
		"mongodb://app@db.internal/shop?tls=true&ca=secret:mongo-ca": {"db.internal:27017", "app", "shop"},
	} {
		tg, err := Parse(raw)
		if err != nil || tg.Address != want[0] || tg.User != want[1] || tg.Database != want[2] || tg.Kind.Family != "db" {
			t.Errorf("%s: %+v %v", raw, tg, err)
		}
	}
	if tg, _ := Parse("mongodb+srv://app@c0.example.net/x"); !tg.Secure {
		t.Error("mongodb+srv uses TLS")
	}
	for _, bad := range []string{
		"mongodb://app:pw@db/shop",                 // a password in the URL
		"mongodb+srv://app@c0.example.net:27017/x", // srv takes no port
		"mongodb://db/x?ca=secret:ca",              // ca= without TLS
		"mongodb://db/x?tls=true&tlsInsecure=true&ca=secret:ca",
		"mongodb://db:99999/x",
	} {
		if _, err := Parse(bad); err == nil {
			t.Errorf("%s: want an error", bad)
		}
	}
}
