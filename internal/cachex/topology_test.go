package cachex

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/sgnd/komando/internal/driver"
)

func TestRedisTopologyURLs(t *testing.T) {
	tg, err := driver.Parse("rediss://default@clustercfg.cache.internal:6379?cluster=1")
	if err != nil || !tg.Cluster || tg.Sentinel != "" || !tg.Secure {
		t.Errorf("cluster: %+v %v", tg, err)
	}
	tg, err = driver.Parse("redis://default@sentinel1:26379/2?sentinel=mymaster&sentinels=sentinel2,sentinel3:26380&sentinel_auth=same")
	if err != nil || tg.Sentinel != "mymaster" || tg.Database != "2" || !tg.SentinelAuth ||
		strings.Join(tg.Sentinels, ",") != "sentinel2:26379,sentinel3:26380" {
		t.Errorf("sentinel: %+v %v", tg, err)
	}
	if tg, _ := driver.Parse("redis://sentinel1?sentinel=mymaster"); tg.Address != "sentinel1:26379" {
		t.Errorf("a Sentinel's own port: %s", tg.Address)
	}
	for _, bad := range []string{
		"redis://n1:6379/3?cluster=1", // a cluster has only db 0
		"redis://n1:6379?cluster=1&sentinel=m",
		"redis://n1:6379?cluster=yes",
		"redis://n1:6379?sentinels=s2",
		"redis://s1?sentinel=m&sentinel_auth=other",
	} {
		if _, err := driver.Parse(bad); err == nil {
			t.Errorf("%s: want an error", bad)
		}
	}
}

// rediss:// through --via: go-redis adds no TLS to a dialer it is given,
// so komando's dialer does, checking each address's own name.
func TestRedisDialerAddsTLS(t *testing.T) {
	caPEM, cert := privateCA(t)
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{cert}})
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			c.(*tls.Conn).Handshake()
			c.Close()
		}
	}()
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM([]byte(caPEM))
	var dialed string
	via := func(ctx context.Context, network, addr string) (net.Conn, error) {
		dialed = addr
		return (&net.Dialer{}).DialContext(ctx, network, ln.Addr().String())
	}
	d := redisDialer(via, &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}, 5*time.Second)
	c, err := d(context.Background(), "tcp", "127.0.0.1:6380")
	if err != nil {
		t.Fatalf("TLS through the --via dialer: %v", err)
	}
	if _, ok := c.(*tls.Conn); !ok || dialed != "127.0.0.1:6380" {
		t.Errorf("conn %T, dialed %q", c, dialed)
	}
	c.Close()
	if _, err := redisDialer(via, &tls.Config{MinVersion: tls.VersionTLS12}, 5*time.Second)(context.Background(), "tcp", "127.0.0.1:6380"); err == nil {
		t.Error("a certificate from an unknown CA must be refused")
	}
}

// The live tests run against a Redis Cluster of two masters (password
// clusterpw) and a master behind a Sentinel (sentpw), all in one container
// so every node can announce 127.0.0.1:
//
//	docker run -d --name redis-topo -p 127.0.0.1:7001-7003:7001-7003 -p 127.0.0.1:26379:26379 redis:8.10.3 sh -c '
//	  cd /tmp; for p in 7001 7002; do redis-server --port $p --cluster-enabled yes --cluster-config-file n$p.conf \
//	    --cluster-announce-ip 127.0.0.1 --requirepass clusterpw --masterauth clusterpw --daemonize yes --save ""; done
//	  redis-server --port 7003 --requirepass sentpw --daemonize yes --save ""; sleep 1
//	  redis-cli -p 7001 -a clusterpw cluster addslotsrange 0 8191; redis-cli -p 7002 -a clusterpw cluster addslotsrange 8192 16383
//	  redis-cli -p 7001 -a clusterpw cluster meet 127.0.0.1 7002
//	  printf "port 26379\nsentinel monitor mymaster 127.0.0.1 7003 1\nsentinel auth-pass mymaster sentpw\n" > s.conf
//	  exec redis-server s.conf --sentinel'
//	KOMANDO_TEST_REDIS_CLUSTER=127.0.0.1:7001 KOMANDO_TEST_REDIS_SENTINEL=127.0.0.1:26379 go test ./internal/cachex -run Live
func TestRedisClusterLive(t *testing.T) {
	addr := os.Getenv("KOMANDO_TEST_REDIS_CLUSTER")
	if addr == "" {
		t.Skip("KOMANDO_TEST_REDIS_CLUSTER is not set")
	}
	tg, err := driver.Parse("redis://default@" + addr + "?cluster=1")
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	s, err := OpenStore(ctx, tg, "clusterpw", nil, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	var keys []string
	for i := range 30 { // spread over both masters' slots
		k := fmt.Sprintf("t-komando:%d", i)
		keys = append(keys, k)
		if err := s.Set(ctx, k, "v", time.Minute); err != nil {
			t.Fatalf("set %s: %v", k, err)
		}
	}
	defer s.Del(ctx, keys...)
	got, more, err := s.Keys(ctx, "t-komando:*", 100)
	if err != nil || more || len(got) != 30 {
		t.Errorf("keys over every master: %d %v %v", len(got), more, err)
	}
	for _, k := range got { // TYPE and PTTL reach each key's own master
		if k.Type == nil || *k.Type != "string" || k.TTL == nil || *k.TTL < 1 || *k.TTL > 60 {
			t.Errorf("type and ttl over every master: %s", keyLine(k))
		}
	}
	if got, more, _ := s.Keys(ctx, "t-komando:*", 10); len(got) != 10 || !more {
		t.Errorf("limit: %d %v", len(got), more)
	}
	if v, err := s.Get(ctx, "t-komando:7", 10, 1024); err != nil || fmt.Sprint(v.Value) != "v" {
		t.Errorf("get: %+v %v", v, err)
	}
	info, err := s.Info(ctx, "")
	if err != nil {
		t.Fatal(err)
	}
	if info["cluster"]["masters"] != "2" || info["cluster"]["cluster_state"] != "ok" || Summarize(info).Keys["db0"] < 30 {
		t.Errorf("info: cluster %v, keys %v", info["cluster"], Summarize(info).Keys)
	}
	if n, err := s.Del(ctx, "t-komando:1"); err != nil || n != 1 {
		t.Errorf("del: %d %v", n, err)
	}
	// keys without a slot: DBSIZE must count every master, not one at random
	if n, err := s.Run(ctx, []string{"DBSIZE"}); err != nil || fmt.Sprint(n) != fmt.Sprint(Summarize(info).Keys["db0"]-1) {
		t.Errorf("DBSIZE over the cluster: %v %v, want %d", n, err, Summarize(info).Keys["db0"]-1)
	}
	if _, err := s.Run(ctx, []string{"SCAN", "0"}); err == nil || !strings.Contains(err.Error(), "one master") {
		t.Errorf("SCAN in a cluster must be refused: %v", err)
	}
	// cache rm with keys in different slots (no CROSSSLOT)
	if n, err := s.Del(ctx, keys[2:]...); err != nil || n != int64(len(keys)-2) {
		t.Errorf("del over several slots: %d %v", n, err)
	}
}

func TestRedisSentinelLive(t *testing.T) {
	addr := os.Getenv("KOMANDO_TEST_REDIS_SENTINEL")
	if addr == "" {
		t.Skip("KOMANDO_TEST_REDIS_SENTINEL is not set")
	}
	tg, err := driver.Parse("redis://" + addr + "/0?sentinel=mymaster")
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	s, err := OpenStore(ctx, tg, "sentpw", nil, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if err := s.Set(ctx, "t-komando:s", "via-sentinel", time.Minute); err != nil {
		t.Fatal(err)
	}
	defer s.Del(ctx, "t-komando:s")
	if v, err := s.Get(ctx, "t-komando:s", 10, 1024); err != nil || fmt.Sprint(v.Value) != "via-sentinel" {
		t.Errorf("get: %+v %v", v, err)
	}
	if got, _, err := s.Keys(ctx, "t-komando:s", 10); err != nil || len(got) != 1 || got[0].Type == nil || *got[0].Type != "string" ||
		got[0].TTL == nil || *got[0].TTL < 1 || *got[0].TTL > 60 {
		t.Errorf("keys through the Sentinels: %v %v", got, err)
	}
	info, err := s.Info(ctx, "replication")
	if err != nil || info["replication"]["role"] != "master" {
		t.Errorf("the Sentinels lead to the master: %v %v", info["replication"], err)
	}
	wrong, _ := driver.Parse("redis://" + addr + "/0?sentinel=nosuchmaster")
	if _, err := OpenStore(ctx, wrong, "sentpw", nil, 3*time.Second); err == nil {
		t.Error("an unknown master name must fail")
	}
}
