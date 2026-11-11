package cli

import (
	"encoding/json"
	"io"
	"net"
	"strconv"
	"testing"
	"time"

	"github.com/sgnd/komando/internal/sshx"
	"github.com/sgnd/komando/internal/store"
)

type waitEnv struct {
	Data struct {
		Results []struct {
			Name  string `json:"host"`
			OK    bool   `json:"ok"`
			Error *struct {
				Code string `json:"code"`
			} `json:"error"`
		} `json:"results"`
		WaitedMS int64 `json:"waited_ms"`
	} `json:"data"`
}

func runWait(t *testing.T, args ...string) (waitEnv, time.Duration, error) {
	t.Helper()
	var err error
	t0 := time.Now()
	got := captureOutput(t, func() error { err = runRoot(t, args...); return err })
	var env waitEnv
	if e := json.Unmarshal([]byte(got), &env); e != nil {
		t.Fatalf("%v\n%s", e, got)
	}
	return env, time.Since(t0), err
}

// closedPort is a TCP port nothing listens on (yet).
func closedPort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	p := ln.Addr().(*net.TCPAddr).Port
	ln.Close()
	return p
}

// forwardLater starts, after a delay, a forwarder from port to the fake
// server: a new server whose SSH comes up while komando waits.
func forwardLater(t *testing.T, port, to int, after time.Duration) {
	t.Helper()
	go func() {
		time.Sleep(after)
		ln, err := net.Listen("tcp", "127.0.0.1:"+strconv.Itoa(port))
		if err != nil {
			t.Error(err)
			return
		}
		t.Cleanup(func() { ln.Close() })
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				d, err := net.Dial("tcp", "127.0.0.1:"+strconv.Itoa(to))
				if err != nil {
					c.Close()
					return
				}
				go func() { _, _ = io.Copy(d, c); d.Close() }()
				_, _ = io.Copy(c, d)
				c.Close()
			}()
		}
	}()
}

func addLateHost(t *testing.T, name string, port int) {
	t.Helper()
	if err := store.Update(func(st *store.State) error {
		h := *st.Hosts["dev"]
		h.Name, h.Address, h.Port = name, "127.0.0.1", port
		st.Hosts[name] = &h
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

// test --wait tests again until a server that was not up yet answers.
func TestTestWaitsForANewServer(t *testing.T) {
	srv := startFakeServer(t)
	srv.reply("deploy\nnew1\nsudo-ok\n")
	saved := waitInterval
	waitInterval = 100 * time.Millisecond
	t.Cleanup(func() { waitInterval = saved })
	port := closedPort(t)
	addLateHost(t, "new1", port)
	forwardLater(t, port, srv.port, time.Second)

	env, took, err := runWait(t, "test", "new1", "--wait", "30s")
	if err != nil || len(env.Data.Results) != 1 || !env.Data.Results[0].OK {
		t.Fatalf("err %v, results %+v", err, env.Data.Results)
	}
	if env.Data.WaitedMS < 900 || took > 15*time.Second {
		t.Errorf("waited %dms, took %s", env.Data.WaitedMS, took)
	}
}

// It never waits out a changed host key (it may be an attack): it fails at
// once, even with time left.
func TestTestWaitStopsAtHostKeyMismatch(t *testing.T) {
	srv := startFakeServer(t)
	_ = srv
	if _, err := sshx.PinHostKey(net.JoinHostPort("localhost", strconv.Itoa(srv.port)), trustSigner(t).PublicKey(), true); err != nil {
		t.Fatal(err)
	}
	env, took, err := runWait(t, "test", "dev", "--wait", "30s")
	if err == nil || env.Data.Results[0].Error == nil || env.Data.Results[0].Error.Code != "HOSTKEY_MISMATCH" {
		t.Fatalf("err %v, results %+v", err, env.Data.Results)
	}
	if took > 10*time.Second {
		t.Errorf("waited %s for a changed key", took)
	}
}

// A server that never comes up fails when the time is up, not before.
func TestTestWaitGivesUp(t *testing.T) {
	startFakeServer(t)
	saved := waitInterval
	waitInterval = 100 * time.Millisecond
	t.Cleanup(func() { waitInterval = saved })
	addLateHost(t, "never", closedPort(t))
	env, _, err := runWait(t, "test", "never", "--wait", "1s")
	if err == nil || env.Data.Results[0].OK || env.Data.WaitedMS < 1000 || env.Data.Results[0].Error.Code != "CONNECTION_REFUSED" {
		t.Fatalf("err %v, waited %dms, results %+v", err, env.Data.WaitedMS, env.Data.Results)
	}
}
