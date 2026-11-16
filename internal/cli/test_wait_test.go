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

// lateServer listens on a new port as a server that is still starting: it
// hangs up on the first connection (its SSH is not up yet), and passes every
// later one on to the fake server. The first test of it fails and the next
// passes, however busy this machine is.
func lateServer(t *testing.T, to int) (port int) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for first := true; ; first = false {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			if first {
				c.Close()
				continue
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
	return ln.Addr().(*net.TCPAddr).Port
}

func addLateHost(t *testing.T, name string, port int) {
	t.Helper()
	if err := store.Update(store.Save(), func(st *store.State) error {
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
	addLateHost(t, "new1", lateServer(t, srv.port))

	// the time given is far more than a busy machine needs: the test ends
	// when the server answers, not when the time is up
	env, _, err := runWait(t, "test", "new1", "--wait", "10m")
	if err != nil || len(env.Data.Results) != 1 || !env.Data.Results[0].OK {
		t.Fatalf("err %v, results %+v", err, env.Data.Results)
	}
	// it passed in a later round, after one pause between rounds
	if env.Data.WaitedMS < waitInterval.Milliseconds() {
		t.Errorf("waited %dms, less than one pause between rounds (%s)", env.Data.WaitedMS, waitInterval)
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
	// given an hour, it answers long before: this test would otherwise
	// run into the time limit of the whole test run
	env, took, err := runWait(t, "test", "dev", "--wait", "1h")
	if err == nil || env.Data.Results[0].Error == nil || env.Data.Results[0].Error.Code != "HOSTKEY_MISMATCH" {
		t.Fatalf("err %v, results %+v", err, env.Data.Results)
	}
	if took > 30*time.Minute {
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
