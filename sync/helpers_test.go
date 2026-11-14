package komandosync

import (
	"errors"
	"strings"
	"sync"
	"testing"
	"time"
)

type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *fakeClock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *fakeClock) add(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

// world is one account's devices around one (possibly hostile) server.
type world struct {
	t   testing.TB
	srv *Hostile
	clk *fakeClock
}

func newWorld(t testing.TB) *world {
	return &world{t: t, srv: NewHostile(), clk: &fakeClock{t: time.Date(2026, 11, 14, 9, 0, 0, 0, time.UTC)}}
}

func must(t testing.TB, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

func (w *world) device(name string, auth bool) *Device {
	w.t.Helper()
	k, err := NewSoftDeviceKeys(auth)
	must(w.t, err)
	return NewDevice(name, k, w.srv, w.clk.now)
}

// typeBack answers the kit's challenge as a person reading the paper.
func typeBack(k *Kit) [2]string {
	g := strings.Fields(k.Letters())
	c := k.Challenge()
	return [2]string{strings.ToLower(g[c[0]]), g[c[1]]}
}

// account makes an account on a new device with Face ID and confirms the
// kit.
func (w *world) account(name string) (*Device, *Kit) {
	w.t.Helper()
	d := w.device(name, true)
	kit, err := d.CreateAccount()
	must(w.t, err)
	must(w.t, d.ConfirmKit(typeBack(kit)))
	_, err = d.Sync()
	must(w.t, err)
	return d, kit
}

// pair lets a new device in through by, the whole SS 6.3 flow.
func (w *world) pair(by *Device, name string, auth bool) *Device {
	w.t.Helper()
	nd := w.device(name, auth)
	j, code, err := StartJoin(nd)
	must(w.t, err)
	must(w.t, by.AcceptJoin(code, func(n string) bool { return n == name }))
	d, err := j.Finish()
	must(w.t, err)
	_, err = d.Sync()
	must(w.t, err)
	return d
}

func (w *world) syncAll(devs ...*Device) {
	w.t.Helper()
	for range 2 {
		for _, d := range devs {
			_, err := d.Sync()
			must(w.t, err)
		}
	}
}

func wantErr(t testing.TB, err, want error) {
	t.Helper()
	if !errors.Is(err, want) {
		t.Fatalf("got error %v, want %v", err, want)
	}
}

func field(name, value string) Field { return Field{Name: name, Value: value} }

func value(t testing.TB, d *Device, id RecordID, name string) string {
	t.Helper()
	f, ok := d.Get(id)
	if !ok {
		return "<none>"
	}
	return f[name]
}

func mustSigner(t testing.TB) *SoftSigner {
	t.Helper()
	s, err := NewSoftSigner()
	must(t, err)
	return s
}
