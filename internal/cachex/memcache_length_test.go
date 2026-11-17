package cachex

import (
	"bufio"
	"context"
	"net"
	"strings"
	"testing"
	"time"
)

// scripted is a memcache client whose server answers every command line
// with the next reply.
func scripted(t *testing.T, meta bool, replies ...string) *memcache {
	t.Helper()
	cli, srv := net.Pipe()
	t.Cleanup(func() { cli.Close(); srv.Close() })
	go func() {
		r := bufio.NewReader(srv)
		for _, rep := range replies {
			if _, err := r.ReadString('\n'); err != nil {
				return
			}
			if _, err := srv.Write([]byte(rep)); err != nil {
				return
			}
		}
	}()
	return &memcache{c: cli, r: bufio.NewReader(cli), tmo: 2 * time.Second, meta: meta}
}

// A server chooses the length it announces: a negative, absurd or
// non-numeric one is an error, never a crash or a huge allocation.
func TestMemcacheBadLength(t *testing.T) {
	ctx := context.Background()
	for _, n := range []string{"-1", "-3", "99999999999", "4611686018427387904", "x"} {
		for name, call := range map[string]func() error{
			"meta get": func() error {
				_, err := scripted(t, true, "VA "+n+" s5\r\nhello\r\n").Get(ctx, "k", 0, 0)
				return err
			},
			"classic get": func() error {
				_, err := scripted(t, false, "VALUE k 0 "+n+"\r\nhello\r\nEND\r\n").Get(ctx, "k", 0, 0)
				return err
			},
			"run get": func() error {
				_, err := scripted(t, false, "VALUE k 0 "+n+"\r\nhello\r\nEND\r\n").Run(ctx, []string{"get", "k"})
				return err
			},
			"run mg": func() error {
				_, err := scripted(t, true, "VA "+n+" s5\r\nhello\r\n").Run(ctx, []string{"mg", "k", "v"})
				return err
			},
		} {
			func() {
				defer func() {
					if r := recover(); r != nil {
						t.Errorf("%s with length %s: panic: %v", name, n, r)
					}
				}()
				if err := call(); err == nil || !strings.Contains(err.Error(), "length") {
					t.Errorf("%s with length %s: want a length error, got %v", name, n, err)
				}
			}()
		}
	}
}

// A length the server announces but never sends does not reserve memory
// up front: the read ends with the connection.
func TestMemcacheShortBlock(t *testing.T) {
	m := scripted(t, true, "VA 1000000000 s5\r\nhello\r\n")
	go func() { time.Sleep(200 * time.Millisecond); m.c.Close() }()
	if _, err := m.Get(context.Background(), "k", 0, 0); err == nil {
		t.Error("want an error for a value cut short")
	}
}

func TestMemcacheGoodLength(t *testing.T) {
	v, err := scripted(t, true, "VA 5 s5\r\nhello\r\n").Get(context.Background(), "k", 0, 0)
	if err != nil || v.Value != "hello" {
		t.Errorf("get: %+v %v", v, err)
	}
}

// A server that never ends its line does not fill memory.
func TestMemcacheEndlessLine(t *testing.T) {
	m := scripted(t, true, strings.Repeat("A", 200<<10))
	m.r = bufio.NewReaderSize(m.c, 64<<10)
	if _, err := m.Get(context.Background(), "k", 0, 0); err == nil || !strings.Contains(err.Error(), "line of more than") {
		t.Errorf("want a line length error, got %v", err)
	}
}
