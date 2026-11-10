package cachex

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/redis/go-redis/v9"

	"github.com/sgnd/komando/internal/driver"
	"github.com/sgnd/komando/internal/out"
)

func TestHideSecrets(t *testing.T) {
	const H = out.Hidden
	hash := sha256Hex("alicepw")
	cases := []struct {
		name string
		cmd  string
		in   any
		want any
	}{
		{"CONFIG GET over RESP3", "CONFIG GET *",
			map[string]any{"requirepass": "Zq7pLmN4vR2x", "masterauth": "Kd93hfPq01aB", "primaryauth": "Kd93hfPq01aB", "tls-key-file-pass": "kp",
				"tls-client-key-file-pass": "", "tls-auth-clients": "yes", "tls-auth-clients-user": "off", "maxmemory": "0", "masteruser": "repl"},
			map[string]any{"requirepass": H, "masterauth": H, "primaryauth": H, "tls-key-file-pass": H,
				"tls-client-key-file-pass": "", "tls-auth-clients": "yes", "tls-auth-clients-user": "off", "maxmemory": "0", "masteruser": "repl"}},
		{"CONFIG GET over RESP2", "config get *pass*",
			[]any{"tls-client-key-file-pass", "", "requirepass", "Zq7pLmN4vR2x", "masterauth", map[string]string{"base64": "AP8="}},
			[]any{"tls-client-key-file-pass", "", "requirepass", H, "masterauth", H}},
		{"SENTINEL CONFIG GET", "SENTINEL CONFIG GET *",
			map[string]any{"sentinel-pass": "s3ntinel-pw", "sentinel-user": "sen", "resolve-hostnames": "no"},
			map[string]any{"sentinel-pass": H, "sentinel-user": "sen", "resolve-hostnames": "no"}},
		{"ACL LIST", "ACL LIST",
			[]any{"user alice on sanitize-payload #" + hash + " ~* resetchannels +@all", "user nobody off nopass"},
			[]any{"user alice on sanitize-payload #" + H + " ~* resetchannels +@all", "user nobody off nopass"}},
		{"ACL GETUSER over RESP3", "acl getuser alice",
			map[string]any{"flags": []any{"on"}, "passwords": []any{hash, hash}, "keys": "~*", "selectors": []any{}},
			map[string]any{"flags": []any{"on"}, "passwords": []any{H, H}, "keys": "~*", "selectors": []any{}}},
		{"ACL GETUSER over RESP2", "ACL GETUSER alice",
			[]any{"flags", []any{"on"}, "passwords", []any{hash}, "commands", "+@all"},
			[]any{"flags", []any{"on"}, "passwords", []any{H}, "commands", "+@all"}},
		// a password that is a switch word is still a password
		{"password that reads yes", "CONFIG GET *",
			map[string]any{"requirepass": "yes", "masterauth": "on", "sentinel-pass": "false", "tls-auth-clients": "optional"},
			map[string]any{"requirepass": H, "masterauth": H, "sentinel-pass": H, "tls-auth-clients": "optional"}},
		{"password that reads yes over RESP2", "CONFIG GET *", []any{"primaryauth", "no", "tls-auth-clients", "no"}, []any{"primaryauth", H, "tls-auth-clients", "no"}},
		// everything else is left to the output masking, which goes by key name
		{"a hash", "HGETALL user:1", map[string]any{"requirepass": "x"}, map[string]any{"requirepass": "x"}},
		// over RESP2 HGETALL is a flat list: made a map, as over RESP3
		{"a hash over RESP2", "hgetall user:1", []any{"name", "ana", "password", "x"}, map[string]any{"name": "ana", "password": "x"}},
		{"an odd list", "HGETALL user:1", []any{"name"}, []any{"name"}},
		{"a binary field name", "HGETALL user:1", []any{map[string]string{"base64": "AP8="}, "x"}, []any{map[string]string{"base64": "AP8="}, "x"}},
		{"a value that looks like a hash", "GET digest", hash, hash},
		{"CONFIG SET", "CONFIG SET requirepass x", "OK", "OK"},
		{"no such parameter", "CONFIG GET nope", map[string]any{}, map[string]any{}},
		{"CONFIG alone", "CONFIG", nil, nil},
	}
	for _, c := range cases {
		if got := HideSecrets(strings.Fields(c.cmd), c.in); !reflect.DeepEqual(got, c.want) {
			t.Errorf("%s: %v, want %v", c.name, got, c.want)
		}
	}
}

// runOut is what `cache run` prints, without the cli package.
type runOut struct {
	Reply any `json:"reply"`
}

func (r runOut) Text() string { return ReplyText(r.Reply) }

func printed(format string, data any) string {
	var b strings.Builder
	p := &out.Printer{Format: format, W: &b, Mask: true}
	p.Print("cache.run", data, nil)
	return b.String()
}

// TestAgentSeesNoPasswords: the output masking does not know requirepass
// and masterauth, so HideSecrets hides them from AI agents in every form
// (JSON and text, RESP2 and RESP3).
func TestAgentSeesNoPasswords(t *testing.T) {
	const pw, ma = "Zq7pLmN4vR2x", "Kd93hfPq01aB"
	for _, format := range []string{"json", "text"} {
		for _, reply := range []any{
			map[string]any{"requirepass": pw, "masterauth": ma, "maxmemory": "0"},
			[]any{"requirepass", pw, "masterauth", ma, "maxmemory", "0"},
		} {
			s := printed(format, runOut{HideSecrets([]string{"CONFIG", "GET", "*"}, reply)})
			if strings.Contains(s, pw) || strings.Contains(s, ma) || !strings.Contains(s, out.Hidden) {
				t.Errorf("%s %T:\n%s", format, reply, s)
			}
		}
	}
	// text shows "name: value", which the masking reads: with redis-cli's
	// "name => value" it hid the ">" and showed the password
	if s := printed("text", runOut{map[string]any{"requirepass": out.Hidden, "password": "abc123xyz"}}); s != "1# password: [hidden]\n2# requirepass: [hidden]\n" {
		t.Errorf("text:\n%s", s)
	}
	// HGETALL over RESP2 is a flat list; its password field is hidden too
	for _, format := range []string{"json", "text"} {
		s := printed(format, runOut{HideSecrets([]string{"HGETALL", "user:1"}, []any{"name", "ana", "password", "abc123xyz"})})
		if strings.Contains(s, "abc123xyz") || !strings.Contains(s, out.Hidden) || !strings.Contains(s, "ana") {
			t.Errorf("HGETALL over RESP2, %s:\n%s", format, s)
		}
	}
	v := &Value{Key: "user:1", Type: "hash", Size: 2, Value: map[string]any{"name": "ana", "password": "abc123xyz"}}
	if s := printed("text", v); strings.Contains(s, "abc123xyz") || !strings.Contains(s, "1) name: ana\n  2) password: [hidden]\n") {
		t.Errorf("cache get of a hash:\n%s", s)
	}
}

func TestScriptTimeout(t *testing.T) {
	timeout := func() error { return cmdErr(context.DeadlineExceeded) }
	for cmd, kill := range map[string]string{"eval_ro": "SCRIPT KILL", "EVALSHA": "SCRIPT KILL", "FCALL_RO": "FUNCTION KILL", "TFCALL": "", "RG.PYEXECUTE": ""} {
		var e *out.Error
		if !errors.As(scriptTimeout([]string{cmd, "x", "0"}, timeout()), &e) || e.Code != "TIMEOUT" ||
			!strings.Contains(e.Hint, kill) || !strings.Contains(e.Hint, "BUSY") || strings.Contains(e.Hint, "raise --timeout") {
			t.Errorf("%s: %+v", cmd, e)
		}
		if kill == "" && strings.Contains(e.Hint, "KILL") {
			t.Errorf("%s names a kill command: %s", cmd, e.Hint)
		}
	}
	// other commands keep "raise --timeout"; other script errors their own
	if e := scriptTimeout([]string{"GET", "k"}, timeout()).(*out.Error); e.Hint != "raise --timeout" {
		t.Errorf("GET: %+v", e)
	}
	if e := scriptTimeout([]string{"EVAL", "x", "0"}, cmdErr(errors.New("ERR syntax"))).(*out.Error); e.Code != "CACHE_ERROR" {
		t.Errorf("script error: %+v", e)
	}
	if err := scriptTimeout(nil, timeout()); err == nil {
		t.Error("no command")
	}
}

func sha256Hex(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}

// TestRedisSecretsLive checks the real reply shapes against a Redis server
// (set KOMANDO_E2E_REDIS=host:port, and KOMANDO_E2E_REDIS_PASSWORD when it
// has requirepass). It sets masterauth and adds a user for the time of the
// test, and runs a script for a few seconds.
func TestRedisSecretsLive(t *testing.T) {
	addr := os.Getenv("KOMANDO_E2E_REDIS")
	if addr == "" {
		t.Skip("set KOMANDO_E2E_REDIS=host:port (and KOMANDO_E2E_REDIS_PASSWORD)")
	}
	pw := os.Getenv("KOMANDO_E2E_REDIS_PASSWORD")
	ctx := context.Background()
	admin := redis.NewClient(&redis.Options{Addr: addr, Password: pw, DisableIdentity: true, ReadTimeout: 20 * time.Second})
	defer admin.Close()
	const masterauth, userPass = "MasterAuth-Live-1234", "LivePass-5678"
	old, err := admin.ConfigGet(ctx, "masterauth").Result()
	if err != nil {
		t.Fatal(err)
	}
	if err := admin.ConfigSet(ctx, "masterauth", masterauth).Err(); err != nil {
		t.Fatal(err)
	}
	defer admin.ConfigSet(ctx, "masterauth", old["masterauth"])
	if err := admin.Do(ctx, "ACL", "SETUSER", "komando-live", "on", ">"+userPass, "~*", "+@all").Err(); err != nil {
		t.Fatal(err)
	}
	defer admin.Do(ctx, "ACL", "DELUSER", "komando-live")
	leaks := []string{masterauth, sha256Hex(userPass)}
	if pw != "" {
		leaks = append(leaks, pw)
	}
	for _, proto := range []int{2, 3} {
		c := redis.NewClient(&redis.Options{Addr: addr, Password: pw, Protocol: proto, DisableIdentity: true})
		for _, cmd := range [][]string{{"CONFIG", "GET", "*"}, {"config", "get", "masterauth"}, {"ACL", "LIST"}, {"ACL", "GETUSER", "komando-live"}} {
			v, err := Run(ctx, c, cmd)
			if err != nil {
				t.Fatalf("%v: %v", cmd, err)
			}
			b, _ := json.Marshal(HideSecrets(cmd, v))
			for _, l := range leaks {
				if strings.Contains(string(b), l) {
					t.Errorf("RESP%d %v shows %q: %s", proto, cmd, l, b)
				}
			}
			if !strings.Contains(string(b), out.Hidden) {
				t.Errorf("RESP%d %v: nothing hidden: %s", proto, cmd, b)
			}
		}
		c.Close()
	}

	// komando stops waiting for a long script, which goes on running: the
	// hint says so instead of "raise --timeout"
	tg, err := driver.Parse("redis://" + addr + "/0")
	if err != nil {
		t.Fatal(err)
	}
	c, err := Open(ctx, tg, pw, nil, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_, err = Run(ctx, c, []string{"EVAL_RO", "for i = 1, 2e9 do end return 1", "0"}) // ends by itself in seconds
	var e *out.Error
	if !errors.As(err, &e) || e.Code != "TIMEOUT" || !strings.Contains(e.Hint, "SCRIPT KILL") {
		t.Errorf("long script: %v", err)
	}
	// Redis takes SCRIPT KILL once the script ran past busy-reply-threshold
	if err := admin.ScriptKill(ctx).Err(); err != nil && !strings.HasPrefix(err.Error(), "NOTBUSY") {
		t.Errorf("SCRIPT KILL: %v", err)
	}
}
