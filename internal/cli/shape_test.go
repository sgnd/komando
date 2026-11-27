package cli

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/sgnd/komando/internal/out"
	"github.com/sgnd/komando/internal/store"
	"github.com/sgnd/komando/internal/storex"
)

var updateShapes = flag.Bool("update-shapes", false, "rewrite testdata/shapes.json from what the commands print now")

// shapeCases run without any server: they read and change komando's own
// inventory in a throwaway KOMANDO_HOME. Each one's JSON answer is
// reduced to its shape (field names and types, not values).
var shapeCases = [][]string{
	{"version"},
	{"config", "show"},
	{"config", "get", "parallel"},
	{"conn", "kinds"},
	{"policy", "list"},
	{"policy", "check", "rm -rf /"},
	{"policy", "check", "uptime"},
	{"snippet", "list"},
	{"list"},
	{"host", "ssh", "list"},
	{"host", "ssh", "show", "web"},
	{"host", "ssh", "show", "nope"},
	{"host", "ssh-command", "web"},
	{"export"},
	{"export", "--sealed", "--to", "never-written.kmdseal", "--dry-run"},
	{"conn", "list"},
	{"conn", "show", "pg"},
	{"group", "list"},
	{"credential", "list"},
	{"credential", "password", "show", "pg-pass"},
	// secret set --new: a taken name is SECRET_EXISTS, a free one a dry run
	{"credential", "password", "add", "pg-pass", "--new", "--from-env", "PG_PASS"},
	{"credential", "password", "add", "pg-new", "--new", "--from-env", "PG_PASS", "--dry-run"},
	{"schema", "credential", "password", "add"},
	{"credential", "key", "list"},
	{"host", "ssh", "tunnel", "list"},
	{"vpn", "wireguard", "list"},
	{"job", "list"},
	{"status"},
	{"audit", "list", "--limit", "5"},
	{"host", "ssh", "edit", "web", "--port", "2222", "--dry-run"},
	{"host", "ssh", "exec", "web", "--dry-run", "--", "uptime"},
	{"host", "ssh", "exec", "web", "--", "rm", "-rf", "/"},
	// cp between two remote places: the plan names both sides
	{"copy", "web:/etc/hosts", "web:/tmp/hosts", "--dry-run"},
	// streams: a dry run reads nothing and answers on stdout
	{"copy", "web:/etc/hosts", "-", "--dry-run"},
	{"copy", "-", "web:/tmp/motd", "--size", "12", "--dry-run"},
	// a dry run names what it would remove would_remove, never removed;
	// vpn rm lists the VPNs it removed; host trust answers with results
	// for one server or many
	{"host", "ssh", "remove", "web", "--dry-run"},
	{"conn", "rm", "pg", "--dry-run"},
	{"host", "ssh", "trust", "web", "--dry-run"},
	{"host", "ssh", "trust", "web", "--fingerprint", "SHA256:pVt2Cc0dD2Q8dVqf7aNzK7TQzWm0yXcQe3uUe0t1abc", "--dry-run"},
	{"vpn", "socks", "add", "lab", "--proxy-address", "127.0.0.1:1080"},
	{"vpn", "socks", "remove", "lab", "--dry-run"},
	{"vpn", "socks", "remove", "lab"},
	// the options an app builds a VPN add form from
	{"schema", "vpn", "socks", "add"},
	{"schema", "conn", "add"},
	// what an app checks its key with (typed here: not through a key)
	{"ssh-gate", "status"},
}

// serverShapeCases read the fake memcached conn "mc".
var serverShapeCases = [][]string{
	{"cache", "keys", "mc"},
}

// clusterShapeCases run against a loopback Kubernetes API
// (newDetailCluster), imported as conn prod after the cases above, so
// those see the same inventory as before.
var clusterShapeCases = [][]string{
	{"cluster", "describe", "prod", "pod/api-1"},
	{"cluster", "describe", "prod", "deployment/api"},
	{"cluster", "describe", "prod", "secret/app-db"},
	{"cluster", "logs", "prod", "api-1"},
	{"cluster", "logs", "prod", "-l", "app=api"},
}

// storageShapeCases run last, against an S3 conn "bk" whose bucket is in
// memory (memBucket).
var storageShapeCases = [][]string{
	{"storage", "s3", "object", "create", "bk", "reports/2026", "--dry-run"},
	{"storage", "s3", "object", "create", "bk", "reports/2026"},
	{"storage", "s3", "object", "move", "bk", "a.txt", "archive/", "--dry-run"},
	{"storage", "s3", "object", "move", "bk", "a.txt", "archive/"},
	{"storage", "s3", "object", "move", "bk", "archive/a.txt", "--mode", "0640"},
}

// TestOutputShapes: agents parse komando's JSON, so a field may be added
// but never renamed, removed or given another type within one output
// contract (out.Contract). This test keeps the shape of the answers above
// in testdata/shapes.json and fails on any difference. A removal or a
// type change is a breaking change; an addition only needs
//
//	go test ./internal/cli -run TestOutputShapes -update-shapes
func TestOutputShapes(t *testing.T) {
	setHome(t, t.TempDir())
	t.Setenv("KOMANDO_VAULT_PASS", "test")
	t.Setenv("PG_PASS", "s3cret")
	defer func() { setGate(tcl, false, gateDryRun) }()
	for _, setup := range [][]string{
		{"host", "ssh", "add", "web", "deploy@web.lan", "--group", "lab", "--tag", "prod"},
		{"credential", "password", "add", "pg-pass", "--from-env", "PG_PASS"},
		{"conn", "add", "pg", "postgres://app@db.lan:5432/app", "--password-ref", "credential:pg-pass"},
		{"snippet", "create", "hello", "echo {{who=world}}"},
	} {
		if s, err := runCache(t, append([]string{"-o", "json"}, setup...)...); err != nil {
			t.Fatalf("setup %v: %v\n%s", setup, err, s)
		}
	}
	// serverShapeCases then clusterShapeCases run last, against a fake
	// memcached and a loopback Kubernetes API, so the conns they need are
	// not in the inventory answers above
	cases := append(append(append(append([][]string{}, shapeCases...), serverShapeCases...), clusterShapeCases...), storageShapeCases...)
	got := map[string]any{}
	kube := newDetailCluster(t)
	for i, args := range cases {
		if i == len(shapeCases) {
			addr, _ := fakeMemcached(t)
			if s, err := runCache(t, "-o", "json", "conn", "add", "mc", "memcached://"+addr); err != nil {
				t.Fatalf("conn add mc: %v\n%s", err, s)
			}
		}
		if i == len(shapeCases)+len(serverShapeCases) {
			if s, err := runCache(t, "-o", "json", "import", "kubeconfig", kube.kubeconfig(t)); err != nil {
				t.Fatalf("import kubeconfig: %v\n%s", err, s)
			}
		}
		if i == len(cases)-len(storageShapeCases) {
			if s, err := runCache(t, "-o", "json", "conn", "add", "bk", "s3://AKIAEXAMPLE@shop-dev/backups?region=eu-west-1"); err != nil {
				t.Fatalf("conn add bk: %v\n%s", err, s)
			}
			m := &memBucket{objs: map[string]string{"a.txt": "a"}}
			saved := openBucket
			openBucket = func(*call, context.Context, *store.State, *store.Conn) (storex.Bucket, error) { return m, nil }
			t.Cleanup(func() { openBucket = saved })
		}
		s := runShape(t, args)
		setGate(tcl, false, gateDryRun)
		var v any
		if err := json.Unmarshal([]byte(s), &v); err != nil {
			t.Errorf("%v: not JSON: %v\n%s", args, err, s)
			continue
		}
		sh := shapeOf(v)
		// error codes are part of the contract too: keep their values
		if e, ok := v.(map[string]any)["error"].(map[string]any); ok {
			if code, ok := e["code"].(string); ok {
				sh.(map[string]any)["error"].(map[string]any)["code"] = "code " + code
			}
		}
		got[strings.Join(args, " ")] = sh
	}
	keys := make([]string, 0, len(cases))
	for _, args := range cases {
		keys = append(keys, strings.Join(args, " "))
	}
	path := filepath.Join("testdata", "shapes.json")
	if *updateShapes {
		b, _ := json.MarshalIndent(got, "", "  ")
		if err := os.WriteFile(path, append(b, '\n'), 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var want map[string]any
	if err := json.Unmarshal(b, &want); err != nil {
		t.Fatal(err)
	}
	for _, key := range keys {
		w, ok := want[key]
		if !ok {
			t.Errorf("komando %s: new case, run with -update-shapes", key)
			continue
		}
		var removed, added []string
		diffShape(key, w, got[key], &removed, &added)
		for _, r := range removed {
			t.Errorf("BREAKING (output contract %d): %s", out.Contract, r)
		}
		for _, a := range added {
			t.Errorf("new in the output: %s (fine: run with -update-shapes)", a)
		}
	}
}

// runShape runs komando and returns its JSON answer, the error envelope
// included (Execute prints that one, not the command).
func runShape(t *testing.T, args []string) string {
	t.Helper()
	root := newRoot(tcl)
	t.Cleanup(endCommand) // the next test starts with none of this command's flags
	root.SetArgs(append([]string{"-o", "json"}, args...))
	root.SilenceErrors, root.SilenceUsage = true, true
	var b strings.Builder
	saved := tcl.out.W
	tcl.out.W = &b
	defer func() { tcl.out.W = saved; tcl.out.Reset() }()
	var ec exitCode // the command printed its own answer already, like in Execute
	if cmd, err := root.ExecuteC(); err != nil && !errors.As(err, &ec) {
		tcl.out.Fail(commandName(cmd), toErr(err))
	}
	return b.String()
}

// dataKeyed are fields whose keys are data, not field names: `recipe
// list`'s params (a recipe's blanks and their defaults) and the flag_notes
// of `schema vpn add` (keyed by flag name). Their shape is "*" for any
// key, so a recipe with other blanks, or a note on another flag, is not a
// change of the output. The keys of a field listed here are not guarded,
// in any command: a new field called params or flag_notes elsewhere needs
// another name, or to be left out of this list.
var dataKeyed = map[string]bool{"params": true, "flag_notes": true}

// shapeOf replaces every value with its JSON type; arrays become one
// element with the merged shape of all their elements. Maps keyed by
// names the user chose (hosts, groups) still show their keys: those come
// from the fixture above, which is fixed.
func shapeOf(v any) any {
	switch x := v.(type) {
	case map[string]any:
		m := map[string]any{}
		for k, e := range x {
			if inner, ok := e.(map[string]any); ok && dataKeyed[k] {
				var merged any
				for _, iv := range inner {
					merged = mergeShape(merged, shapeOf(iv))
				}
				m[k] = map[string]any{"*": merged}
				continue
			}
			m[k] = shapeOf(e)
		}
		return m
	case []any:
		var merged any
		for _, e := range x {
			merged = mergeShape(merged, shapeOf(e))
		}
		if merged == nil {
			return []any{}
		}
		return []any{merged}
	case string:
		return "string"
	case float64:
		return "number"
	case bool:
		return "bool"
	case nil:
		return "null"
	}
	return fmt.Sprintf("%T", v)
}

func mergeShape(a, b any) any {
	if a == nil {
		return b
	}
	am, aok := a.(map[string]any)
	bm, bok := b.(map[string]any)
	if aok && bok {
		for k, v := range bm {
			am[k] = mergeShape(am[k], v)
		}
		return am
	}
	if a == "null" {
		return b
	}
	return a
}

// diffShape lists what was in want but not in got (or has another type),
// and what got has that want does not. A field that is null in one and has
// a type in the other is not a change: omitempty and empty lists do that.
func diffShape(path string, want, got any, removed, added *[]string) {
	if want == "null" || got == "null" {
		return
	}
	wm, wok := want.(map[string]any)
	gm, gok := got.(map[string]any)
	if wok || gok {
		if !wok || !gok {
			*removed = append(*removed, fmt.Sprintf("%s: was %s, now %s", path, kindName(want), kindName(got)))
			return
		}
		keys := make([]string, 0, len(wm))
		for k := range wm {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			if _, ok := gm[k]; !ok {
				*removed = append(*removed, fmt.Sprintf("%s.%s: gone", path, k))
				continue
			}
			diffShape(path+"."+k, wm[k], gm[k], removed, added)
		}
		for k := range gm {
			if _, ok := wm[k]; !ok {
				*added = append(*added, path+"."+k)
			}
		}
		return
	}
	wl, wok := want.([]any)
	gl, gok := got.([]any)
	if wok || gok {
		if !wok || !gok {
			*removed = append(*removed, fmt.Sprintf("%s: was %s, now %s", path, kindName(want), kindName(got)))
			return
		}
		if len(wl) == 1 && len(gl) == 1 {
			diffShape(path+"[]", wl[0], gl[0], removed, added)
		}
		return
	}
	if want != got {
		*removed = append(*removed, fmt.Sprintf("%s: was %v, now %v", path, want, got))
	}
}

func kindName(v any) string {
	switch v.(type) {
	case map[string]any:
		return "object"
	case []any:
		return "list"
	}
	return fmt.Sprint(v)
}
