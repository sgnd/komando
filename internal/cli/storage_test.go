package cli

import (
	"context"
	"fmt"
	"io"
	"net/url"
	"os"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/sgnd/komando/internal/out"
	"github.com/sgnd/komando/internal/store"
	"github.com/sgnd/komando/internal/storex"
)

// An sftp:// conn reaches an SSH server, so it must not be a way around
// that server's protection.
func TestSFTPConnInheritsHostProtection(t *testing.T) {
	st := &store.State{
		Hosts: map[string]*store.Host{"web1": {Name: "web1", Address: "10.0.0.5", Protected: true}},
		Conns: map[string]*store.Conn{},
	}
	same := &store.Conn{Name: "files", URL: "sftp://deploy@10.0.0.5/uploads"}
	other := &store.Conn{Name: "elsewhere", URL: "sftp://deploy@10.0.0.6/uploads"}
	port := &store.Conn{Name: "otherport", URL: "sftp://deploy@10.0.0.5:2222/uploads"}
	if !protectedConn(st, same) {
		t.Error("sftp conn to a protected host is not protected")
	}
	if protectedConn(st, other) || protectedConn(st, port) {
		t.Error("sftp conn to another server counted as protected")
	}
}

// smb:// conns open an SMB share; KOMANDO_TEST_SMB (with the password in
// KOMANDO_TEST_SMB_PASSWORD) names a real one to list.
func TestOpenBucketSMB(t *testing.T) {
	t.Setenv("KOMANDO_TEST_SMB_PW", os.Getenv("KOMANDO_TEST_SMB_PASSWORD"))
	st := &store.State{Hosts: map[string]*store.Host{}, Conns: map[string]*store.Conn{}}
	c := &store.Conn{Name: "share", URL: "smb://alice@127.0.0.1:1/team", PasswordRef: "env:KOMANDO_TEST_SMB_PW"}
	if _, err := openBucket(tcl, context.Background(), st, c); toErr(err).Code != "STORAGE_CONNECT" {
		t.Errorf("closed port: %v", err)
	}
	if c.URL = os.Getenv("KOMANDO_TEST_SMB"); c.URL == "" {
		return
	}
	b, err := openBucket(tcl, context.Background(), st, c)
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	if _, _, err := b.List(context.Background(), "", false, 10); err != nil {
		if oe, ok := err.(*out.Error); !ok || oe.Code != "FOLDER_NOT_FOUND" {
			t.Error(err)
		}
	}
}

// memBucket is a storage conn in memory, for the command layer's tests.
type memBucket struct {
	objs   map[string]string
	listed int // List calls
}

func (m *memBucket) List(_ context.Context, prefix string, recursive bool, limit int) ([]storex.Object, bool, error) {
	m.listed++
	var objs []storex.Object
	dirs := map[string]bool{}
	for k, v := range m.objs {
		if !strings.HasPrefix(k, prefix) {
			continue
		}
		if strings.HasSuffix(k, "/") && (recursive || k == prefix) {
			continue // a folder marker, as a bucket lists it
		}
		rest := strings.TrimPrefix(k, prefix)
		if i := strings.Index(rest, "/"); !recursive && i >= 0 {
			if d := prefix + rest[:i+1]; !dirs[d] {
				dirs[d] = true
				objs = append(objs, storex.Object{Key: d, Dir: true})
			}
			continue
		}
		objs = append(objs, storex.Object{Key: k, Size: int64(len(v)), Modified: time.Now().Add(-time.Hour)})
	}
	sort.Slice(objs, func(i, j int) bool { return objs[i].Key < objs[j].Key })
	if limit > 0 && len(objs) > limit {
		return objs[:limit], true, nil
	}
	return objs, false, nil
}

func (m *memBucket) Get(_ context.Context, key string, w io.Writer) (int64, error) {
	v, ok := m.objs[key]
	if !ok {
		return 0, out.Errf(out.ExitNotFound, "OBJECT_NOT_FOUND", "list objects with `komando storage s3 object list NAME [PREFIX]`", "object not found")
	}
	n, err := io.WriteString(w, v)
	return int64(n), err
}

func (m *memBucket) Exists(_ context.Context, key string) (bool, error) {
	_, ok := m.objs[key]
	return ok, nil
}

func (m *memBucket) Stat(_ context.Context, key string) (storex.Object, error) {
	v, ok := m.objs[key]
	if !ok {
		return storex.Object{}, out.Errf(out.ExitNotFound, "OBJECT_NOT_FOUND", "list objects with `komando storage s3 object list NAME [PREFIX]`", "%s not found", key)
	}
	return storex.Object{Key: key, Size: int64(len(v))}, nil
}

func (m *memBucket) Put(_ context.Context, key string, r io.Reader, _ int64, _ string) error {
	b, err := io.ReadAll(r)
	if err == nil { // a store keeps nothing of an upload that failed
		m.objs[key] = string(b)
	}
	return err
}

func (m *memBucket) Remove(_ context.Context, key string) error { delete(m.objs, key); return nil }

func (m *memBucket) Link(context.Context, string, time.Duration) (*url.URL, error) {
	return nil, out.Errf(out.ExitUsage, "NOT_SUPPORTED", "", "no links")
}

// Lookup: a key is a file; a folder is any key under name/.
func (m *memBucket) Lookup(_ context.Context, rel string) (storex.Object, bool, error) {
	r := strings.Trim(rel, "/")
	if err := storex.CheckKey(r); err != nil {
		return storex.Object{}, false, err
	}
	if v, ok := m.objs[r]; ok {
		return storex.Object{Key: r, Size: int64(len(v))}, true, nil
	}
	for k := range m.objs {
		if strings.HasPrefix(k, r+"/") {
			return storex.Object{Key: r + "/", Dir: true}, true, nil
		}
	}
	return storex.Object{}, false, nil
}

// Mkdir makes a folder marker, as on S3.
func (m *memBucket) Mkdir(ctx context.Context, rel string) (bool, error) {
	o, found, err := m.Lookup(ctx, rel)
	if err != nil || found {
		if found && !o.Dir {
			err = out.Errf(out.ExitConflict, "FILE_EXISTS", "", "a file named %q is already there", rel)
		}
		return found, err
	}
	m.objs[strings.Trim(rel, "/")+"/"] = ""
	return false, nil
}

// Move copies and deletes, as on S3: one object, no folders.
func (m *memBucket) Move(ctx context.Context, src, dst string, o storex.MoveOpts) (storex.Moved, error) {
	so, found, err := m.Lookup(ctx, src)
	switch {
	case err != nil:
		return storex.Moved{}, err
	case !found:
		return storex.Moved{}, storex.NotThere(src)
	case so.Dir:
		return storex.Moved{}, out.Errf(out.ExitUsage, "STORAGE_UNSUPPORTED", "", "%q is a folder", src)
	}
	_, replaced, _ := m.Lookup(ctx, dst)
	if replaced && !o.Overwrite {
		return storex.Moved{}, out.Errf(out.ExitConflict, "FILE_EXISTS", "", "a file named %q is already there", dst)
	}
	mv := storex.Moved{Replaced: replaced, Size: so.Size, Copied: true}
	if !o.DryRun {
		m.objs[dst] = m.objs[src]
		delete(m.objs, src)
	}
	return mv, nil
}

func (m *memBucket) Close() error { return nil }

// withMemBucket adds the storage conn bk, backed by m.
func withMemBucket(t *testing.T, m *memBucket) {
	t.Helper()
	invHome(t)
	mustRun(t, "conn", "add", "bk", "s3://AKIAEXAMPLE@shop-dev/backups?region=eu-west-1")
	saved := openBucket
	openBucket = func(*call, context.Context, *store.State, *store.Conn) (storex.Bucket, error) { return m, nil }
	t.Cleanup(func() { openBucket = saved })
}

// typing answers what komando asks on the terminal with answer.
func typing(t *testing.T, answer string) {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	w.WriteString(answer)
	w.Close()
	saved, savedI := tcl.stdin, tcl.terminal
	tcl.stdin, tcl.terminal = r, true
	t.Cleanup(func() { tcl.stdin, tcl.terminal = saved, savedI; r.Close() })
}

// rm --prefix at a person's terminal lists what goes before asking for
// how many go (S-7.3: several items, so the count, labelled); the bucket's
// name deletes nothing, the right count deletes it all.
func TestStorageRmPrefixShowsBeforeAsking(t *testing.T) {
	m := &memBucket{objs: map[string]string{"daily/a.gz": "aa", "daily/b.gz": "bbb", "keep.txt": "k"}}
	withMemBucket(t, m)
	typing(t, "bk\n")
	var e *out.Error
	said := stderrOf(t, func() { _, e = invRun(t, "storage", "s3", "object", "delete", "bk", "--prefix", "daily") })
	if e == nil || e.Code != "POLICY_BLOCKED" || len(m.objs) != 3 {
		t.Fatalf("a wrong name: %+v, %d objects left", e, len(m.objs))
	}
	list, typeName := strings.Index(said, "daily/b.gz"), strings.Index(said, "Type 2 (objects under daily/ in bk) to continue")
	if list < 0 || typeName < list || !strings.Contains(said, "2 objects (5 B) under daily/ in bk") {
		t.Errorf("the list comes before the question:\n%s", said)
	}
	typing(t, "2\n")
	stderrOf(t, func() { mustRun(t, "storage", "s3", "object", "delete", "bk", "--prefix", "daily/") })
	if _, ok := m.objs["keep.txt"]; len(m.objs) != 1 || !ok {
		t.Errorf("after the right name: %v", m.objs)
	}
}

// An agent (no terminal) is stopped before komando lists anything.
func TestStorageRmPrefixAgentStopsFirst(t *testing.T) {
	m := &memBucket{objs: map[string]string{"daily/a.gz": "aa"}}
	withMemBucket(t, m)
	saved := tcl.terminal
	tcl.terminal = false
	t.Cleanup(func() { tcl.terminal = saved })
	if e := wantCode(t, "POLICY_BLOCKED", "storage", "s3", "object", "delete", "bk", "--prefix", "daily/"); e.Exit != out.ExitPolicy || m.listed != 0 || len(m.objs) != 1 {
		t.Errorf("exit %d, listed %d, %d objects", e.Exit, m.listed, len(m.objs))
	}
}

// Storage errors name the conn in the command they suggest.
func TestStorageHintNamesTheConn(t *testing.T) {
	withMemBucket(t, &memBucket{objs: map[string]string{}})
	e := wantCode(t, "OBJECT_NOT_FOUND", "storage", "s3", "object", "read", "bk", "nope.txt")
	if e.Hint != "list objects with `komando storage s3 object list bk [PREFIX]`" {
		t.Errorf("hint: %q", e.Hint)
	}
	in := out.Errf(out.ExitConnect, "STORAGE_AUTH", "store a key with `komando secret set NAME` and pass --password-ref secret:NAME; then `komando conn test NAME`", "x")
	if got := namedHint(in, "bk").(*out.Error).Hint; got != "store a key with `komando secret set NAME` and pass --password-ref secret:NAME; then `komando conn test bk`" {
		t.Errorf("only conn commands change: %q", got)
	}
}

// storage s3 object list CONN db lists what is in the folder db/ on a bucket too, as
// on a file server; a prefix that names no folder still lists by prefix.
func TestStorageLsFolderWithoutSlash(t *testing.T) {
	withMemBucket(t, &memBucket{objs: map[string]string{"db/a.sql": "a", "db/b.sql": "b", "dbx.txt": "x"}})
	keys := func(d map[string]any) string {
		var k []string
		for _, o := range d["objects"].([]any) {
			k = append(k, o.(map[string]any)["key"].(string))
		}
		return strings.Join(k, ",")
	}
	if got := keys(mustRun(t, "storage", "s3", "object", "list", "bk", "db/")); got != "db/a.sql,db/b.sql" {
		t.Errorf("db/: %s", got)
	}
	d := mustRun(t, "storage", "s3", "object", "list", "bk", "db")
	if got := keys(d); got != "db/a.sql,db/b.sql" || d["prefix"] != "db/" {
		t.Errorf("db: %s (prefix %v)", got, d["prefix"])
	}
	if got := keys(mustRun(t, "storage", "s3", "object", "list", "bk", "d")); got != "db/,dbx.txt" {
		t.Errorf("d: %s", got)
	}
}

// tempKeyBucket makes links with temporary keys, as an S3 conn with an
// SSO or role profile does.
type tempKeyBucket struct{ *memBucket }

func (tempKeyBucket) TemporaryKeys() bool { return true }

func (tempKeyBucket) Link(_ context.Context, key string, _ time.Duration) (*url.URL, error) {
	return url.Parse("https://shop-dev.s3.amazonaws.com/" + key + "?X-Amz-Security-Token=x")
}

// A link signed with temporary AWS keys says it can end early.
func TestStorageLinkTemporaryKeysWarns(t *testing.T) {
	invHome(t)
	mustRun(t, "conn", "add", "bk", "s3://shop-dev/backups?region=eu-west-1", "--option", "aws_profile=dev")
	saved := openBucket
	openBucket = func(*call, context.Context, *store.State, *store.Conn) (storex.Bucket, error) {
		return tempKeyBucket{&memBucket{objs: map[string]string{"a.txt": "a"}}}, nil
	}
	t.Cleanup(func() { openBucket = saved })
	d := mustRun(t, "storage", "s3", "object", "link", "bk", "a.txt", "--expires", "24h")
	if w, _ := d["warning"].(string); !strings.Contains(w, "temporary AWS keys (profile dev)") {
		t.Errorf("warning: %q", w)
	}
}

// The steps around the storage's own entry, as storage --help names them.
func TestStorageJourneyCommands(t *testing.T) {
	withMemBucket(t, &memBucket{objs: map[string]string{}})
	if d := mustRun(t, "list", "kind:storage"); !strings.Contains(fmt.Sprint(d), "bk") {
		t.Errorf("list kind:storage: %v", d)
	}
	e := wantCode(t, "USAGE", "storage", "s3", "object", "delete", "bk")
	if !strings.Contains(e.Hint, "komando conn rm bk") || !strings.Contains(e.Hint, "komando storage s3 object list bk") {
		t.Errorf("rm without keys: %q", e.Hint)
	}
	mustRun(t, "conn", "edit", "bk", "--add-tag", "backup")
	mustRun(t, "conn", "rm", "bk")
}

// C-F03: storage s3 object delete's cap is --max-remove, with no short form, so it is
// not taken for a list's --limit.
func TestStorageRmMaxRemove(t *testing.T) {
	m := &memBucket{objs: map[string]string{"daily/a.gz": "aa", "daily/b.gz": "bbb"}}
	withMemBucket(t, m)
	defer func() { setGate(tcl, false, gateDryRun) }()
	tcl.out.Reset()
	e := wantCode(t, "TOO_MANY", "storage", "s3", "object", "delete", "bk", "--prefix", "daily/", "--dry-run", "--max-remove", "1")
	if !strings.Contains(e.Message, "more than --max-remove 1") || !strings.Contains(e.Hint, "raise --max-remove") {
		t.Errorf("--max-remove 1: %+v", e)
	}
	if len(m.objs) != 2 {
		t.Errorf("a dry run removed objects: %v", m.objs)
	}
	c, _, _ := newRoot(tcl).Find([]string{"storage", "s3", "object", "delete"})
	if c.Flags().ShorthandLookup("n") != nil || c.Flags().Lookup("limit") != nil || c.Flags().Lookup("max-remove").Shorthand != "" {
		t.Error("storage s3 object delete has -n or --limit, or a short --max-remove")
	}
}

// A folder given where a file goes is IS_A_DIRECTORY, as fs cat says it
// (C79): storage download without -r, storage s3 object delete without --prefix. A
// pattern is a usage error.
func TestStorageFolderIsADirectory(t *testing.T) {
	withMemBucket(t, &memBucket{objs: map[string]string{"logs/a.txt": "x"}})
	if e := wantCode(t, "IS_A_DIRECTORY", "storage", "download", "bk", "logs/", "--to", t.TempDir()); e.Exit != out.ExitUsage || !strings.Contains(e.Hint, "-r") {
		t.Errorf("download: %+v", e)
	}
	if e := wantCode(t, "IS_A_DIRECTORY", "storage", "s3", "object", "delete", "bk", "logs/"); !strings.Contains(e.Hint, "--prefix") {
		t.Errorf("rm: %+v", e)
	}
	wantCode(t, "USAGE", "storage", "s3", "object", "delete", "bk", "logs/*.txt")
}
