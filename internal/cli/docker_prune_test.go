package cli

import (
	"encoding/json"
	"io"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/sgnd/komando/internal/store"
)

// recorded from docker 27 (API 1.47), trimmed
const prunePreviewOut = `== api
1.47
== containers
{"Command":"\"sh\"","CreatedAt":"2026-09-01 10:00:00 +0000 UTC","ID":"aaa111aaa111aaa111","Image":"busybox","Names":"old_job","Size":"12.3kB (virtual 4.26MB)","State":"exited","Status":"Exited (0) 2 months ago"}
{"Command":"\"node\"","CreatedAt":"2026-11-04 09:00:00 +0000 UTC","ID":"bbb222bbb222bbb222","Image":"shop/api:2","Names":"new_job","Size":"1.5MB (virtual 200MB)","State":"exited","Status":"Exited (1) 1 day ago"}
== images
{"Containers":"N/A","CreatedAt":"2026-08-01 12:00:00 +0200 CEST","ID":"sha256:dangling1dangling1","Repository":"<none>","Tag":"<none>","Size":"150MB"}
{"Containers":"N/A","CreatedAt":"2026-11-03 12:00:00 +0200 CEST","ID":"sha256:dangling2dangling2","Repository":"<none>","Tag":"<none>","Size":"80MB"}
{"Containers":"N/A","CreatedAt":"2026-07-01 12:00:00 +0000 UTC","ID":"sha256:busyboxbusybox","Repository":"busybox","Tag":"latest","Size":"4.26MB"}
{"Containers":"N/A","CreatedAt":"2026-06-01 12:00:00 +0000 UTC","ID":"sha256:nginxnginxnginx","Repository":"nginx","Tag":"1.27","Size":"1.2GB"}
{"Containers":"N/A","CreatedAt":"2026-05-01 12:00:00 +0000 UTC","ID":"sha256:oldtaggedold","Repository":"shop/api","Tag":"1","Size":"300MB"}
== uses
aaa111aaa111aaa111 sha256:busyboxbusybox
bbb222bbb222bbb222 sha256:apiapiapi
ccc333ccc333ccc333 sha256:nginxnginxnginx
== cache
Reclaimable:	2.5GB
Total:		3GB
== df
{"Active":"1","Reclaimable":"1.7GB (70%)","Size":"2.4GB","TotalCount":"5","Type":"Images"}
== volumes
{"Driver":"local","Labels":"com.docker.volume.anonymous=","Name":"3f9a0anon","Scope":"local"}
{"Driver":"local","Labels":"","Name":"pgdata","Scope":"local"}
== volume-sizes
VOLUME NAME   LINKS     SIZE
3f9a0anon     0         64MB
pgdata        0         5GB
== volume-created
3f9a0anon 2026-09-01T10:00:00Z
pgdata 2026-01-01T10:00:00+02:00

`

func TestParsePrunePreview(t *testing.T) {
	now := time.Date(2026, 11, 5, 0, 0, 0, 0, time.UTC)

	// plain prune: every stopped container, dangling images, build cache
	p := parsePrunePreview(prunePreviewOut, pruneOpts{}, now)
	if len(p.Containers) != 2 || len(p.Images) != 2 || p.Volumes != nil {
		t.Fatalf("got %+v", p)
	}
	if p.Images[0].Name != "<none> (dangling)" || p.Images[0].Bytes != 150_000_000 {
		t.Errorf("images %+v", p.Images)
	}
	want := int64(12_300 + 1_500_000 + 150_000_000 + 80_000_000 + 2_500_000_000)
	if p.TotalBytes != want || p.CacheBytes != 2_500_000_000 {
		t.Errorf("total %d, want %d", p.TotalBytes, want)
	}
	if len(p.DockerDF) != 1 {
		t.Errorf("df %v", p.DockerDF)
	}

	// --older-than 30d --all: the new container and the new dangling image
	// stay; busybox goes with old_job; nginx stays (a running container uses it)
	p = parsePrunePreview(prunePreviewOut, pruneOpts{olderThan: 30 * 24 * time.Hour, all: true}, now)
	var names []string
	for _, c := range p.Containers {
		names = append(names, c.Name)
	}
	if strings.Join(names, ",") != "old_job" {
		t.Errorf("containers %v", names)
	}
	names = nil
	for _, i := range p.Images {
		names = append(names, i.Name)
	}
	if strings.Join(names, ",") != "shop/api:1,<none> (dangling),busybox:latest" {
		t.Errorf("images %v", names)
	}

	// --volumes on docker 23+: only the anonymous volume
	p = parsePrunePreview(prunePreviewOut, pruneOpts{volumes: true}, now)
	if len(p.Volumes) != 1 || p.Volumes[0].Name != "3f9a0anon" || p.Volumes[0].Bytes != 64_000_000 {
		t.Errorf("volumes %+v", p.Volumes)
	}
	old := strings.Replace(prunePreviewOut, "1.47", "1.41", 1)
	if p = parsePrunePreview(old, pruneOpts{volumes: true}, now); len(p.Volumes) != 2 || len(p.Notes) == 0 {
		t.Errorf("old docker removes named volumes too: %+v", p)
	}
	// --volumes --older-than: only volumes made before the cut-off; one of
	// unknown age is kept
	young := strings.Replace(prunePreviewOut, "3f9a0anon 2026-09-01T10:00:00Z", "3f9a0anon 2026-11-04T10:00:00Z", 1)
	if p = parsePrunePreview(young, pruneOpts{volumes: true, olderThan: 30 * 24 * time.Hour}, now); len(p.Volumes) != 0 {
		t.Errorf("a young volume stays: %+v", p.Volumes)
	}
	if p = parsePrunePreview(prunePreviewOut, pruneOpts{volumes: true, olderThan: 30 * 24 * time.Hour}, now); len(p.Volumes) != 1 || p.Volumes[0].Created.IsZero() {
		t.Errorf("an old volume goes: %+v", p.Volumes)
	}
	unknown := strings.Replace(prunePreviewOut, "3f9a0anon 2026-09-01T10:00:00Z\n", "", 1)
	if p = parsePrunePreview(unknown, pruneOpts{volumes: true, olderThan: 30 * 24 * time.Hour}, now); len(p.Volumes) != 0 {
		t.Errorf("a volume of unknown age stays: %+v", p.Volumes)
	}
	// no builder du
	if p = parsePrunePreview(strings.Replace(prunePreviewOut, "Reclaimable:\t2.5GB", "", 1), pruneOpts{}, now); p.BuildCache != "" || p.CacheBytes != 0 {
		t.Errorf("cache %+v", p)
	}
}

func TestDockerSize(t *testing.T) {
	for in, want := range map[string]int64{"0B": 0, "12.3kB": 12_300, "77.8MB": 77_800_000, "1.2GB (virtual 2GB)": 1_200_000_000, "1KiB": 1024, "": 0, "N/A": 0} {
		if got := dockerSize(in); got != want {
			t.Errorf("%q: %d, want %d", in, got, want)
		}
	}
	if decimalBytes(2_954_272_300) != "3.0GB" || decimalBytes(999) != "999B" || decimalBytes(12_300) != "12.3kB" {
		t.Error(decimalBytes(2_954_272_300), decimalBytes(999), decimalBytes(12_300))
	}
	if goDuration(30*24*time.Hour) != "720h" || goDuration(90*time.Minute) != "90m" {
		t.Error(goDuration(30*24*time.Hour), goDuration(90*time.Minute))
	}
}

func TestDockerPruneCommand(t *testing.T) {
	srv := startFakeServer(t)
	srv.reply(prunePreviewOut)
	pre := []string{"--host-key-policy", "accept-new"}

	// the dry run reads, sums up and says the real run needs a person
	d, e := invRun(t, append(pre, "docker", "prune", "dev", "--older-than", "30d", "--all", "--dry-run")...)
	if e != nil {
		t.Fatalf("%+v", e)
	}
	r := d["results"].([]any)[0].(map[string]any)
	if r["would_run"] != "docker system prune -f -a --filter until=720h" || r["total_bytes"].(float64) <= 0 {
		t.Errorf("preview %v", r)
	}
	if b, _ := d["would_be_blocked"].(map[string]any); b["code"] != "POLICY_BLOCKED" {
		t.Errorf("would_be_blocked %v", d["would_be_blocked"])
	}
	execs := srv.take()
	if len(execs) != 1 {
		t.Fatalf("execs %d", len(execs))
	}
	for _, bad := range []string{"prune", " rm ", "rmi"} {
		if strings.Contains(execs[0].cmd, bad) {
			t.Errorf("the preview ran %q: %s", bad, execs[0].cmd)
		}
	}

	// the real run deletes: it needs --allow-dangerous, and nothing runs
	wantCode(t, "POLICY_BLOCKED", append(pre, "docker", "prune", "dev")...)
	if n := len(srv.take()); n != 0 {
		t.Errorf("%d commands ran", n)
	}

	// --volumes --older-than: the dry run lists the old anonymous volume
	d, e = invRun(t, append(pre, "docker", "prune", "dev", "--volumes", "--older-than", "30d", "--dry-run")...)
	if e != nil {
		t.Fatalf("%+v", e)
	}
	r = d["results"].([]any)[0].(map[string]any)
	if !strings.Contains(r["would_run"].(string), "docker system prune -f --filter until=720h; docker volume rm") || len(r["volumes"].([]any)) != 1 {
		t.Errorf("preview %v", r)
	}
	if ex := srv.take(); len(ex) != 1 || !strings.Contains(ex[0].cmd, "volume inspect") || strings.Contains(ex[0].cmd, " rm ") {
		t.Errorf("the preview: %v", ex)
	}
	// the real run: prune with the age filter (docker refuses --volumes
	// with it), then the volumes read again and removed by name
	if _, e := invRun(t, append(pre, "docker", "prune", "dev", "--volumes", "--older-than", "30d", "--allow-dangerous", "--yes")...); e != nil {
		t.Fatalf("%+v", e)
	}
	ex := srv.take()
	if len(ex) != 3 || !strings.Contains(ex[0].cmd, "docker system prune -f --filter until=720h") || strings.Contains(ex[0].cmd, "--volumes") ||
		!strings.Contains(ex[1].cmd, "volume inspect") || !strings.Contains(ex[2].cmd, "docker volume rm 3f9a0anon") || strings.Contains(ex[2].cmd, "pgdata") {
		t.Errorf("the real run: %v", ex)
	}
	wantCode(t, "USAGE", append(pre, "docker", "prune", "dev", "--older-than", "-3d")...)
}

// A person confirms a docker delete by typing the server's name, as for
// any other destructive command, and only once: the server guard that
// runs next takes the same answer (a prune --all used to ask "Type yes"
// and then the name again).
func TestDockerDeleteConfirmsWithTheServerName(t *testing.T) {
	setHome(t, t.TempDir())
	t.Setenv("KOMANDO_VAULT_PASS", "test")
	if err := store.Update(store.Save(), func(st *store.State) error {
		st.Hosts["web1"] = &store.Host{Name: "web1", Address: "10.255.255.1", User: "deploy"}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	savedInteractive, savedStdin, savedErr := tcl.terminal, tcl.stdin, tcl.out.Err
	t.Cleanup(func() { tcl.terminal, tcl.stdin, tcl.out.Err = savedInteractive, savedStdin, savedErr; resetApproval() })
	tcl.terminal = true
	answer := func(typed string, args ...string) (string, error) {
		resetApproval()
		in, w, _ := os.Pipe()
		_, _ = w.WriteString(typed + "\n")
		_ = w.Close()
		er, ew, _ := os.Pipe()
		tcl.stdin, tcl.out.Err = in, ew
		_, err := guardDocker(tcl, "web1", args)
		var asked string
		if err == nil {
			// the server guard of the same command: no second question
			st, _ := store.Load()
			hosts, _ := resolveTargets(tcl, st, "web1")
			err = Guard(tcl, st, hosts, "docker "+strings.Join(args, " "), true)
		}
		_ = ew.Close()
		b, _ := io.ReadAll(er)
		asked = string(b)
		tcl.stdin, tcl.out.Err = savedStdin, savedErr
		return asked, err
	}
	asked, err := answer("web1", "system", "prune", "-f", "-a")
	if err != nil || strings.Count(asked, "Type the name web1") != 1 || strings.Contains(asked, "Type yes") {
		t.Errorf("prune --all with the name: err %v, asked %q", err, asked)
	}
	asked, err = answer("yes", "rm", "old-api")
	if e := toErr(err); e == nil || e.Code != "POLICY_BLOCKED" || !strings.Contains(asked, "Type the name web1") {
		t.Errorf("docker rm answered yes: err %v, asked %q", err, asked)
	}
}

// A dry run with --volumes has "volumes" even when no volume would go;
// without --volumes the key is absent.
func TestPrunePreviewEmptyVolumes(t *testing.T) {
	for _, volumes := range []bool{true, false} {
		b, err := json.Marshal(parsePrunePreview("== api\n1.45\n", pruneOpts{volumes: volumes}, time.Now()))
		if err != nil {
			t.Fatal(err)
		}
		if got := strings.Contains(string(b), `"volumes":[]`); got != volumes {
			t.Errorf("--volumes=%v: %s", volumes, b)
		}
	}
}

// C136: an unknown target stops the rating with its error, before a
// compose file check that would find no server to read it from.
func TestGuardDockerUnknownTarget(t *testing.T) {
	setHome(t, t.TempDir())
	t.Setenv("KOMANDO_VAULT_PASS", "test")
	if _, err := guardDocker(tcl, "nosuch", []string{"compose", "up", "-d"}); err == nil {
		t.Error("an unknown target was rated without an error")
	}
}
