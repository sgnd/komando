package cli

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

// facts reports every real file system, with its mount point, so the
// phone app's readings (load, cores, memory, disks) come from one read.
func TestFactsDisks(t *testing.T) {
	out := "cpus=4\nmem_total_mb=7962\nmem_available_mb=5120\nload=0.12 0.10 0.05\n" +
		"disk=/dev/sda1\t81264764\t51086560\t30161820\t63\t/\n" +
		"disk=/dev/sdb1\t1048576000\t524288000\t524288000\t50\t/srv/data dir\n" +
		"disk=nas:/export\t2097152\t0\t2097152\t0\t/mnt/nas\n"
	f := parseFactsAt(out, time.Now())
	b, _ := json.Marshal(f)
	for _, want := range []string{`"load":[0.12,0.1,0.05]`, `"cpus":4`, `"mem_total_mb":7962`, `"mem_available_mb":5120`,
		`"disks":[{"mount":"/","device":"/dev/sda1","size_mb":79360,"used_mb":49889,"avail_mb":29454,"used_pct":63}`,
		`{"mount":"/srv/data dir","device":"/dev/sdb1","size_mb":1024000,"used_mb":512000,"avail_mb":512000,"used_pct":50}`,
		`{"mount":"/mnt/nas","device":"nas:/export","size_mb":2048,"used_mb":0,"avail_mb":2048,"used_pct":0}]`} {
		if !strings.Contains(string(b), want) {
			t.Errorf("want %s in %s", want, b)
		}
	}
	// no disk lines (df missing): unknown, not an empty list
	if f := parseFactsAt("cpus=1\n", time.Now()); f["disks"] != nil {
		t.Errorf("disks without df: %v", f["disks"])
	}
	// the script lists real file systems only
	for _, skip := range []string{"tmpfs", "devtmpfs", "overlay", "squashfs", "loop", "proc", "sys", "run", "snap"} {
		if !strings.Contains(factsScript, skip) {
			t.Errorf("factsScript does not skip %s", skip)
		}
	}
	w := parseWinFacts("disk=C:\t512000\t256000\t256000\t50\tC:\\\n", time.Now())
	if b, _ := json.Marshal(w["disks"]); string(b) != `[{"mount":"C:\\","device":"C:","size_mb":500,"used_mb":250,"avail_mb":250,"used_pct":50}]` {
		t.Errorf("windows disks: %s", b)
	}
}
