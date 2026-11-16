package cli

import (
	"encoding/json"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/sgnd/komando/internal/store"
)

// facts --only runs the probes of the sections named, for a phone that
// polls: no package index, Docker, ports or units, and only those keys.
func TestFactsOnly(t *testing.T) {
	script, keys, err := factsOnly([]string{"load", "mem", "disks"})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"/proc/loadavg", "nproc", "/proc/meminfo", "df -P -k"} {
		if !strings.Contains(script, want) {
			t.Errorf("script lacks %s", want)
		}
	}
	for _, heavy := range []string{"apt-get", "docker", "ss -l", "systemctl", "pm2", "dnf", "hoststate", "sudo"} {
		if strings.Contains(script, heavy) {
			t.Errorf("script runs %s", heavy)
		}
	}
	h := &store.Host{Name: "web"}
	d, err := factsOnlyParse(keys)(h, "load=0.12 0.10 0.05\ncpus=4\nmem_total_mb=7962\nmem_available_mb=5120\n"+
		"disk_root_total_gb=78\ndisk_root_used_pct=63\ndisk=/dev/sda1\t81264764\t51086560\t30161820\t63\t/\n")
	if err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(d)
	want := `{"cpus":4,"disk_root_total_gb":78,"disk_root_used_pct":63,"disks":[{"mount":"/","device":"/dev/sda1","size_mb":79360,"used_mb":49889,"avail_mb":29454,"used_pct":63}],"load":[0.12,0.1,0.05],"mem_available_mb":5120,"mem_total_mb":7962,"swap_free_mb":null,"swap_total_mb":null}`
	if string(b) != want {
		t.Errorf("got  %s\nwant %s", b, want)
	}
	// one section: only its keys
	_, keys, _ = factsOnly([]string{"load"})
	d, _ = factsOnlyParse(keys)(h, "load=1 2 3\ncpus=2\nmem_total_mb=1\n")
	m := d.(map[string]any)
	got := []string{}
	for k := range m {
		got = append(got, k)
	}
	slices.Sort(got)
	if !slices.Equal(got, []string{"cpus", "load"}) {
		t.Errorf("load only: %v", got)
	}
	if _, _, err := factsOnly([]string{"load", "cpu"}); err == nil || toErr(err).Code != "USAGE" || !strings.Contains(toErr(err).Hint, "disks, load, mem, system") {
		t.Errorf("unknown section: %+v", toErr(err))
	}
	_ = time.Now
}

// The system section gives what an overview shows of the machine itself:
// the OS name and how long it has been up, from /etc/os-release and
// /proc/uptime only (C103).
func TestFactsOnlySystem(t *testing.T) {
	script, keys, err := factsOnly([]string{"system"})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"/etc/os-release", "/proc/uptime"} {
		if !strings.Contains(script, want) {
			t.Errorf("script lacks %s", want)
		}
	}
	for _, heavy := range []string{"apt-get", "docker", "systemctl", "sudo", "pro "} {
		if strings.Contains(script, heavy) {
			t.Errorf("script runs %s", heavy)
		}
	}
	d, err := factsOnlyParse(keys)(&store.Host{Name: "web"}, "os=ubuntu\nos_version=24.04\nos_pretty=Ubuntu 24.04.1 LTS\nuptime_sec=86400\ncpus=4\n")
	if err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(d)
	if want := `{"os":"ubuntu","os_pretty":"Ubuntu 24.04.1 LTS","os_version":"24.04","uptime_sec":86400}`; string(b) != want {
		t.Errorf("got  %s\nwant %s", b, want)
	}
}

func TestFactsOnlyCommand(t *testing.T) {
	invHome(t)
	mustRun(t, "host", "add", "web", "u@10.0.0.5")
	tcl.flags.dryRun = true
	d := mustRun(t, "facts", "web", "--only", "load,mem,disks", "--dry-run")
	tcl.flags.dryRun = false
	if run, _ := d["would_run"].(string); !strings.Contains(run, "/proc/loadavg") || strings.Contains(run, "apt-get") {
		t.Errorf("would_run %q", run)
	}
	if e := wantCode(t, "USAGE", "facts", "web", "--only", "ports"); !strings.Contains(e.Hint, "disks, load, mem") {
		t.Errorf("hint %q", e.Hint)
	}
	// a phone's read key without --network may poll it
	gateInventory(t)
	if got := gateKeyAnswer(t, "facts web --only load,mem,disks -o json", readKey); got != "" {
		t.Errorf("read key: %q", got)
	}
}
