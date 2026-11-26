package cli

import (
	"slices"
	"strings"
	"testing"
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
	wantKeys := []string{"load", "cpus", "mem_total_mb", "mem_available_mb", "swap_total_mb", "swap_free_mb", "disks", "disk_root_total_gb", "disk_root_used_pct"}
	if !slices.Equal(keys, wantKeys) {
		t.Errorf("keys %v, want %v", keys, wantKeys)
	}
	// one section: only its keys
	_, keys, _ = factsOnly([]string{"load"})
	if !slices.Equal(keys, []string{"load", "cpus"}) {
		t.Errorf("load only: %v", keys)
	}
	if _, _, err := factsOnly([]string{"load", "cpu"}); err == nil || toErr(err).Code != "USAGE" || !strings.Contains(toErr(err).Hint, "disks, load, mem, system") {
		t.Errorf("unknown section: %+v", toErr(err))
	}
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
	if want := []string{"os", "os_version", "os_pretty", "uptime_sec"}; !slices.Equal(keys, want) {
		t.Errorf("keys %v, want %v", keys, want)
	}
}
