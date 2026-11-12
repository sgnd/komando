package cli

import (
	"slices"
	"testing"
)

// TestTargetKinds: the TARGET question says which kinds the command picks,
// and Tab offers only those (S-4.2, C-A04).
func TestTargetKinds(t *testing.T) {
	invHome(t)
	mustRun(t, "host", "add", "web1", "root@10.0.0.5")
	mustRun(t, "conn", "add", "app-db", "postgres://app@10.0.0.9/app")
	mustRun(t, "conn", "add", "prod-k8s", "kubernetes://10.0.0.20:6443")
	root := newRoot()
	for line, want := range map[string]string{
		"exec": "Target (servers)", "svc restart": "Target (servers)", "cluster status": "Target (clusters)",
		"upload": "Target (servers or file storage)", "conn rm": "Target (conns)", "test": "Target",
	} {
		c, _, err := root.Find(shellWords(line))
		if err != nil {
			t.Fatal(err)
		}
		sp := formCmdSpec(c)
		if len(sp.qs) == 0 || sp.qs[0].label != want {
			t.Errorf("%s: label %q, want %q", line, sp.qs[0].label, want)
		}
	}
	c, _, _ := root.Find([]string{"exec"})
	got, _ := c.ValidArgsFunction(c, nil, "")
	if !slices.Contains(got, "web1") || slices.Contains(got, "app-db") || !slices.Contains(got, "all") {
		t.Errorf("exec <TAB>: %v", got)
	}
	c, _, _ = root.Find([]string{"cluster", "status"})
	got, _ = c.ValidArgsFunction(c, nil, "")
	if slices.Contains(got, "web1") || slices.Contains(got, "app-db") {
		t.Errorf("cluster status <TAB>: %v", got)
	}
	c, _, _ = root.Find([]string{"fs", "cat"})
	got, _ = c.ValidArgsFunction(c, nil, "")
	if !slices.Contains(got, "web1") || slices.Contains(got, "app-db") {
		t.Errorf("fs cat <TAB> (SERVER): %v", got)
	}
}
