package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sgnd/komando/internal/kube"
	"github.com/sgnd/komando/internal/store"
	"github.com/sgnd/komando/internal/vault"
)

// blocked is the stop a dry run reports in meta.would_be_blocked, or nil.
func blocked(d map[string]any) map[string]any {
	meta, _ := d["_meta"].(map[string]any)
	wb, _ := meta["would_be_blocked"].(map[string]any)
	return wb
}

// A kubeconfig that logs in with `aws eks get-token` or
// gke-gcloud-auth-plugin runs no program, but komando makes the token from
// this computer's AWS or Google Cloud login and sends it to the
// kubeconfig's server. An AI agent brings such a kubeconfig in, or points
// one at another server, only with a person's yes.
func TestCloudLoginKubeconfigNeedsAPerson(t *testing.T) {
	for name, plugin := range map[string]string{
		"gke": "    exec:\n      apiVersion: client.authentication.k8s.io/v1beta1\n      command: gke-gcloud-auth-plugin\n",
		"eks": "    exec:\n      apiVersion: client.authentication.k8s.io/v1beta1\n      command: aws\n      args: [\"eks\", \"get-token\", \"--cluster-name\", \"prod\"]\n",
	} {
		t.Run(name, func(t *testing.T) {
			invHome(t)
			l := newLabCluster(t)
			file := l.kubeconfigFile(t, plugin)
			windows := asAgent(t, false, false)
			if _, e := cliRun(t, "import", "kubeconfig", file); e == nil || e.Code != "SAFETY_SETTING" || !strings.Contains(e.Message, "login") {
				t.Fatalf("an agent's import: %+v", e)
			}
			if d, e := cliRun(t, "--dry-run", "import", "kubeconfig", file); e != nil || blocked(d) == nil {
				t.Errorf("an agent's dry-run import reports the stop: %v %+v", d, e)
			}
			noAgent(t)
			mustRun(t, "import", "kubeconfig", file) // a person brought it in: this server gets the login
			setCallerEnv(t, "CLAUDECODE", "1")
			if d, e := cliRun(t, "--dry-run", "cluster", "exec", "prod", "pod-a", "--", "id"); e != nil || blocked(d) != nil {
				t.Errorf("an agent on the conn a person imported: %v %+v", d, e)
			}
			// the kubeconfig in the vault now names another server (an
			// agent's secret set): the person did not send the login there
			noAgent(t)
			kc, _ := vault.Get("prod-kubeconfig")
			if err := vault.Set(store.Save(), "prod-kubeconfig", strings.Replace(kc, l.srv.URL, "https://attacker.example:6443", 1)); err != nil || !strings.Contains(kc, l.srv.URL) {
				t.Fatalf("vault: %v %q", err, kc)
			}
			setCallerEnv(t, "CLAUDECODE", "1")
			if _, e := cliRun(t, "cluster", "ls", "prod", "pods"); e == nil || e.Code != "SAFETY_SETTING" || !strings.Contains(e.Message, "attacker.example") {
				t.Errorf("an agent's read sends the cloud login to a new server: %+v", e)
			}
			if d, e := cliRun(t, "--dry-run", "cluster", "exec", "prod", "pod-a", "--", "id"); e != nil || blocked(d)["code"] != "SAFETY_SETTING" {
				t.Errorf("dry run: %v %+v", d, e)
			}
			if *windows != 0 {
				t.Errorf("without --yes nobody is asked: %d windows", *windows)
			}
		})
	}
}

// tokenProgram writes a login program into dir: it prints a token, and
// appends its name, arguments and PATH to log.
func tokenProgram(t *testing.T, dir, name, log string) string {
	t.Helper()
	p := filepath.Join(dir, "mytoken")
	script := "#!/bin/sh\necho \"" + name + " $* STEER=$KOMANDO_TEST_STEER PATH=$PATH\" >> " + log + "\necho '{\"status\":{\"token\":\"t\"}}'\n"
	if err := os.WriteFile(p, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	return p
}

// The login program a person trusted for a conn is one file on this
// computer. An AI agent's command runs that file, with the PATH of the
// import, whatever PATH the agent sets on its own line; another program
// of the same name earlier in PATH gets neither the run nor the
// kubeconfig's arguments. A program file that changed since asks again.
func TestTrustedPluginIsTheProgramImported(t *testing.T) {
	unixOnly(t, "the kubeconfig's login program is a /bin/sh script")
	invHome(t)
	l := newLabCluster(t)
	real, fake := t.TempDir(), t.TempDir()
	log := filepath.Join(t.TempDir(), "runs")
	tokenProgram(t, real, "real", log)
	tokenProgram(t, fake, "fake", log)
	runs := func() string { b, _ := os.ReadFile(log); os.Remove(log); return string(b) }
	plugin := "    exec:\n      apiVersion: client.authentication.k8s.io/v1\n      command: mytoken\n      args: [\"--client-secret\", \"s3cr3t-arg\"]\n"
	personPath := real + string(os.PathListSeparator) + os.Getenv("PATH")
	t.Setenv("PATH", personPath)
	mustRun(t, "import", "kubeconfig", l.kubeconfigFile(t, plugin)) // a person
	runs()

	windows := asAgent(t, false, false)
	t.Setenv("PATH", fake+string(os.PathListSeparator)+personPath) // PATH=<dir>:$PATH komando ...
	t.Setenv("KOMANDO_TEST_STEER", "agent")                        // any variable that steers a program
	if _, e := cliRun(t, "cluster", "ls", "prod", "pods"); e != nil {
		t.Fatalf("an agent on a trusted conn: %+v", e)
	}
	got := runs()
	if strings.Contains(got, "fake") || !strings.Contains(got, "real --client-secret s3cr3t-arg STEER= ") {
		t.Errorf("the program that ran: %q", got)
	}
	if !strings.Contains(got, "PATH="+personPath+"\n") {
		t.Errorf("the program's PATH is the import's: %q", got)
	}
	if *windows != 0 {
		t.Errorf("a trusted program asked %d times", *windows)
	}

	// the trusted file is swapped (its folder is the user's to write)
	tokenProgram(t, real, "swapped", log)
	if _, e := cliRun(t, "cluster", "ls", "prod", "pods"); e == nil || e.Code != "SAFETY_SETTING" {
		t.Errorf("a changed program runs without a yes: %+v", e)
	}
	if got := runs(); got != "" {
		t.Errorf("it ran: %q", got)
	}
	// the window names the file that would run, found by the agent's PATH
	var texts []string
	saved := askOnScreen
	askOnScreen = func(_ *call, text string) (bool, bool) { texts = append(texts, text); return true, true }
	t.Cleanup(func() { askOnScreen = saved })
	if _, e := cliRun(t, "--yes", "cluster", "ls", "prod", "pods"); e != nil {
		t.Fatalf("approved: %+v", e)
	}
	if len(texts) != 1 || !strings.Contains(texts[0], filepath.Join(fake, "mytoken")) {
		t.Errorf("the window names the program file: %q", texts)
	}
	if got := runs(); !strings.Contains(got, "fake --client-secret s3cr3t-arg STEER= PATH="+fake+string(os.PathListSeparator)+"/usr/bin:") {
		t.Errorf("after a yes, the named program runs, with the system's PATH and none of the agent's variables: %q", got)
	}
	askOnScreen = saved

	// a person's own command runs what their PATH finds, as before
	noAgent(t)
	t.Setenv("PATH", personPath)
	if _, e := cliRun(t, "cluster", "ls", "prod", "pods"); e != nil || !strings.Contains(runs(), "swapped --client-secret") {
		t.Errorf("a person: %+v", e)
	}
}

// The trust covers the whole cluster block of the kubeconfig: the token
// the program prints goes to the server through the proxy and under the
// CA written there, so a change to any of them asks again.
func TestPluginTrustCoversTheClusterBlock(t *testing.T) {
	unixOnly(t, "the kubeconfig's login program is a /bin/sh script")
	invHome(t)
	l := newLabCluster(t)
	plugin := "    exec:\n      apiVersion: client.authentication.k8s.io/v1\n      command: /bin/sh\n      args: [\"-c\", \"echo '{\\\"status\\\":{\\\"token\\\":\\\"t\\\"}}'\"]\n"
	mustRun(t, "import", "kubeconfig", l.kubeconfigFile(t, plugin))
	kc, _ := vault.Get("prod-kubeconfig")
	server := "server: " + l.srv.URL
	if !strings.Contains(kc, server) {
		t.Fatalf("kubeconfig: %q", kc)
	}
	for _, line := range []string{"proxy-url: http://127.0.0.1:9", "insecure-skip-tls-verify: true", "tls-server-name: other.example", "certificate-authority-data: Zm9v"} {
		noAgent(t)
		pad := kc[strings.LastIndex(kc[:strings.Index(kc, server)], "\n")+1 : strings.Index(kc, server)]
		if err := vault.Set(store.Save(), "prod-kubeconfig", strings.Replace(kc, server, server+"\n"+pad+line, 1)); err != nil {
			t.Fatal(err)
		}
		setCallerEnv(t, "CLAUDECODE", "1")
		if d, e := cliRun(t, "--dry-run", "cluster", "exec", "prod", "pod-a", "--", "id"); e != nil || blocked(d)["code"] != "SAFETY_SETTING" {
			t.Errorf("%s: %v %+v", line, d, e)
		}
	}
	noAgent(t)
	vault.Set(store.Save(), "prod-kubeconfig", kc)
	setCallerEnv(t, "CLAUDECODE", "1")
	if d, e := cliRun(t, "--dry-run", "cluster", "exec", "prod", "pod-a", "--", "id"); e != nil || blocked(d) != nil {
		t.Errorf("unchanged: %v %+v", d, e)
	}
}

// An import an AI agent made with a person's yes trusts nothing for later:
// the program and its helpers were found by the agent's PATH, which the
// window did not show.
func TestAgentImportIsNotTrusted(t *testing.T) {
	unixOnly(t, "the kubeconfig's login program is a /bin/sh script")
	invHome(t)
	l := newLabCluster(t)
	dir := t.TempDir()
	log := filepath.Join(t.TempDir(), "runs")
	tokenProgram(t, dir, "prog", log)
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	plugin := "    exec:\n      apiVersion: client.authentication.k8s.io/v1\n      command: mytoken\n"
	asAgent(t, true, true)
	if _, e := cliRun(t, "--yes", "import", "kubeconfig", l.kubeconfigFile(t, plugin)); e != nil {
		t.Fatalf("approved import: %+v", e)
	}
	st, err := loadState()
	if err != nil {
		t.Fatal(err)
	}
	if c := st.Conns["prod"]; c == nil || c.TrustedPlugin+c.PluginProgram+c.PluginSearchPath != "" {
		t.Errorf("the agent's import left trust: %+v", c)
	}
	asAgent(t, false, false)
	if _, e := cliRun(t, "cluster", "ls", "prod", "pods"); e == nil || e.Code != "SAFETY_SETTING" {
		t.Errorf("the agent's next command: %+v", e)
	}
}

// The trust keeps each word of the plugin apart, and names the file.
func TestPluginTrustInput(t *testing.T) {
	c := kube.Cluster{Server: "https://10.0.0.1:6443"}
	one, _ := pluginTrust(tcl, &kube.ExecAuth{Command: "/bin/sh", Args: []string{"--a b"}}, "/bin/sh", c)
	two, _ := pluginTrust(tcl, &kube.ExecAuth{Command: "/bin/sh", Args: []string{"--a", "b"}}, "/bin/sh", c)
	if one == two || one == "" {
		t.Errorf("one argument and two hash the same: %s", one)
	}
	if _, ok := pluginTrust(tcl, &kube.ExecAuth{Command: "x"}, filepath.Join(t.TempDir(), "gone"), c); ok {
		t.Error("a program file that is not there is trusted")
	}
}
