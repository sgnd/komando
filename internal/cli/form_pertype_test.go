package cli

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/sgnd/komando/internal/capability"
	"github.com/sgnd/komando/internal/driver"
	"github.com/sgnd/komando/internal/store"
)

// perTypeAdds are the add commands of the conn types that are built.
func perTypeAdds(t *testing.T) []capability.Key {
	t.Helper()
	var keys []capability.Key
	for _, l := range capability.All() {
		if l.State == capability.Built && l.Key.Verb == "add" && l.Key.Area == "" && slices.Contains(connTypes, l.Key.Type) {
			keys = append(keys, l.Key)
		}
	}
	if len(keys) == 0 {
		t.Fatal("no per-type add in the table")
	}
	return keys
}

// Every per-type add typed alone at a terminal asks its provider's own
// questions: one group, with the form of that kind only.
func TestPerTypeAddOpensItsForm(t *testing.T) {
	root := newRoot(tcl)
	for _, k := range perTypeAdds(t) {
		cmd := cmdByKey(root, k.String())
		if cmd == nil {
			t.Errorf("%s: not a command", k)
			continue
		}
		if !formAddCmd(cmd) {
			t.Errorf("%s: typed alone it asks no form", k)
			continue
		}
		// a registry has one add for every login a registry takes
		if gs := formAddGroups(cmd); len(gs) != 1 || len(gs[0].kinds) == 0 || (len(gs[0].kinds) != 1 && k.Type != "registry") {
			t.Errorf("%s: %d groups, want one group with the form of its kind", k, len(gs))
		}
	}
}

// `komando database postgres add` alone asks the PostgreSQL questions, the
// name first, not the bare NAME of the command.
func TestPerTypeAddAsksTheKindQuestions(t *testing.T) {
	invHome(t)
	saved := promptable
	promptable = func(*call, string) bool { return true }
	defer func() { promptable = saved }()
	drawn := promptFake(t) // Ctrl-C at the first question
	if _, err := promptFill(tcl, []string{"database", "postgres", "add"}); err == nil {
		t.Fatalf("a bare add ran\n%s", drawn)
	}
	if !strings.Contains(drawn.String(), "Name, like app-db: ") || strings.Contains(drawn.String(), "NAME: ") {
		t.Errorf("not the PostgreSQL form:\n%s", drawn)
	}
}

// formSampleLines builds the lines of one kind's form from sample answers.
func formSampleLines(st *store.State, sp formSpec) [][]string {
	a := formAnswers{}
	for _, q := range sp.qs {
		if q.visible(st, a) {
			a[q.key] = formSample(st, q, a)
		}
	}
	return sp.build(st, a)
}

// What an add form builds is the add of the URL's own type and provider,
// never the conn group, and the URL is that provider's.
func TestFormAddBuildsThePerTypePath(t *testing.T) {
	st := &store.State{Hosts: map[string]*store.Host{}}
	for _, g := range formGroups(tcl) {
		if g.label == "Server" || g.label == "VPN" {
			continue
		}
		for _, k := range g.kinds {
			line := formSampleLines(st, k.spec(tcl))[0]
			if !slices.Contains(connTypes, line[0]) {
				continue // a server, a swarm manager, an import
			}
			if len(line) < 5 {
				t.Errorf("%s/%s: `komando %s`", g.label, k.label, pickCommandLine(line))
				continue
			}
			if want := entryWordsOfURL(line[4]); !slices.Equal(line[:3], append(slices.Clone(want), "add")) {
				t.Errorf("%s/%s: `komando %s`, want %v add", g.label, k.label, pickCommandLine(line), want)
			}
			if _, err := driver.Parse(line[4]); err != nil {
				t.Errorf("%s/%s: URL %q: %v", g.label, k.label, line[4], err)
			}
		}
	}
}

// A saved secret is named with --credential, never --password-ref, and a
// file path is never a reference (the store refuses file: since format 3).
func TestFormAddNamesSecretsWithCredential(t *testing.T) {
	invHome(t)
	saveSecrets(t, "a-key")
	st := &store.State{Hosts: map[string]*store.Host{}}
	for _, g := range formGroups(tcl) {
		for _, k := range g.kinds {
			sp := k.spec(tcl)
			for _, q := range sp.qs {
				if q.choices == nil {
					continue
				}
				for _, row := range q.choices(st, formAnswers{}) {
					a := formAnswers{}
					for _, qq := range sp.qs {
						switch {
						case qq.key == q.key:
							a[qq.key] = row.value
						case qq.key == "secret":
							a[qq.key] = "a-key"
						case qq.visible(st, a):
							a[qq.key] = formSample(st, qq, a)
						}
					}
					for _, line := range sp.build(st, a) {
						for _, w := range line {
							if w == "--password-ref" || strings.HasPrefix(w, "file:") || strings.HasPrefix(w, "credential:a-key") && !strings.Contains(w, "?") {
								t.Errorf("%s/%s %s=%s: `komando %s`", g.label, k.label, q.key, row.value, pickCommandLine(line))
							}
						}
					}
				}
			}
		}
	}
}

// writeKubeconfig writes a kubeconfig with one cluster, called name.
func writeKubeconfig(t *testing.T, name string) string {
	t.Helper()
	kc := "apiVersion: v1\nkind: Config\ncurrent-context: " + name + "\nclusters:\n- name: " + name +
		"\n  cluster:\n    server: https://k.example.com\nusers:\n- name: " + name + "\n  user:\n    token: test-token-abcdef\n" +
		"contexts:\n- name: " + name + "\n  context: {cluster: " + name + ", user: " + name + "}\n"
	p := filepath.Join(t.TempDir(), "kubeconfig")
	if err := os.WriteFile(p, []byte(kc), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// The cluster form protects what it imported with the cluster's own edit.
func TestKubeconfigFormProtectsWithTheTypePath(t *testing.T) {
	invHome(t)
	st := &store.State{Hosts: map[string]*store.Host{}}
	file := writeKubeconfig(t, "prod")
	cmds := kubeconfigBuild(st, formAnswers{"file": file, "protected": "yes"})
	var edits int
	for _, c := range cmds {
		if slices.Contains(c, "--protected") {
			edits++
			if !slices.Equal(c[:3], []string{"cluster", "kubernetes", "edit"}) {
				t.Errorf("`komando %s`", pickCommandLine(c))
			}
		}
	}
	if edits == 0 {
		t.Errorf("no edit built: %v", cmds)
	}
}

// The commands the kubeconfig form builds, run as the form runs them: a
// cluster answered protected=yes ends protected (the cut audit, item 2).
func TestKubeconfigFormEndsProtected(t *testing.T) {
	invHome(t)
	file := writeKubeconfig(t, "prod")
	cmds := kubeconfigBuild(&store.State{Hosts: map[string]*store.Host{}}, formAnswers{"file": file, "protected": "yes"})
	for _, c := range cmds {
		if c[0] == "test" { // only reaches the port
			continue
		}
		if _, e := cliRun(t, c...); e != nil {
			t.Fatalf("`komando %s`: %s: %s", pickCommandLine(c), e.Code, e.Message)
		}
	}
	st, err := loadState()
	if err != nil {
		t.Fatal(err)
	}
	if c := st.Conns["prod"]; c == nil || !c.Protected {
		t.Errorf("the cluster is not protected: %+v", c)
	}
}

// A failed add names the entry's own remove, as the form's add made it.
func TestFormRemoveCmdFollowsTheAdd(t *testing.T) {
	for _, c := range []struct{ add, want string }{
		{"database postgres add app-db postgres://app@h/app", "database postgres remove app-db"},
		{"storage s3 add media s3://b", "storage s3 remove media"},
		{"host ssh add web1 root@10.0.0.5", "host ssh remove web1"},
		{"host winrm add win1 winrm://u@10.0.0.9", "host winrm remove win1"},
		{"vpn wireguard add office", "vpn wireguard remove office"},
	} {
		got := formRemoveCmd([][]string{strings.Fields(c.add), {"test", "x"}})
		if strings.Join(got, " ") != c.want {
			t.Errorf("%s: %q, want %q", c.add, strings.Join(got, " "), c.want)
		}
	}
	if got := formRemoveCmd([][]string{{"import", "kubeconfig", "f"}, {"test", "x"}}); got != nil {
		t.Errorf("an import has no remove: %v", got)
	}
}

// A question about several entries names them in the plural a person says.
func TestEntryQuestionsUseTheRightPlural(t *testing.T) {
	for noun, want := range map[string]string{"registry": "registries", "cache": "caches", "database": "databases", "queue": "queues"} {
		if got := formPlural(noun); got != want {
			t.Errorf("%s: %q, want %q", noun, got, want)
		}
	}
	h, ok := hintOf("registry oci remove")
	if !ok || len(h.args) == 0 || !strings.Contains(h.args[0].ask, "registries") {
		t.Errorf("registry oci remove asks %+v", h.args)
	}
}
