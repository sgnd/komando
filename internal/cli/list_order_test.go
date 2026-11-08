package cli

import (
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/sgnd/komando/internal/driver"
	"github.com/sgnd/komando/internal/sshx"
	"github.com/sgnd/komando/internal/storex"
)

// Every list reads by name, whatever kinds or sources its rows come from.

// field is the key field of each row of a JSON list.
func field(t *testing.T, list any, key string) []string {
	t.Helper()
	rows, ok := list.([]any)
	if !ok {
		t.Fatalf("not a list: %#v", list)
	}
	var got []string
	for _, r := range rows {
		got = append(got, str(r.(map[string]any)[key]))
	}
	return got
}

func TestListSortsAllKindsByName(t *testing.T) {
	invHome(t)
	mustRun(t, "host", "add", "zeta", "u@10.0.0.1", "-g", "g")
	mustRun(t, "host", "add", "mid", "u@10.0.0.2", "-g", "g")
	mustRun(t, "conn", "add", "alpha", "rediss://10.0.0.3:6379", "-g", "g")
	for _, args := range [][]string{{"list"}, {"list", "@g"}, {"list", "zeta,alpha,mid"}} {
		d := mustRun(t, args...)
		if got := strings.Join(field(t, d["targets"], "name"), ","); got != "alpha,mid,zeta" {
			t.Errorf("%v: %s, want alpha,mid,zeta", args, got)
		}
	}
	if got := strings.Join(field(t, mustRun(t, "host", "list")["targets"], "name"), ","); got != "mid,zeta" {
		t.Errorf("host list: %s", got)
	}
}

func TestTestResultsSortByName(t *testing.T) {
	invHome(t)
	port := strconv.Itoa(closedPort(t))
	mustRun(t, "host", "add", "zeta", "u@127.0.0.1:"+port)
	mustRun(t, "conn", "add", "alpha", "redis://127.0.0.1:"+port)
	mustRun(t, "host", "add", "mid", "u@127.0.0.1:"+port)
	env, _, _ := runWait(t, "test", "all")
	var got []string
	for _, r := range env.Data.Results {
		got = append(got, r.Name)
	}
	if strings.Join(got, ",") != "alpha,mid,zeta" {
		t.Errorf("results: %v, want alpha,mid,zeta", got)
	}
}

func TestGroupListTextSortsGroupsAndTagsTogether(t *testing.T) {
	l := groupList{Groups: map[string][]string{"web": {"a"}, "api": {"b"}}, Tags: map[string][]string{"live": {"a"}, "api": {"a"}}}
	var got []string
	for _, line := range strings.Split(strings.TrimSpace(l.Text()), "\n")[1:] {
		got = append(got, strings.Fields(line)[0])
	}
	if strings.Join(got, " ") != "@api tag:api tag:live @web" {
		t.Errorf("rows: %v", got)
	}
}

func TestRecipeListSortsSavedAmongBuiltins(t *testing.T) {
	invHome(t)
	mustRun(t, "recipe", "add", "zzz-mine", "uptime", "--read-only")
	mustRun(t, "recipe", "add", "aaa-mine", "uptime", "--read-only")
	got := field(t, mustRun(t, "recipe", "list")["recipes"], "name")
	if !sort.StringsAreSorted(got) || got[0] != "aaa-mine" || got[len(got)-1] != "zzz-mine" {
		t.Errorf("recipes: %v", got)
	}
}

func TestPolicyListSortsRulesByID(t *testing.T) {
	invHome(t)
	d := mustRun(t, "policy", "list")
	for _, k := range []string{"builtin", "sql", "redis", "memcached", "data"} {
		if got := field(t, d[k], "id"); len(got) == 0 || !sort.StringsAreSorted(got) {
			t.Errorf("%s rules: %v", k, got)
		}
	}
	if got := rulesByID([]driver.Rule{{ID: "b"}, {ID: "a"}}); got[0].ID != "a" {
		t.Errorf("rulesByID: %v", got)
	}
}

func TestServerListsSortByName(t *testing.T) {
	svc, _ := svcListResult(&sshx.RunResult{Stdout: "z.service loaded active running Z\na.service loaded failed failed A\n"})
	if rows := svc.([]map[string]string); rows[0]["unit"] != "a.service" || rows[1]["unit"] != "z.service" {
		t.Errorf("svc list: %v", rows)
	}

	ps, err := dockerTable([]string{"name"}, []string{"Names"}, "Names")(nil, `{"Names":"web"}`+"\n"+`{"Names":"api"}`)
	if err != nil || strings.Join(field(t, ps, "Names"), ",") != "api,web" {
		t.Errorf("docker ps: %v %v", ps, err)
	}
	images, _ := dockerTable([]string{"repository", "tag"}, []string{"Repository", "Tag"}, "Repository", "Tag")(nil,
		`{"Repository":"b","Tag":"1"}`+"\n"+`{"Repository":"a","Tag":"2"}`+"\n"+`{"Repository":"a","Tag":"1"}`+"\n"+`{"Repository":"ab","Tag":"0"}`)
	var got []string
	for _, r := range images.([]any) {
		m := r.(map[string]any)
		got = append(got, str(m["Repository"])+":"+str(m["Tag"]))
	}
	if strings.Join(got, ",") != "a:1,a:2,ab:0,b:1" {
		t.Errorf("docker images: %v", got)
	}
}

// fs ls and storage ls on SFTP: a server sends a folder in any order.
func TestSFTPListingsSortByName(t *testing.T) {
	dir := t.TempDir()
	for _, f := range []string{"c", "b/z", "a", "b/y"} {
		p := filepath.Join(dir, f)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, nil, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	sc := localSFTP(t)
	fis, err := storex.SortedReadDir(sc, dir)
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, fi := range fis {
		got = append(got, fi.Name())
	}
	if strings.Join(got, ",") != "a,b,c" {
		t.Errorf("read dir: %v", got)
	}
	got = nil
	for w := storex.SortedWalk(sc, dir); w.Step(); {
		if w.Path() != dir {
			got = append(got, strings.TrimPrefix(w.Path(), dir+"/"))
		}
	}
	if strings.Join(got, ",") != "a,b,b/y,b/z,c" {
		t.Errorf("walk: %v", got)
	}
}
