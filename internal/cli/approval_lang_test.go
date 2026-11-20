package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sgnd/komando/internal/policy"
	"github.com/sgnd/komando/internal/store"
)

// approval_language picks the window's words: en and id as set, auto from
// the system language (id when it starts with "id", else en).
func TestApprovalLangPick(t *testing.T) {
	for _, c := range []struct{ setting, system, want string }{
		{"en", "id", "en"},
		{"id", "en", "id"},
		{"auto", "id", "id"},
		{"auto", "id-ID", "id"},
		{"auto", "ID", "id"},
		{"", "id", "id"}, // an older store: auto
		{"auto", "en", "en"},
		{"auto", "", "en"},
		{"auto", "it", "en"},
		{"auto", "ind", "en"},
		{"auto", "ido", "en"},
		{"auto", "id_ID.UTF-8", "id"},
	} {
		if got := pickApprovalLang(c.setting, c.system); got != c.want {
			t.Errorf("setting %q, system %q: %q, want %q", c.setting, c.system, got, c.want)
		}
	}
}

// On macOS and Linux the system language comes from LC_ALL, then
// LC_MESSAGES, then LANG; C and POSIX name no language.
func TestApprovalEnvLang(t *testing.T) {
	for _, c := range []struct {
		env  map[string]string
		want string
	}{
		{map[string]string{"LANG": "id_ID.UTF-8"}, "id_ID.UTF-8"},
		{map[string]string{"LANG": "id_ID.UTF-8", "LC_ALL": "en_US.UTF-8"}, "en_US.UTF-8"},
		{map[string]string{"LANG": "en_US.UTF-8", "LC_MESSAGES": "id_ID"}, "id_ID"},
		{map[string]string{"LANG": "C"}, ""},
		{map[string]string{"LC_ALL": "POSIX", "LANG": "id_ID"}, "id_ID"},
		{nil, ""},
	} {
		if got := envLang(func(k string) string { return c.env[k] }); got != c.want {
			t.Errorf("%v: %q, want %q", c.env, got, c.want)
		}
	}
	if got := firstAppleLanguage([]byte("(\n    \"id-ID\",\n    \"en-US\"\n)\n")); got != "id-ID" {
		t.Errorf("AppleLanguages: %q", got)
	}
	if got := firstAppleLanguage([]byte("garbage")); got != "" {
		t.Errorf("AppleLanguages garbage: %q", got)
	}
}

// The setting is read from the store when a window is built.
func TestApprovalLangSetting(t *testing.T) {
	invHome(t)
	old := systemLanguage
	systemLanguage = func(func(string) string) string { return "id" }
	t.Cleanup(func() { systemLanguage = old })
	if got := resolveApprovalLang(tcl); got != "id" {
		t.Errorf("auto with an Indonesian system: %q", got)
	}
	setCallerEnv(t, "KOMANDO_AGENT", "1") // not a safety setting: no yes needed
	mustRun(t, "config", "set", "approval_language", "en")
	if got := resolveApprovalLang(tcl); got != "en" {
		t.Errorf("en: %q", got)
	}
	mustRun(t, "config", "set", "approval-language", "ID")
	st, err := store.Load()
	if err != nil || st.Settings.ApprovalLanguage != "id" {
		t.Fatalf("stored %q, %v", st.Settings.ApprovalLanguage, err)
	}
	wantCode(t, "USAGE", "config", "set", "approval_language", "fr")
}

func idView(v approvalView) approvalView { v.Lang = "id"; return v }

// An Indonesian window: every line komando writes is in Indonesian; the
// command, the script, names and the agent stay as they are.
func TestApprovalViewIndonesian(t *testing.T) {
	v := idView(testView("Codex", []string{"--allow-dangerous", "--yes"}, "", []string{"it runs on web-1.example.test (protected), db-1.example.test", "[rm-system-dir,db-drop] deletes a system folder recursively; drops a database"},
		"komando exec web-1.example.test,db-1.example.test --user deploy --allow-dangerous --yes -- rm -rf /etc/x", ""))
	if got, want := v.title(), "Jalankan perintah di 2 server"; got != want {
		t.Errorf("title %q, want %q", got, want)
	}
	want := "Diminta oleh Codex\nTarget: web-1.example.test, db-1.example.test\nStatus: Dilindungi\n" +
		"Risiko: Menghapus folder sistem secara rekursif (rm -rf)\nRisiko: Menghapus database (DROP DATABASE)\n" +
		"Melewati: pengecekan perintah berbahaya\nOpsi: --user deploy\n\nPerintah: rm -rf /etc/x"
	if got := v.details(); got != want {
		t.Errorf("details:\n%s\nwant:\n%s", got, want)
	}
	if got := v.ownerReason(); got != "komando: izinkan web-1.example.test, db-1.example.test" {
		t.Errorf("owner %q", got)
	}
	// the key of the request does not change with the language
	en := v
	en.Lang = "en"
	if v.text() != en.text() {
		t.Error("text() depends on the language")
	}
	if r := (approvalView{raw: "t", Lang: "id"}); r.title() != "komando: izinkan?" {
		t.Errorf("raw title %q", r.title())
	}
}

// Every built-in rule's reason has Indonesian words, made for that exact
// English reason; a reason that changed falls back to English.
func TestApprovalRiskWordsIndonesian(t *testing.T) {
	for _, r := range policy.Rules() {
		tr, ok := riskID[r.ID]
		if !ok {
			t.Errorf("%s: no Indonesian words", r.ID)
			continue
		}
		if tr.en != r.Reason {
			t.Errorf("%s: words made for %q, the rule now says %q", r.ID, tr.en, r.Reason)
		}
	}
	if got := riskWords("[mkfs] formats a filesystem now", "id"); got[0] != "Formats a filesystem now (mkfs)" {
		t.Errorf("changed reason: %q", got)
	}
	if got := riskWords("[mkfs] formats a filesystem", "id"); got[0] != "Memformat filesystem (mkfs)" {
		t.Errorf("id: %q", got)
	}
	if got := riskWords("[custom-ab12] my own rule", "id"); got[0] != "My own rule" {
		t.Errorf("custom: %q", got)
	}
}

// The button komando treats as Allow is found by its identifier, never
// by its label: the macOS script returns a fixed token, and a translated
// label printed back allows nothing.
func TestApprovalAllowKeyedOnIdentifier(t *testing.T) {
	args := macArgs(idView(testView("Codex", nil, "", []string{"it runs on web-1.example.test"}, "komando exec web-1.example.test -- id", "")))
	if args[10] != "komando minta persetujuan Anda" || args[11] != "Tolak" || args[12] != "Izinkan sekali" {
		t.Errorf("labels %q", args[10:])
	}
	for _, want := range []string{"buttonWithTitleTargetAction(argv[7], answer, 'deny:')", "buttonWithTitleTargetAction(argv[8], answer, 'allow:')",
		"panel.title = argv[6]", "return 'Allow once\\n' + owner(argv[3], argv[4]);"} {
		if !strings.Contains(macAlertScript, want) {
			t.Errorf("script has no %q", want)
		}
	}
	if macAnswer([]byte("Izinkan sekali\nowner ok\n")) != macDenied || macAnswer([]byte("Allow once\nowner ok\n")) != macAllowed {
		t.Error("macAnswer reads a label")
	}
}

// Golden: the Indonesian window for the cases of approval_window.txt.
func TestApprovalWindowGoldenIndonesian(t *testing.T) {
	long := "komando exec web-1.example.test -- " + strings.Repeat("echo abcdefghij && ", 12) + "true"
	views := []approvalView{
		idView(testView("Claude Code", []string{"--yes"}, "", []string{protWhy([]string{"web-1.example.test"}), "it runs on web-1.example.test (protected)"},
			"komando fs write web-1.example.test /etc/app.yaml --content $'a: 1\\nb:\\n  c: 2' --yes", "")),
		idView(testView("Codex", []string{"--allow-dangerous", "--yes"}, "", []string{"it runs on web-1.example.test (protected)", "[rm-system-dir] deletes a system folder recursively", protWhy([]string{"web-1.example.test"})}, long, "")),
		idView(testView("Claude Code", []string{"--yes"}, "the program /usr/local/bin/x", []string{"it runs on db-2.example.test"}, "komando exec db-2.example.test --script ./deploy.sh --yes",
			"It also sends the script ./deploy.sh (40 bytes, 3 lines, SHA-256 ab12), all of it:\n\n  1  #!/bin/sh\n  2  set -e\n  3  systemctl restart app\n\n")),
		idView(testView("Claude Code", []string{"--yes"}, "", []string{"it runs on web-1.example.test"}, "komando host rm web-1.example.test --yes", "")),
		idView(testView("Codex", []string{"--reveal"}, "", nil, "komando db query shop --reveal -- select 1", "")),
	}
	windowGolden(t, "approval_window_id.txt", views)
	// each Indonesian line komando writes fits the window's 60 columns
	b, err := os.ReadFile(filepath.Join("testdata", "approval_window_id.txt"))
	if err != nil {
		t.Fatal(err)
	}
	for l := range strings.SplitSeq(string(b), "\n") {
		if strings.HasPrefix(l, "Risiko:") || strings.HasPrefix(l, "Melewati:") || strings.HasPrefix(l, "Status:") {
			if n := len([]rune(l)); n > winTextCols {
				t.Errorf("%d columns: %s", n, l)
			}
		}
	}
}
