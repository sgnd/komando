package cli

import (
	"strings"

	"github.com/sgnd/komando/internal/store"
)

// The approval window's language: the approval_language setting (auto,
// en or id). auto is id when the system language is Indonesian, else en.

// approvalLang is the language of the next window; TestMain keeps tests
// in English whatever the machine says.
var approvalLang = resolveApprovalLang

func resolveApprovalLang(cl *call) string {
	setting := ""
	if st, err := store.Load(); err == nil {
		setting = st.Settings.ApprovalLanguage
	}
	if setting == "en" || setting == "id" {
		return setting
	}
	getenv := func(string) string { return "" }
	if cl != nil {
		getenv = cl.getenv
	}
	return pickApprovalLang(setting, systemLanguage(getenv))
}

// pickApprovalLang is en or id for a setting and a system language tag
// ("id", "id-ID", "id_ID.UTF-8").
func pickApprovalLang(setting, system string) string {
	if setting == "en" || setting == "id" {
		return setting
	}
	s := strings.ToLower(system)
	if rest, ok := strings.CutPrefix(s, "id"); ok && (rest == "" || strings.ContainsRune("-_.@", rune(rest[0]))) {
		return "id"
	}
	return "en"
}

// envLang is the language the environment names: LC_ALL, then
// LC_MESSAGES, then LANG, as POSIX reads them. C and POSIX name none.
func envLang(getenv func(string) string) string {
	for _, k := range []string{"LC_ALL", "LC_MESSAGES", "LANG"} {
		if v := getenv(k); v != "" && v != "C" && v != "POSIX" && !strings.HasPrefix(v, "C.") {
			return v
		}
	}
	return ""
}

// firstAppleLanguage is the first entry of `defaults read -g
// AppleLanguages`, a list like ("id-ID", "en-US").
func firstAppleLanguage(out []byte) string {
	_, rest, ok := strings.Cut(string(out), "\"")
	if !ok {
		return ""
	}
	lang, _, ok := strings.Cut(rest, "\"")
	if !ok {
		return ""
	}
	return lang
}

// approvalLanguages is what the approval_language setting takes.
var approvalLanguages = []string{"auto", "en", "id"}
