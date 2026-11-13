package cli

import (
	"fmt"
	"os"
	"strings"
	"testing"
)

// The tier table in docs/features/safety.md ("What needs a yes") is made from the rule table
// (S-7.2, C-C11), so the design text, the schema's confirm and the stops
// cannot tell different stories. KOMANDO_UPDATE_TIERS=1 writes it again.
func TestTiersDoc(t *testing.T) {
	const path = "../../docs/features/safety.md"
	const start, end = "<!-- tiers: made by TestTiersDoc from risk.go; KOMANDO_UPDATE_TIERS=1 writes it -->\n", "<!-- end of tiers -->\n"
	doc, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	i, j := strings.Index(string(doc), start), strings.Index(string(doc), end)
	if i < 0 || j < i {
		t.Fatalf("safety.md has no tier table between %q and %q", start, end)
	}
	want := string(doc[:i]) + start + tiersTable() + end + string(doc[j+len(end):])
	if os.Getenv("KOMANDO_UPDATE_TIERS") != "" {
		if err := os.WriteFile(path, []byte(want), 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	if string(doc) != want {
		t.Error("the tier table in docs/features/safety.md is out of date: run KOMANDO_UPDATE_TIERS=1 go test ./internal/cli/ -run TestTiersDoc")
	}
}

// tiersTable is the tiers, then every row of the rule table.
func tiersTable() string {
	var b strings.Builder
	b.WriteString(`
| Tier | What | An AI agent or a script needs | A person at a terminal |
|---|---|---|---|
| read | looks only | nothing | nothing |
| change | can be undone, or only komando's own list | nothing | typed in full: runs; filled in: ` + "`Run it?`" + ` |
| protected | a change on a protected server, conn or VPN | ` + "`--yes`" + ` (PROTECTED_HOST, PROTECTED_TARGET) | ` + "`NAME (protected): ... Continue? [y/N]`" + ` |
| dangerous | cannot be undone, or an outage | ` + "`--allow-dangerous`" + ` (POLICY_BLOCKED) | types the name of what goes, the count, or the target |
| safety | weakens komando's own checks | ` + "`--yes`" + ` (SAFETY_SETTING, OPEN_BIND, SECRET_DESTINATION) | ` + "`This turns off a komando safety check: ... Continue? [y/N]`" + ` |
| person | only a person at a terminal | no flag: NEEDS_PERSON and friends | the command itself |

Every row of the rule table (` + "`risk.go`" + `). A command without a row has its
kind's tier: read, or change. "when the ..." rows are decided at run time.

| Command | When | Tier | Flag |
|---|---|---|---|
`)
	for _, r := range riskRows {
		when := r.cond
		switch {
		case r.bulk != "":
			when += ": " + r.bulk + " (CONFIRM_REQUIRED)"
		case r.dynamic != "" && when != "":
			when += ", when " + r.dynamic
		case r.dynamic != "":
			when = "when " + r.dynamic
		case r.typed != "":
			when = "a person types the name of what goes"
		}
		if when == "" {
			when = "always"
		}
		flag := r.tier.flag()
		if r.bulk != "" {
			flag = "--yes"
		}
		if flag != "" {
			flag = "`" + flag + "`"
		}
		fmt.Fprintf(&b, "| `%s` | %s | %s | %s |\n", strings.ReplaceAll(r.id, ".", " "), strings.ReplaceAll(when, "|", `\|`), r.tier, flag)
	}
	b.WriteString("\n")
	return b.String()
}
