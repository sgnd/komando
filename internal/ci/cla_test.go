// Package ci tests the scripts inside the GitHub workflows.
package ci

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

const sentence = "I have read the CLA Document and I hereby sign the CLA"

// claScript returns the run block of the CLA workflow's check step.
func claScript(t *testing.T) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "..", ".github", "workflows", "cla.yml"))
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(string(b), "\n")
	var out []string
	in := false
	indent := ""
	for _, l := range lines {
		if !in {
			if strings.TrimSpace(l) == "run: |" {
				in = true
				indent = l[:strings.Index(l, "run")] + "  "
			}
			continue
		}
		if strings.TrimSpace(l) != "" && !strings.HasPrefix(l, indent) {
			break
		}
		out = append(out, strings.TrimPrefix(l, indent))
	}
	if len(out) == 0 {
		t.Fatal("no run block in cla.yml")
	}
	return strings.Join(out, "\n")
}

// check runs the script with a fake gh that lists the given commit authors.
func check(t *testing.T, opener, body string, authors ...string) bool {
	t.Helper()
	return checkC(t, opener, body, nil, authors...)
}

// checkC is check with PR comments that hold the sentence, by login.
func checkC(t *testing.T, opener, body string, commenters []string, authors ...string) bool {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("shell script")
	}
	bin := t.TempDir()
	fake := "#!/bin/sh\ncase \"$*\" in\n*/comments*) printf '%s\\n' " + quoteAll(commenters) + " ;;\n*) printf '%s\\n' " + quoteAll(authors) + " ;;\nesac\n"
	if err := os.WriteFile(filepath.Join(bin, "gh"), []byte(fake), 0o700); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("bash", "-e", "-c", claScript(t))
	cmd.Env = append(os.Environ(), "PATH="+bin+":"+os.Getenv("PATH"),
		"AUTHOR="+opener, "BODY="+body, "REPO=o/r", "PR=7", "GH_TOKEN=fake")
	err := cmd.Run()
	return err == nil
}

func quoteAll(xs []string) string {
	var q []string
	for _, x := range xs {
		q = append(q, "'"+strings.ReplaceAll(x, "'", `'\''`)+"'")
	}
	if len(q) == 0 {
		return "''"
	}
	return strings.Join(q, " ")
}

// MEDIUM 1: the untouched template must not pass.
func TestTemplateAloneDoesNotSign(t *testing.T) {
	tpl, err := os.ReadFile(filepath.Join("..", "..", ".github", "pull_request_template.md"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(tpl), sentence) {
		t.Fatal("the template holds the CLA sentence, so an untouched template signs")
	}
	if check(t, "alice", string(tpl), "alice") {
		t.Fatal("an untouched template passed the check")
	}
}

func TestOpenerSigns(t *testing.T) {
	if !check(t, "alice", "Fixes a typo.\n\n"+sentence+"\n", "alice") {
		t.Fatal("a signed PR failed")
	}
	if check(t, "alice", "Fixes a typo.", "alice") {
		t.Fatal("an unsigned PR passed")
	}
	if check(t, "alice", "I have not read the CLA Document and I hereby sign the CLA", "alice") {
		t.Fatal("a changed sentence passed")
	}
}

// MEDIUM 2a: every commit author signs, not only the opener.
func TestEveryCommitAuthorSigns(t *testing.T) {
	body := sentence + "\n"
	if check(t, "alice", body, "alice", "bob") {
		t.Fatal("a commit by an unsigned second author passed")
	}
	if !checkC(t, "alice", body, []string{"bob"}, "alice", "bob") {
		t.Fatal("a second author who signed in their own comment failed")
	}
	if check(t, "alice", body, "alice", "unknown") {
		t.Fatal("a commit with no GitHub account passed")
	}
	if !check(t, "alice", body, "alice", "dependabot[bot]", "sgnd") {
		t.Fatal("exempt authors failed")
	}
	if check(t, "sgnd", "", "sgnd", "carol") {
		t.Fatal("an exempt opener let an unsigned author through")
	}
	if !check(t, "sgnd", "", "sgnd") {
		t.Fatal("the owner's own PR failed")
	}
}

// Audit: a co-author signs in their own comment, not in a line the opener typed.
func TestCoAuthorSignsInOwnComment(t *testing.T) {
	body := sentence + "\n@bob " + sentence + "\n"
	if check(t, "alice", body, "alice", "bob") {
		t.Fatal("the opener signed for bob in the description")
	}
	if !checkC(t, "alice", sentence+"\n", []string{"bob"}, "alice", "bob") {
		t.Fatal("bob's own comment did not count")
	}
	if checkC(t, "alice", sentence+"\n", []string{"alice"}, "alice", "bob") {
		t.Fatal("a comment by the opener counted for bob")
	}
}
