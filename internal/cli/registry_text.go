package cli

import (
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/sgnd/komando/internal/registry"
)

// What a person reads from the registry commands with -o text. The JSON
// stays the map each command builds.

// lsData is `registry list`: repositories, or one repository's tags.
type lsData map[string]any

func (d lsData) Text() string {
	var b strings.Builder
	items, _ := d["repositories"].([]string)
	what := "repositories"
	if repo, ok := d["repo"].(string); ok {
		items, _ = d["tags"].([]string)
		what = "tags in " + repo
	}
	if len(items) == 0 {
		return noneYet(what, "", "an image appears here after docker push")
	}
	for _, s := range items {
		b.WriteString(s + "\n")
	}
	if d["truncated"] == true {
		fmt.Fprintf(&b, "(the first %d %s; there are more: raise -n)\n", len(items), what)
	}
	return b.String()
}

// listed is registry list's result; a person's Next: line names the
// command for one of its items (a repository's tags, a tag's details).
func listed(cl *call, m map[string]any) lsData {
	if repo, ok := m["repo"].(string); ok {
		sayNext(cl, "komando registry inspect "+fmt.Sprint(m["conn"])+" "+repo+":TAG")
	} else {
		sayNext(cl, "komando registry list "+fmt.Sprint(m["conn"])+" REPO")
	}
	return lsData(m)
}

// rmData is `registry rm`: the image, and every tag that goes with it.
type rmData map[string]any

func (d rmData) Text() string {
	var b strings.Builder
	tags, _ := d["tags"].([]string)
	if img, ok := d["would_delete"].(string); ok {
		fmt.Fprintf(&b, "would delete %s\n", img)
	} else {
		fmt.Fprintf(&b, "deleted %s\n", d["deleted"])
	}
	verb := "goes"
	if d["deleted"] != nil {
		verb = "went"
	}
	if len(tags) > 0 {
		fmt.Fprintf(&b, "with it %s every tag on that image: %s\n", verb, strings.Join(tags, ", "))
	}
	if slices.Contains(tags, "latest") {
		b.WriteString("latest is one of them: docker pull without a tag stops working\n")
	}
	if n, ok := d["tags_note"].(string); ok {
		b.WriteString(n + "\n")
	}
	if n, ok := d["note"].(string); ok {
		b.WriteString(n + "\n")
	}
	return b.String()
}

// pruneData is `registry prune`: what goes, what stays and why.
type pruneData map[string]any

func (d pruneData) Text() string {
	var b strings.Builder
	del, _ := d["delete"].([]registry.PruneImage)
	keep, _ := d["keep"].([]registry.PruneKeep)
	verb := "deleted"
	if d["dry_run"] == true {
		verb = "would delete"
	} else if done, _ := d["deleted"].([]string); len(done) < len(del) {
		verb = fmt.Sprintf("deleted %d of", len(done))
	}
	fmt.Fprintf(&b, "%s: %s %s of %s\n", d["repo"], verb, countOf(len(del), "image"), countOf(toInt(d["tags"]), "tag"))
	for _, img := range del {
		fmt.Fprintf(&b, "  - %-20s %s  %s\n", strings.Join(img.Tags, ","), timeCell(img.Created), shortDigest(img.Digest))
	}
	if len(keep) > 0 {
		fmt.Fprintf(&b, "keeps %s:\n", countOf(len(keep), "tag"))
		for _, k := range keep {
			fmt.Fprintf(&b, "  = %-20s %s\n", k.Tag, k.Reason)
		}
	}
	if n, ok := d["note"].(string); ok {
		b.WriteString(n + "\n")
	}
	return b.String()
}

func toInt(v any) int {
	n, _ := v.(int)
	return n
}

// shortDigest is sha256: and the first 12 hex digits, as docker shows it.
func shortDigest(d string) string {
	if len(d) > len("sha256:")+12 {
		return d[:len("sha256:")+12]
	}
	return d
}

// localCreated is an image's build date in the person's own time.
func localCreated(s string) string {
	t, err := time.Parse(time.RFC3339Nano, s)
	if err != nil {
		return s
	}
	return t.Local().Format("2006-01-02 15:04:05 MST")
}
