package cli

import (
	"fmt"
	"path"
	"sort"
	"strings"
	"sync"

	"github.com/sgnd/komando/internal/cli/kit/term"
	"github.com/sgnd/komando/internal/out"
)

// guardDelete: --delete removes files for good, like `storage rm`. A person
// at the terminal confirms by typing the destination.
// Under --dry-run the stop goes to meta.would_be_blocked.
func guardDelete(cl *call, o syncOpts, dst string) error {
	if o.delete && !cl.dangerOK() && !confirmDangerous(cl, []string{dst}, "deletes the files in "+dst+" that the source does not have (--delete)") {
		return cl.policyStop(approvalErr(cl, "POLICY_BLOCKED",
			"--delete removes files in the destination that the source does not have"))
	}
	return nil
}

// excluded matches a path, or any of its folders, against the patterns
// (shell globs: *.log, node_modules, .git).
func excluded(rel string, patterns []string) bool {
	parts := strings.Split(rel, "/")
	for _, p := range patterns {
		if ok, _ := path.Match(p, rel); ok {
			return true
		}
		for _, part := range parts {
			if ok, _ := path.Match(p, part); ok {
				return true
			}
		}
	}
	return false
}

// emptiedFolder is a destination folder that sync --delete would empty
// because the source lists no files in it (C124). A listing cut short
// looks like that, so sync asks before deleting.
type emptiedFolder struct {
	Path  string `json:"path"`
	Files int    `json:"files"` // files --delete would remove under it
}

// emptiedFolders names each destination folder whose files the plan
// deletes while the source lists nothing under it: the top folder of an
// emptied subtree, once. Files at the top of the sync are never named
// (SOURCE_EMPTY covers a source with no files at all).
func emptiedFolders(src, dst map[string]syncFile, acts []syncAction, exclude []string) []emptiedFolder {
	listed := map[string]bool{} // every folder the source has a file to sync under
	for rel, f := range src {
		if f.Skip || excluded(rel, exclude) {
			continue // a link or an excluded file does not show the folder was listed whole
		}
		for d := path.Dir(rel); d != "."; d = path.Dir(d) {
			listed[d] = true
		}
	}
	count := map[string]int{}
	for _, a := range acts {
		if a.Op != "delete" {
			continue
		}
		parts := strings.Split(a.Path, "/")
		for i := 1; i < len(parts); i++ {
			if d := strings.Join(parts[:i], "/"); !listed[d] {
				count[d]++
				break
			}
		}
	}
	var found []emptiedFolder
	for d, n := range count {
		found = append(found, emptiedFolder{d, n})
	}
	sort.Slice(found, func(i, j int) bool { return found[i].Path < found[j].Path })
	return found
}

// guardEmptied stops sync --delete before it empties a folder the source
// lists as empty, unless the run says it means it: a person types the
// folder, an AI agent's person allows it in the window (--allow-dangerous),
// a script names each folder with --emptied. --allow-dangerous alone does
// not do for a script: an unattended run is the one that loses files
// without anyone seeing.
func guardEmptied(cl *call, found []emptiedFolder, named []string, multi bool, srcName, dstName string) error {
	byPath := map[string]bool{}
	for _, f := range found {
		byPath[f.Path] = true
	}
	ok := map[string]bool{}
	for _, n := range named {
		p := emptiedName(n)
		if !byPath[p] && !multi {
			return out.Usage("--emptied %s: this sync empties no folder by that name (folders are named from the top of the sync, as the error lists them)", n)
		}
		ok[p] = true // on several servers a folder may be gone on some already
	}
	var left []emptiedFolder
	var names []string
	total := 0
	for _, f := range found {
		if !ok[f.Path] {
			left = append(left, f)
			names = append(names, f.Path)
			total += f.Files
		}
	}
	if len(left) == 0 {
		return nil
	}
	files := fmt.Sprintf("%d file%s", total, term.Plural(total))
	what := fmt.Sprintf("%s lists no files in %s, so --delete would remove %s there in %s",
		srcName, term.JoinAnd(names), files, dstName)
	switch {
	case cl.isAgent():
		if cl.dangerOK(what) {
			return nil
		}
	case cl.interactive():
		if askEmptied(cl, names, what) {
			return nil
		}
	}
	return cl.policyStop(emptiedErr(cl, left, srcName, term.JoinAnd(names), files, dstName))
}

// emptiedName is a folder as --emptied names it, cleaned; "" for none.
func emptiedName(n string) string {
	return strings.Trim(path.Clean("/"+strings.TrimSpace(strings.ReplaceAll(n, "\\", "/"))), "/")
}

// checkEmptied refuses --emptied before anything is listed: it goes with
// --delete, and names a folder (not the top of the sync).
func checkEmptied(o syncOpts) error {
	if len(o.emptied) > 0 && !o.delete {
		return out.Usage("--emptied goes with --delete")
	}
	for _, n := range o.emptied {
		if emptiedName(n) == "" {
			return out.Usage("--emptied %q names no folder: name a folder inside the sync, as the error lists them", n)
		}
	}
	return nil
}

// askMu: a sync to several servers plans them at once; one question at
// a time.
var askMu sync.Mutex

// askEmptied asks the person to type the folders, every time: an answer
// to another question (--delete's, another server's) never counts here,
// since this one names other files.
func askEmptied(cl *call, names []string, what string) bool {
	askMu.Lock()
	defer askMu.Unlock()
	want, shown := typedAnswer(names, "the number of folders")
	fmt.Fprintln(cl.out.Err, dangerLine(what+" (a listing cut short looks like this)"))
	ok := ask(cl, "Type "+shown+" to continue: ") == want
	cl.sess.SaidNo(!ok)
	if ok {
		ttyYes(cl, "typed "+want+": "+what)
	}
	return ok
}

// emptiedErr is EMPTY_FOLDER_CONFIRM_REQUIRED. An agent's hint is the one
// approval hint (--allow-dangerous, then the window); a script's names
// --emptied, which no other flag replaces.
func emptiedErr(cl *call, left []emptiedFolder, src, folders, files, dst string) *out.Error {
	const code = "EMPTY_FOLDER_CONFIRM_REQUIRED"
	var e *out.Error
	if cl.isAgent() {
		e = out.Errf(out.ExitPolicy, code,
			"see what would go with `komando sync SRC DST --delete --dry-run`, ask the user; once they agree, run it again with --allow-dangerous (komando then asks them in a window on their screen)",
			"%s lists no files in %s, so --delete would remove %s there in %s; nothing was deleted", src, folders, files, dst)
	} else {
		flags := make([]string, len(left))
		for i, f := range left {
			flags[i] = "--emptied " + shellQuote(f.Path)
		}
		e = out.Errf(out.ExitPolicy, code,
			"check that the source really has no files there (`komando storage list` or `komando ls`); if so, run it again with "+
				strings.Join(flags, " ")+", or remove the folder on the destination first",
			"%s lists no files in %s, so --delete would remove %s there in %s; nothing was deleted", src, folders, files, dst).NoFlag()
	}
	e.Details = map[string]any{"folders": left}
	return e
}
