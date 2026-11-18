package cli

import (
	"fmt"
	"path"
	"sort"
	"strings"

	"github.com/sgnd/komando/internal/out"
)

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
func emptiedFolders(src, dst map[string]syncFile, acts []syncAction) []emptiedFolder {
	listed := map[string]bool{} // every folder the source has a file under
	for rel := range src {
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
func guardEmptied(cl *call, found []emptiedFolder, named []string, srcName, dstName string) error {
	byPath := map[string]bool{}
	for _, f := range found {
		byPath[f.Path] = true
	}
	ok := map[string]bool{}
	for _, n := range named {
		p := strings.Trim(path.Clean("/"+strings.TrimSpace(n)), "/")
		if !byPath[p] {
			return out.Usage("--emptied %s: this sync empties no folder by that name (folders are named from the top of the sync, as the error lists them)", n)
		}
		ok[p] = true
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
	files := fmt.Sprintf("%d file%s", total, plural(total))
	what := fmt.Sprintf("%s lists no files in %s, so --delete would remove %s there in %s",
		srcName, joinAnd(names), files, dstName)
	switch {
	case cl.isAgent():
		if cl.dangerOK(what) {
			return nil
		}
	case cl.interactive():
		if confirmDangerous(cl, names, what+" (a listing cut short looks like this)") {
			return nil
		}
	}
	return cl.policyStop(emptiedErr(cl, left, srcName, joinAnd(names), files, dstName))
}

// emptiedErr is EMPTY_FOLDER_CONFIRM_REQUIRED. An agent's hint is the one
// approval hint (--allow-dangerous, then the window); a script's names
// --emptied, which no other flag replaces.
func emptiedErr(cl *call, left []emptiedFolder, src, folders, files, dst string) *out.Error {
	const code = "EMPTY_FOLDER_CONFIRM_REQUIRED"
	var e *out.Error
	if cl.isAgent() {
		e = out.Errf(out.ExitPolicy, code, "", "%s lists no files in %s, so --delete would remove %s there in %s; nothing was deleted", src, folders, files, dst)
		e.Hint = approvalText(cl, e.Flags(), true, cl.flags.dryRun)
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
