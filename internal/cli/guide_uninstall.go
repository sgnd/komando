package cli

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"

	"github.com/sgnd/komando/internal/out"
	"github.com/sgnd/komando/internal/store"
)

// guide uninstall takes out what guide install put in: the skill files and
// komando's guard entries in each agent's hooks, leaving everything else in
// those files as it is (a changed file is kept as .bak, as install does).

func guideUninstallCmd() *cobra.Command {
	var project bool
	c := &cobra.Command{
		Use:   "uninstall",
		Short: "Take the komando skill and guard out of your AI agents",
		Long: `Removes what ` + "`komando guide install`" + ` added: komando/SKILL.md in ~/.claude/skills
and ~/.agents/skills, and komando's guard entries in .claude/settings.json,
.cursor/hooks.json, .gemini/settings.json and .codex/hooks.json. Everything
else in those files stays; a changed file is kept as .bak. Taking the guard
away from an AI agent lets it read secret files on this computer again, so
an agent needs a person's yes (--yes).`,
		Example: `  komando guide uninstall             # from your home folder
  komando guide uninstall --project   # from the folder you are in
  komando guide uninstall --dry-run   # show what it would remove`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			base, err := os.UserHomeDir()
			if project {
				base, err = os.Getwd()
			}
			if err != nil {
				return out.Errf(out.ExitError, "NO_FOLDER", "set HOME, or run it from the project folder", "cannot find the folder: %v", err)
			}
			// the whole plan first: a stop for the guard must come before
			// anything is removed, the skill files too
			var files []skillFile
			for _, d := range skillDirs {
				f, err := removeSkill(filepath.Join(base, d, "komando", "SKILL.md"), true)
				if err != nil {
					return out.Errf(out.ExitError, "WRITE_FAILED", "check that you may change this folder", "%v", err)
				}
				if f.Action != "" {
					files = append(files, f)
				}
			}
			hookFiles := []string{filepath.Join(base, ".claude", "settings.json")}
			for _, h := range agentHooks {
				hookFiles = append(hookFiles, filepath.Join(base, h.dir, h.file))
			}
			var guards []skillFile
			for _, p := range hookFiles {
				f, err := removeGuard(p, true)
				if err != nil {
					return out.Errf(out.ExitError, "WRITE_FAILED", "fix the file, then run it again", "%v", err)
				}
				if f.Action == "updated" {
					guards = append(guards, f)
				}
			}
			if len(guards) > 0 { // under --dry-run the stop lands in meta.would_be_blocked
				if err := guardSafety("removing komando's guard, which keeps AI agents away from secret files on this computer"); err != nil {
					audit(nil, "guide.uninstall", nil, "", false, map[string]any{"blocked": toErr(err).Code})
					return err
				}
			}
			if !g.dryRun {
				for i := range files {
					if files[i], err = removeSkill(files[i].Path, false); err != nil {
						return out.Errf(out.ExitError, "WRITE_FAILED", "check that you may change this folder", "%v", err)
					}
				}
				for i := range guards {
					if guards[i], err = removeGuard(guards[i].Path, false); err != nil {
						return out.Errf(out.ExitError, "WRITE_FAILED", "fix the file, then run it again", "%v", err)
					}
				}
			}
			files = append(files, guards...)
			if len(files) == 0 {
				out.P.Print("guide.uninstall", skillResult{Files: []skillFile{}, uninstall: true}, nil)
				return nil
			}
			audit(nil, "guide.uninstall", nil, "", true, map[string]any{"files": len(files)})
			out.P.Print("guide.uninstall", skillResult{Files: files, uninstall: true}, nil)
			return nil
		},
	}
	c.Flags().BoolVar(&project, "project", false, "remove from the current folder instead of your home folder")
	return c
}

// removeSkill deletes a skill file komando wrote (and its .bak), and the
// komando folder when nothing else is in it. Action is "" when there was
// none.
func removeSkill(path string, dryRun bool) (skillFile, error) {
	f := skillFile{Path: path}
	if _, err := os.Stat(path); errors.Is(err, fs.ErrNotExist) {
		return f, nil
	} else if err != nil {
		return f, err
	}
	f.Action = "removed"
	if dryRun {
		return f, nil
	}
	if err := os.Remove(path); err != nil {
		return f, err
	}
	_ = os.Remove(path + ".bak")
	_ = os.Remove(filepath.Dir(path)) // only when empty
	return f, nil
}

// removeGuard takes komando's guard entries out of a hooks file, keeping
// everything else. check: only say whether there is one (Action updated).
func removeGuard(path string, check bool) (skillFile, error) {
	f := skillFile{Path: path, Action: "unchanged"}
	old, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) || err == nil && len(bytes.TrimSpace(old)) == 0 {
		return f, nil
	}
	if err != nil {
		return f, err
	}
	settings := map[string]any{}
	if err := json.Unmarshal(old, &settings); err != nil {
		return f, fmt.Errorf("%s is not valid JSON, so komando left it alone: %v", path, err)
	}
	hooks, _ := settings["hooks"].(map[string]any)
	changed := false
	for ev, v := range hooks {
		l, _ := v.([]any)
		kept := withoutGuard(v)
		if len(kept) == len(l) {
			continue
		}
		changed = true
		if len(kept) == 0 {
			delete(hooks, ev)
		} else {
			hooks[ev] = kept
		}
	}
	if !changed {
		return f, nil
	}
	if len(hooks) == 0 {
		delete(settings, "hooks")
	}
	f.Action, f.Backup = "updated", path+".bak"
	if check || g.dryRun {
		return f, nil
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(settings); err != nil {
		return f, err
	}
	if err := os.WriteFile(f.Backup, old, 0o600); err != nil {
		return f, err
	}
	return f, store.WriteFileAtomic(path, buf.Bytes(), 0o600)
}
