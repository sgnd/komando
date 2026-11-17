package cli

import (
	"bytes"
	"context"
	"regexp"
	"strings"

	"github.com/spf13/cobra"

	"github.com/sgnd/komando/internal/out"
	"github.com/sgnd/komando/internal/sshx"
)

// replaceEdit is one fs replace: the same edit for every server.
type replaceEdit struct {
	cl               *call // the call it works for
	path, oldS, newS string
	re               *regexp.Regexp
	all              bool
	o                writeOpts
}

// on makes the edit on one server.
func (e replaceEdit) on(ctx context.Context, c *sshx.Client) (fsChange, error) {
	sc, err := sftpClient(c)
	if err != nil {
		return nil, err
	}
	defer sc.Close()
	p := expandRemote(sc, e.path)
	b, trunc, err := readRemote(e.cl, ctx, c, sc, p, e.o.sudo, 64<<20)
	if err != nil {
		return nil, err
	}
	if trunc {
		return nil, out.Errf(out.ExitConflict, "FILE_TOO_LARGE", "for a bigger file: `komando download` it, edit it here, then `komando upload` it", "%s is larger than 64MiB, the most fs replace edits", p)
	}
	src := string(b)
	pl, err := planReplace(e.cl.out, src, e.oldS, e.newS, e.re, e.all, e.path)
	if err != nil {
		return nil, err
	}
	if !pl.changed {
		res := fsChange{"path": p, "changed": false, "replacements": pl.n}
		if pl.note != "" {
			res["note"] = pl.note
		}
		return res, nil
	}
	res := fsChange{"path": p, "changed": true, "replacements": pl.n, "diff": unifiedDiff(pl.view, pl.shown, 3)}
	if e.cl.flags.dryRun {
		delete(res, "changed")
		res["would_change"] = true
		if t, err := resolveLink(e.cl, sc, p); err == nil && t != p {
			res["followed"] = t
		}
		return res, nil
	}
	w, err := writeRemote(e.cl, ctx, c, sc, p, []byte(pl.updated), e.o)
	if err != nil {
		return nil, err
	}
	for k, v := range w {
		res[k] = v
	}
	if pl.view != src {
		// a hash of the real file would let a weak hidden value be
		// guessed offline from the rest, which the agent saw
		delete(res, "sha256")
	}
	return res, nil
}

func fsReplaceCmd() *cobra.Command {
	var o writeOpts
	var oldS, newS string
	var all, isRegex bool
	c := &cobra.Command{
		Use:   "replace TARGET PATH --old TEXT --new TEXT",
		Short: "Edit a file on servers by replacing exact text",
		Long: `Replaces --old with --new in PATH. On a group (@web) every server gets the
same edit; each server's result says what changed there, and a server where
--old is not found fails on its own (NO_MATCH) while the others are changed.
Run it with --dry-run first to see each server's diff.`,
		Example: `  komando fs replace web1 /etc/nginx/nginx.conf --old 'worker_connections 768;' --new 'worker_connections 4096;' --sudo --backup
  komando fs replace @web /etc/nginx/nginx.conf --old 'worker_connections 768;' --new 'worker_connections 4096;' --sudo --backup --dry-run
  komando fs replace web1 /etc/ssh/sshd_config --regex --old '(?m)^#?PasswordAuthentication .*$' --new 'PasswordAuthentication no' --sudo`,
		Args: cobra.ExactArgs(2),
		RunE: inCall(func(cl *call, cmd *cobra.Command, args []string) error {
			if oldS == "" {
				return out.Usage("give the text to replace with --old, and its replacement with --new")
			}
			if out.HasHidden(newS) {
				return hiddenValueErr()
			}
			var re *regexp.Regexp
			var err error
			switch {
			case isRegex:
				if re, err = regexp.Compile(oldS); err != nil {
					return out.Usage("--old is not a valid Go regular expression: %v", err)
				}
			case strings.Contains(oldS, out.Hidden) && !cl.out.Mask:
				// a line an AI agent saw masked: [hidden] stands for the value
				// (an agent's own run finds it as it is, in out.View)
				if re, err = regexp.Compile(hiddenPattern(oldS)); err != nil {
					return out.Usage("--old: %v", err)
				}
				newS = strings.ReplaceAll(newS, "$", "$$")
			}
			if o.owner != "" && !o.sudo {
				return out.Usage("--owner needs --sudo (only root can give a file to another user)")
			}
			st, err := loadState()
			if err != nil {
				return err
			}
			hosts, err := resolveTargets(cl, st, args[0])
			if err != nil {
				return err
			}
			if err := checkValidate(o.validate); err != nil {
				return err
			}
			if err := guard(cl, st, hosts, o.validate, true); err != nil {
				return err
			}
			if newS, err = expandSecretRefs(cl, newS, args[0]+":"+args[1], re != nil); err != nil {
				return err
			}
			e := replaceEdit{cl: cl, path: args[1], oldS: oldS, newS: newS, re: re, all: all, o: o}
			data, err := runFsFleet(cl, cmd.Context(), st, "fs.replace", args[1], hosts, e.on)
			if n := data.changedWithBackup(); n > 0 && !cl.flags.dryRun {
				s := ""
				if o.sudo {
					s = " --sudo"
				}
				where := countOf(n, "server")
				if len(hosts) == 1 {
					where = hosts[0].Name
				}
				textNote(cl, "Changed %s on %s. To undo: komando fs restore %s %s%s", args[1], where, args[0], argQ(args[1]), s)
			}
			return err
		}),
	}
	c.Flags().StringVar(&oldS, "old", "", "the text to find (a regular expression with --regex)")
	c.Flags().StringVar(&newS, "new", "", "the text to put in its place ($1 for a group with --regex)")
	c.Flags().BoolVar(&all, "all", false, "replace every occurrence")
	c.Flags().BoolVar(&isRegex, "regex", false, "treat --old as a Go regular expression")
	bindWriteOpts(c, &o)
	return c
}

// sameForAgent: fs write would leave the file as it is. For an AI agent
// a file with a value komando hides always counts as changed (and is
// written again), so --if-changed and would_change never confirm that the
// content the agent wrote guessed the hidden value.
func sameForAgent(cl *call, old, data []byte) bool {
	if cl.out.Mask && cl.out.View(string(old)).Masked() {
		return false
	}
	return bytes.Equal(old, data)
}

// replacePlan is what fs replace does to a file: the new file (updated),
// and the file and the new file as the caller sees them (view, shown).
type replacePlan struct {
	updated, view, shown string
	n                    int // matches of --old
	changed              bool
	note                 string
}

// planReplace edits src as p shows it. For an AI agent (p.Mask) the file
// is the masked view: every answer (no match, no change, already applied,
// the diff) depends only on what the agent saw, never on a hidden value.
func planReplace(p *out.Printer, src, oldS, newS string, re *regexp.Regexp, all bool, name string) (replacePlan, error) {
	view := out.View{Text: src}
	if p.Mask {
		view = p.View(src)
	}
	pl := replacePlan{view: view.Text}
	locs := findOld(view.Text, oldS, re)
	pl.n = len(locs)
	if pl.n == 0 {
		if re == nil && newS != "" && alreadyThere(p, view.Text, newS) {
			pl.note = "old text not found but new text already present (already applied?)"
			return pl, nil
		}
		return pl, out.Errf(out.ExitConflict, "NO_MATCH", "read the file with `komando fs cat TARGET "+name+"` and copy the exact text (whitespace matters)", "--old text not found in %s", name)
	}
	if pl.n > 1 && !all {
		return pl, out.Errf(out.ExitConflict, "AMBIGUOUS_MATCH", "add surrounding context to --old so it is unique (read the file with `komando fs cat SERVER PATH`), or pass --all", "--old matches %d times in %s", pl.n, name)
	}
	if !all {
		locs = locs[:1]
	}
	var err error
	if pl.updated, pl.shown, err = replaceOld(view, src, locs, newS, re); err != nil {
		return pl, err
	}
	if !p.Mask {
		pl.changed = pl.updated != src
		return pl, nil
	}
	// decided on the view: whether the real bytes stay the same would say
	// whether --new guessed a hidden value (the same bytes are then written)
	pl.changed = pl.shown != view.Text
	// an edit can leave a hidden value in place but take away what made it
	// look secret (DB_PASSWORD= renamed, postgres:// or Bearer cut off): the
	// next fs cat would show it. The new file, as it will be shown, must not
	// hold a hidden value more often than the edit the agent asked for does.
	now, asked := p.View(pl.updated).Text, p.View(pl.shown).Text
	for _, v := range view.Hidden(src) {
		if v != "" && strings.Count(now, v) > strings.Count(asked, v) {
			return pl, out.Errf(out.ExitUsage, "HIDDEN_VALUE", "keep the name or text around a hidden value that marks it as secret, or replace the value too, for example --old 'NAME=[hidden]' --new 'NAME={{secret:VAULT_NAME}}'",
				"the edit would show a value komando hid")
		}
	}
	return pl, nil
}

// alreadyThere: --new, as the caller would see it, is in the file as the
// caller sees it. A --new that spells out a value komando hides is never
// reported as there, or the answer would confirm a guessed value.
func alreadyThere(p *out.Printer, view, newS string) bool {
	if !p.Mask {
		return strings.Contains(view, newS)
	}
	nv := p.View(newS)
	return !nv.Masked() && strings.Contains(view, nv.Text)
}

// findOld returns where --old matches in text, not overlapping: the
// regexp's submatch indexes, or [start, end] of the exact text.
func findOld(text, oldS string, re *regexp.Regexp) [][]int {
	if re != nil {
		return re.FindAllStringSubmatchIndex(text, -1)
	}
	var locs [][]int
	for i := 0; ; {
		j := strings.Index(text[i:], oldS)
		if j < 0 {
			return locs
		}
		locs = append(locs, []int{i + j, i + j + len(oldS)})
		i += j + len(oldS)
	}
}

// replaceOld puts --new (with $1 groups for a regexp) at the matches locs
// of v.Text. It returns the new file, edited where each match is in src,
// and the new text as shown (the diff). A match that cuts into a hidden
// value, or a replacement that copies one ([hidden] captured by a group),
// is refused: the real value is never moved anywhere the agent could see it.
func replaceOld(v out.View, src string, locs [][]int, newS string, re *regexp.Regexp) (updated, shown string, err error) {
	var ub, sb strings.Builder
	lastT, lastS := 0, 0
	for _, loc := range locs {
		r := newS
		if re != nil {
			r = string(re.ExpandString(nil, newS, v.Text, loc))
		}
		a, e, ok := v.Source(loc[0], loc[1])
		if !ok {
			return "", "", out.Errf(out.ExitUsage, "HIDDEN_VALUE", "match a hidden value whole: [hidden] in --old (without --regex) stands for it",
				"--old starts or ends inside a value komando hid")
		}
		if v.Text != src && out.HasHidden(r) {
			return "", "", hiddenValueErr()
		}
		sb.WriteString(v.Text[lastT:loc[0]])
		sb.WriteString(r)
		ub.WriteString(src[lastS:a])
		ub.WriteString(r)
		lastT, lastS = loc[1], e
	}
	sb.WriteString(v.Text[lastT:])
	ub.WriteString(src[lastS:])
	return ub.String(), sb.String(), nil
}
