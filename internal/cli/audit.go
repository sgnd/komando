package cli

import (
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/spf13/cobra"

	"github.com/sgnd/komando/internal/out"
	"github.com/sgnd/komando/internal/sealdb"
)

type auditList struct {
	Count   int              `json:"count"`
	Entries []map[string]any `json:"entries"`
	filters []string         // the filter flags given, for the empty line
}

// Text is one line per entry, like `git log --oneline`.
func (l auditList) Text() string {
	if len(l.Entries) == 0 && len(l.filters) > 0 {
		return noneMatch("audit entries", strings.Join(l.filters, " "), "fewer filters show more")
	}
	if len(l.Entries) == 0 {
		return noneYet("audit entries", "", "`komando config get audit` says whether the log is on")
	}
	var rows [][]string
	for _, e := range l.Entries {
		ts := fmt.Sprint(e["ts"])
		if t, err := time.Parse(time.RFC3339Nano, ts); err == nil {
			ts = timeCell(t)
		}
		who := fmt.Sprint(e["actor"])
		if a, ok := e["agent"].(string); ok && a != "" {
			who += " (" + a + ")"
			if e["actor_claimed"] == true { // the agent is sure; the name is what it says
				who = a + " (as " + fmt.Sprint(e["actor"]) + ")"
			}
		}
		var targets []string
		for _, k := range []string{"hosts", "conns"} {
			if l, ok := e[k].([]any); ok {
				for _, x := range l {
					targets = append(targets, fmt.Sprint(x))
				}
			}
		}
		for _, k := range []string{"key", "secret", "group"} {
			if v, ok := e[k].(string); ok && v != "" {
				targets = append(targets, k+" "+v)
			}
		}
		if v, ok := e["ssh_command"].(string); ok && v != "" {
			targets = append(targets, strconv.Quote(v)) // what an ssh-gate key asked for, line breaks and escapes shown as \n, \x1b
		}
		res := "ok"
		switch {
		case e["dry_run"] == true:
			res = "dry-run"
		case e["blocked"] != nil:
			res = "blocked"
		case e["ok"] != true:
			res = "failed"
		}
		t := truncateWidth(auditCell(strings.Join(targets, ",")), 60)
		rows = append(rows, []string{auditCell(ts), auditCell(who), auditCell(fmt.Sprint(e["command"])), t, res})
	}
	return textTable([]string{"TIME", "ACTOR", "COMMAND", "TARGETS", "OK"}, rows)
}

// auditCell shows a value from the log on one row: a line break, a
// terminal escape or another control character comes out escaped (\n,
// \x1b), so a value cannot add or hide rows.
func auditCell(s string) string {
	if strings.IndexFunc(s, func(r rune) bool { return !unicode.IsPrint(r) }) < 0 {
		return s
	}
	q := strconv.Quote(s)
	return q[1 : len(q)-1]
}

func auditCmd() *cobra.Command {
	var limit int
	var target, command, since, until, actorName string
	var failed bool
	c := &cobra.Command{
		Use:   "audit",
		Short: "Show the audit log: who did what, where, and the result",
		Long: `Every change komando makes, and every blocked attempt, is a sealed record in
~/.komando/store.db: when, who (and which AI agent), the command, its
targets and whether it worked. The newest entries come last.

--since and --until take how long ago (30m, 12h, 7d), today, yesterday,
or a time (2026-11-07, '2026-11-07 14:30', 2026-11-07T14:30:00Z); a time
without a zone is this computer's. --since keeps entries from that moment
on, --until those before it. With either, every match is shown unless -n
is given.`,
		Example: `  komando audit                      # the last 50
  komando audit -n 0 --target @prod  # everything about @prod
  komando audit --command host. --failed
  komando audit --since 2h           # everything in the last two hours
  komando audit --since yesterday --until today --target @prod
  komando audit --actor claude --since 7d        # what Claude Code did this week
  komando audit verify               # was the log changed outside komando?`,
		Args: cobra.NoArgs,
		RunE: inCall(func(cl *call, cmd *cobra.Command, _ []string) error {
			if limit < 0 {
				return out.Errf(out.ExitUsage, "USAGE", "-n takes how many of the newest entries to show; 0 shows all", "-n takes 0 or more, not %d", limit)
			}
			flt := auditFilter{command: command, failed: failed, byTarget: target != "", actor: actorName}
			if err := flt.setWindow(since, until, time.Now()); err != nil {
				return err
			}
			if (since != "" || until != "") && !cmd.Flags().Changed("limit") {
				limit = 0
			}
			if target != "" {
				st, err := loadState()
				if err != nil {
					return err
				}
				flt.names = targetNames(cl, st, target)
			}
			// without a filter only the newest records are read
			var from int64
			if limit > 0 && command == "" && !failed && target == "" && actorName == "" && since == "" && until == "" {
				last, err := newestAuditSeq()
				if err != nil {
					return err
				}
				from = max(0, last-int64(limit))
			}
			all := []map[string]any{}
			err := eachAuditAfter(from, func(_ int, b []byte) error {
				var e map[string]any
				if json.Unmarshal(b, &e) != nil {
					return nil
				}
				delete(e, "prev") // the chain is for `audit verify`
				if flt.keep(e) {
					all = append(all, e)
				}
				return nil
			})
			if errors.Is(err, sealdb.ErrTampered) {
				// the records before the broken one are still shown
				cl.out.Warn(fmt.Sprintf("the audit log is broken after the %d records shown: %v; run `komando audit verify`", len(all), err))
			} else if err != nil {
				return err
			}
			if from > 0 && len(all) >= limit {
				cl.out.Cut(limit) // older records were not read
			}
			all = cutLast(cl, all, limit)
			var given []string
			for _, f := range []string{"target", "command", "failed", "actor", "since", "until"} {
				if cmd.Flags().Changed(f) {
					given = append(given, "--"+f)
				}
			}
			cl.out.Print("audit", auditList{Count: len(all), Entries: all, filters: given}, nil)
			return nil
		}),
	}
	c.AddCommand(auditVerifyCmd())
	c.Flags().IntVarP(&limit, "limit", "n", 50, "the newest N entries (0 = all; with --since or --until, all unless given)")
	c.Flags().StringVar(&target, "target", "", "only entries for these servers or conns (a selector, like @prod)")
	c.Flags().StringVar(&command, "command", "", "only commands that start with this (like exec, svc.)")
	c.Flags().BoolVar(&failed, "failed", false, "only actions that failed or were blocked")
	c.Flags().StringVar(&actorName, "actor", "", "only what this one did: part of the name in KOMANDO_ACTOR, the AI agent (claude, codex ...) or the computer account")
	c.Flags().StringVar(&since, "since", "", "only entries from this time on: 2h, 7d, today, 2026-11-07 or '2026-11-07 14:30'")
	c.Flags().StringVar(&until, "until", "", "only entries before this time (the same forms as --since)")
	return c
}
