package cli

import (
	"sort"
	"strconv"
	"time"

	"github.com/spf13/cobra"

	"github.com/sgnd/komando/internal/out"
	"github.com/sgnd/komando/internal/sshx"
	"github.com/sgnd/komando/internal/store"
)

func jobListCmd() *cobra.Command {
	var target string
	var refresh bool
	var limit int
	c := &cobra.Command{
		Use:   "list",
		Short: "List the jobs komando started (--refresh asks the servers)",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			st, err := loadState()
			if err != nil {
				return err
			}
			var names map[string]bool
			if target != "" {
				names = targetNames(st, target)
				// a name that is no longer in the inventory still finds its jobs
				if _, err := resolveSelection(st, target); err != nil {
					known := false
					for _, j := range st.Jobs {
						known = known || names[j.Host]
					}
					if !known {
						return err
					}
				}
			}
			jobs := []*store.Job{}
			for _, j := range st.Jobs {
				if target == "" || names[j.Host] {
					jobs = append(jobs, j)
				}
			}
			sort.Slice(jobs, func(a, b int) bool { return jobs[a].StartedAt.After(jobs[b].StartedAt) })
			jobs = cutRows(jobs, limit) // newest first: the cut drops the oldest
			if !refresh {
				out.P.Print("job.list", jobList{Count: len(jobs), Jobs: jobs}, nil)
				return nil
			}
			rows := []any{}
			for _, j := range jobs {
				h, ok := st.Hosts[j.Host]
				if !ok {
					rows = append(rows, map[string]any{"id": j.ID, "host": j.Host, "state": "unknown-host"})
					continue
				}
				var s *jobStatus
				err := withClient(cmd.Context(), st, h, func(c *sshx.Client) error {
					var e error
					s, e = fetchStatus(cmd.Context(), c, j, 0)
					return e
				})
				if err != nil {
					rows = append(rows, map[string]any{"id": j.ID, "host": j.Host, "state": "unreachable", "error": toErr(err)})
					continue
				}
				rows = append(rows, s)
			}
			out.P.Print("job.list", jobList{Count: len(rows), Jobs: rows}, nil)
			return nil
		},
	}
	c.Flags().StringVar(&target, "target", "", "only jobs on these servers (a selector, like @web)")
	c.Flags().BoolVar(&refresh, "refresh", false, "ask each server for the job's current state")
	limitFlag(c, &limit, 0, "jobs, newest first")
	return c
}

type jobList struct {
	Count int `json:"count"`
	Jobs  any `json:"jobs"`
}

func (l jobList) Text() string {
	rows := [][]string{}
	add := func(id, host, state, exit string, started time.Time, command string) {
		age := "-"
		if !started.IsZero() {
			age = humanAge(time.Since(started))
		}
		command = truncateWidth(command, 60)
		rows = append(rows, []string{id, host, state, exit, age, command})
	}
	switch js := l.Jobs.(type) {
	case []*store.Job:
		for _, j := range js {
			add(j.ID, j.Host, "?", "", j.StartedAt, j.Command)
		}
	case []any:
		for _, r := range js {
			switch v := r.(type) {
			case *jobStatus:
				exit := ""
				if v.ExitCode != nil {
					exit = strconv.Itoa(*v.ExitCode)
				}
				t, _ := time.Parse(time.RFC3339, v.StartedAt)
				add(v.ID, v.Host, v.State, exit, t, v.Command)
			case map[string]any:
				add(v["id"].(string), v["host"].(string), v["state"].(string), "", time.Time{}, "")
			}
		}
	}
	if len(rows) == 0 {
		return noneYet("jobs", "job start TARGET -- COMMAND")
	}
	s := textTable([]string{"id", "host", "state", "exit", "age", "command"}, rows)
	if _, ok := l.Jobs.([]*store.Job); ok {
		s += "(state: add --refresh to ask the servers)\n"
	}
	return s
}
