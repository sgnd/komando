package cli

import (
	"strings"

	"github.com/spf13/cobra"

	"github.com/sgnd/komando/internal/out"
	"github.com/sgnd/komando/internal/sshx"
	"github.com/sgnd/komando/internal/store"
)

// cronListCmd is `cron list TARGET`. readCron puts the crontab in $cur;
// useSudo says whether reading it needs sudo (cronCmd).
func cronListCmd(readCron func() string, useSudo func() bool) *cobra.Command {
	var cronLimit int
	list := &cobra.Command{
		Use:     "list TARGET",
		Aliases: []string{"ls"},
		Short:   "Show crontab entries",
		Args:    cobra.ExactArgs(1),
		RunE: inCall(func(cl *call, cmd *cobra.Command, args []string) error {
			return runOps(cl, cmd.Context(), opsSpec{name: "cron.list", target: args[0], command: readCron() + `printf '%s\n' "$cur"`, display: "cron list", sudo: useSudo(), limit: cronLimit,
				parse: func(_ *store.Host, rr *sshx.RunResult) (any, *out.Error) {
					if rr.ExitCode != 0 {
						return nil, out.Errf(out.ExitRemote, "CRONTAB_UNREADABLE", "check the user name; reading another user's crontab needs sudo", "cannot read the crontab (exit %d)", rr.ExitCode)
					}
					rows := []map[string]any{}
					for _, l := range strings.Split(rr.Stdout, "\n") {
						t := strings.TrimSpace(l)
						if t == "" || strings.HasPrefix(t, "#") {
							continue
						}
						rows = append(rows, parseCronLine(t))
					}
					return rows, nil
				},
				text: func(data any) string {
					rows := [][]string{}
					for _, r := range data.([]map[string]any) {
						cmdText := cell(r["command"])
						if r["schedule"] == nil {
							cmdText = cell(r["line"])
						}
						rows = append(rows, []string{cell(r["schedule"]), cmdText, cell(r["id"])})
					}
					return textTable([]string{"schedule", "command", "id"}, rows)
				}})
		}),
	}
	limitFlag(list, &cronLimit, 0, "entries per server")
	return list
}
