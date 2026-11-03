package cli

import (
	"encoding/json"
	"strings"

	"github.com/spf13/cobra"

	"github.com/sgnd/komando/internal/driver"
	"github.com/sgnd/komando/internal/sshx"
	"github.com/sgnd/komando/internal/store"
)

// --------------------------------------------------------------- docker ---

func dockerCmd() *cobra.Command {
	var sudo bool
	c := &cobra.Command{
		Use:     "docker",
		Aliases: []string{"container", "ctr"},
		Short:   "Docker: ps/stats/images (structured), logs, start/stop/restart, exec, compose, raw",
	}
	c.PersistentFlags().BoolVarP(&sudo, "sudo", "s", false, "run docker via sudo")
	jsonLines := func(name, args string) *cobra.Command {
		return &cobra.Command{
			Use:   name + " TARGET",
			Short: "docker " + name + " as structured JSON",
			Args:  cobra.ExactArgs(1),
			RunE: func(cmd *cobra.Command, a []string) error {
				return probe(cmd.Context(), "docker."+name, a[0], "docker "+args+" --format '{{json .}}'", sudo, parseJSONLines)
			},
		}
	}
	ps := jsonLines("ps", "ps -a")
	c.AddCommand(ps, jsonLines("stats", "stats --no-stream"), jsonLines("images", "images"))
	for _, a := range []string{"start", "stop", "restart", "rm", "pull"} {
		action := a
		c.AddCommand(&cobra.Command{
			Use:   action + " TARGET NAME...",
			Short: "docker " + action,
			Args:  cobra.MinimumNArgs(2),
			RunE: func(cmd *cobra.Command, args []string) error {
				if _, err := guardDocker(append([]string{action}, args[1:]...)); err != nil {
					return err
				}
				return runOne(cmd.Context(), "docker."+action, args[0], "docker "+action+" "+quoteAll(args[1:]), sudo, true)
			},
		})
	}
	var lo logOpts
	logs := &cobra.Command{
		Use:   "logs TARGET CONTAINER",
		Short: "Same as `komando logs TARGET --container NAME`",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			lo.container = args[1]
			return runLogs(cmd.Context(), "docker.logs", args[0], &lo, sudo)
		},
	}
	lo.bind(logs, false)
	_ = logs.Flags().MarkHidden("sudo")
	inspect := &cobra.Command{
		Use:   "inspect TARGET NAME",
		Short: "docker inspect (JSON)",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			return probe(cmd.Context(), "docker.inspect", args[0], "docker inspect "+sshx.Q(args[1]), sudo, func(_ *store.Host, s string) (any, error) {
				var v any
				if err := json.Unmarshal([]byte(s), &v); err != nil {
					return s, nil
				}
				return v, nil
			})
		},
	}
	var readOnly bool
	execC := &cobra.Command{
		Use:     "exec TARGET CONTAINER -- COMMAND...",
		Short:   "Run a command inside a container",
		Example: "  komando docker exec app1 api -- php artisan migrate:status",
		Args:    cobra.MinimumNArgs(3),
		RunE: func(cmd *cobra.Command, args []string) error {
			inner := strings.Join(args[2:], " ")
			st, err := loadState()
			if err == nil {
				if err := guard(st, nil, inner, false); err != nil {
					return err
				}
			}
			return runOne(cmd.Context(), "docker.exec", args[0], "docker exec -i "+sshx.Q(args[1])+" sh -c "+sshx.Q(inner), sudo, !readOnly)
		},
	}
	execC.Flags().BoolVar(&readOnly, "read-only", false, "declare read-only")
	var file, dir string
	compose := &cobra.Command{
		Use:     "compose TARGET -- ARGS...",
		Short:   "docker compose with -f/--project-dir (e.g. ps, up -d, pull, logs --tail 50)",
		Example: "  komando docker compose app1 --dir /srv/shop -- up -d --pull always",
		Args:    cobra.MinimumNArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			c := "docker compose"
			if dir != "" {
				c = "cd " + sshx.Q(dir) + " && " + c
			}
			if file != "" {
				c += " -f " + sshx.Q(file)
			}
			sub := strings.Join(args[1:], " ")
			c += " " + sub + " 2>&1"
			ro := strings.HasPrefix(sub, "ps") || strings.HasPrefix(sub, "logs") || strings.HasPrefix(sub, "config") || strings.HasPrefix(sub, "ls")
			// down with volumes or images deletes data; plain down only stops
			if args[1] == "down" && hasFlag(args[2:], "-v", "--volumes", "--rmi") {
				if _, err := guardDocker([]string{"volume", "rm"}); err != nil {
					return err
				}
			}
			return runOne(cmd.Context(), "docker.compose", args[0], c, sudo, !ro)
		},
	}
	compose.Flags().StringVarP(&file, "file", "f", "", "compose file")
	compose.Flags().StringVar(&dir, "dir", "", "project directory")
	raw := &cobra.Command{
		Use:   "raw TARGET -- DOCKER_ARGS...",
		Short: "Any docker subcommand (policy still applies)",
		Args:  cobra.MinimumNArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			mutating, err := guardDocker(args[1:])
			if err != nil {
				return err
			}
			return runOne(cmd.Context(), "docker.raw", args[0], "docker "+strings.Join(args[1:], " "), sudo, mutating)
		},
	}
	c.AddCommand(logs, inspect, execC, compose, raw)
	return c
}

func parseJSONLines(_ *store.Host, s string) (any, error) {
	rows := []any{}
	for _, line := range strings.Split(s, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		var v any
		if err := json.Unmarshal([]byte(line), &v); err != nil {
			return s, nil
		}
		rows = append(rows, v)
	}
	return rows, nil
}

// guardDocker rates a docker command line the way `cluster run` rates one
// on a Swarm manager: reads stay reads, and deleting or running anything
// (rm, volume rm, prune, run, exec) needs --allow-dangerous.
func guardDocker(args []string) (mutating bool, err error) {
	if len(args) == 0 {
		return true, nil
	}
	risk := classifyDocker(args)
	if risk >= driver.RiskDestructive && !dangerOK() {
		st, err := loadState()
		if err != nil {
			return true, err
		}
		return true, guardConns(st, nil, driver.Verdict{Risk: risk, RuleIDs: []string{"docker"}, Reasons: []string{"docker " + strings.Join(args, " ")}})
	}
	return risk > driver.RiskRead, nil
}
