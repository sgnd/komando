package cli

import (
	"strings"

	"github.com/spf13/cobra"

	"github.com/sgnd/komando/internal/dbx"
	"github.com/sgnd/komando/internal/out"
	"github.com/sgnd/komando/internal/store"
)

// Personal data (email addresses, phone numbers, card numbers, IBANs) is
// hidden from AI agents in what they read from servers and resources, as
// [hidden: KIND]. The mask_personal setting says where: on protected
// targets (the default), on all, or nowhere. A conn can ask for it
// whatever the setting (--option mask_personal=on), and a database conn
// can hide whole columns (--option 'mask_columns=name address').
//
// It is on only for the commands below, whose output carries data read
// from a target; komando's own inventory (server addresses, conn URLs)
// is never hidden. --reveal, which a person allows, shows everything.

// personalCmds are the command IDs (as in commandKinds) whose output
// carries data read from a server or resource.
var personalCmds = map[string]bool{
	"cache get": true, "cache keys": true, "cache run": true, // moveType moves cache run to each provider's raw
	"cluster describe": true, "cluster events": true, "cluster exec": true, "cluster get": true, "cluster logs": true, "cluster run": true,
	"cluster helm status": true, "cluster helm values": true,
	"cron list":   true,
	"db activity": true, "db explain": true, "db locks": true, "db query": true,
	"docker compose": true, "docker exec": true, "docker inspect": true, "docker logs": true, "docker raw": true,
	"cp": true, "download": true, "exec": true, "recipe run": true, "sync": true,
	"fs cat": true, "fs list": true, "fs replace": true, "fs restore": true, "fs write": true,
	"job logs": true, "job status": true, "job wait": true,
	"logs": true, "svc logs": true, "svc status": true,
	"net http":    true,
	"queue peek":  true,
	"storage cat": true, "storage download": true, "storage list": true,
	"user list": true,
}

// startPersonal decides, before a command runs, whether it may hide
// personal data; notePersonal then turns it on per target.
func startPersonal(cmd *cobra.Command) {
	cl := callOf(cmd)
	cl.out.Personal, cl.twinMask = false, nil
	cl.personalCmd = cl.out.Mask && personalCmds[idKey(cmd)]
}

// notePersonal turns on personal data masking when the command works on a
// target the mask_personal setting covers.
func notePersonal(cl *call, st *store.State, hosts []*store.Host, conns []*store.Conn) {
	if !cl.personalCmd {
		return
	}
	noteTwinMask(cl, st, conns)
	if !cl.out.Personal {
		cl.out.Personal = personalTarget(st, hosts, conns)
	}
}

// maskColumns hides, in query results, what no output pass can see: a
// binary cell that holds a hidden value (as [hidden], so -o text and csv,
// which print it as hex, show no more than JSON), and, where personal data
// is hidden, whole values of the conn's mask_columns (names, addresses,
// birth dates: personal data no pattern finds), by column and inside cells
// that hold JSON (to_jsonb(row), row_to_json).
func maskColumns(cl *call, c *store.Conn, res *dbx.Result) {
	names := map[string]bool{}
	if cl.out.Mask && cl.out.Personal {
		for _, n := range maskedColumnsFor(cl, c) {
			names[n] = true
		}
	}
	label := out.PersonalLabel(out.PersonalColumn)
	for ri := range res.Results {
		r := &res.Results[ri]
		hide := map[int]bool{}
		for i, col := range r.Columns {
			if names[strings.ToLower(col.Name)] || names[strings.ToLower(lastPart(col.Name))] {
				hide[i] = true
			}
		}
		for _, row := range r.Rows {
			for i := range row {
				switch {
				case row[i] == nil:
				case hide[i]:
					row[i] = label
				default:
					row[i] = maskCell(cl, row[i], names, label)
				}
			}
		}
	}
}

// lastPart is a result column's name without the table in front (b.name)
// or the number a database adds to a name that is there twice (name_1).
func lastPart(n string) string {
	if i := strings.LastIndexByte(n, '.'); i >= 0 {
		n = n[i+1:]
	}
	if i := strings.LastIndexByte(n, '_'); i > 0 && strings.Trim(n[i+1:], "0123456789") == "" && i+1 < len(n) {
		n = n[:i]
	}
	return n
}

// refuseHiddenWrite stops a write that carries a value komando hid from the
// agent: it would put "[hidden: email]" where the real address was.
func refuseHiddenWrite(texts ...string) error {
	for _, s := range texts {
		if out.HasHidden(s) {
			return out.Errf(out.ExitUsage, "HIDDEN_VALUE",
				"write the real value, or leave that column or key out of the change; a person can let you see values with --reveal",
				"the change holds a value komando hid ([hidden], [hidden: KIND] or [credential:NAME]); writing it would destroy the real value")
		}
	}
	return nil
}

// refuseHiddenSQL is refuseHiddenWrite for `db query --write`: the SQL and
// its --arg values.
func refuseHiddenSQL(write bool, query string, args []string) error {
	if !write {
		return nil
	}
	return refuseHiddenWrite(append([]string{query}, args...)...)
}
