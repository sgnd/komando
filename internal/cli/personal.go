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
	"cache get": true, "cache keys": true, "cache run": true,
	"cluster describe": true, "cluster events": true, "cluster exec": true, "cluster get": true, "cluster logs": true, "cluster run": true,
	"cluster helm status": true, "cluster helm values": true,
	"cron list":   true,
	"db activity": true, "db explain": true, "db locks": true, "db query": true,
	"docker exec": true, "docker inspect": true, "docker logs": true, "docker raw": true,
	"download": true, "exec": true, "script": true, "recipe run": true,
	"fs cat": true, "fs ls": true,
	"job logs": true, "job status": true, "job wait": true,
	"logs": true, "svc logs": true, "svc status": true,
	"net http":    true,
	"queue peek":  true,
	"storage cat": true, "storage download": true, "storage ls": true,
	"user list": true,
}

// personalCmd: this command, run by an AI agent, may hide personal data.
var personalCmd bool

// startPersonal decides, before a command runs, whether it may hide
// personal data; notePersonal then turns it on per target.
func startPersonal(cmd *cobra.Command) {
	out.P.Personal = false
	personalCmd = out.P.Mask && personalCmds[idKey(cmd)]
}

// notePersonal turns on personal data masking when the command works on a
// target the mask_personal setting covers.
func notePersonal(st *store.State, hosts []*store.Host, conns []*store.Conn) {
	if !personalCmd || out.P.Personal {
		return
	}
	for _, c := range conns {
		if strings.EqualFold(c.Options["mask_personal"], "on") || c.Options["mask_columns"] != "" {
			out.P.Personal = true
			return
		}
	}
	switch st.Settings.MaskPersonal {
	case "off":
		return
	case "all":
		out.P.Personal = len(hosts)+len(conns) > 0
		return
	}
	for _, h := range hosts {
		if protectedHost(st, h) {
			out.P.Personal = true
			return
		}
	}
	for _, c := range conns {
		if protectedConn(st, c) {
			out.P.Personal = true
			return
		}
	}
}

// maskColumns hides whole values of the conn's mask_columns (names,
// addresses, birth dates: personal data no pattern finds) in query
// results, when personal data is hidden for this command.
func maskColumns(c *store.Conn, res *dbx.Result) {
	if !out.P.Mask || !out.P.Personal || c.Options["mask_columns"] == "" {
		return
	}
	want := map[string]bool{}
	// names split by spaces (--option takes a comma as the next option)
	for _, n := range strings.FieldsFunc(c.Options["mask_columns"], func(r rune) bool { return r == ' ' || r == ',' || r == ';' }) {
		want[strings.ToLower(n)] = true
	}
	label := out.PersonalLabel(out.PersonalColumn)
	for ri := range res.Results {
		r := &res.Results[ri]
		var idx []int
		for i, col := range r.Columns {
			if want[strings.ToLower(col.Name)] {
				idx = append(idx, i)
			}
		}
		for _, row := range r.Rows {
			for _, i := range idx {
				if i < len(row) && row[i] != nil {
					row[i] = label
				}
			}
		}
	}
}

// refuseHiddenWrite stops a write that carries a value komando hid from the
// agent: it would put "[hidden: email]" where the real address was.
func refuseHiddenWrite(texts ...string) error {
	for _, s := range texts {
		if out.HasHidden(s) {
			return out.Errf(out.ExitUsage, "HIDDEN_VALUE",
				"write the real value, or leave that column or key out of the change; a person can let you see values with --reveal",
				"the change holds a value komando hid ([hidden], [hidden: KIND] or [secret:NAME]); writing it would destroy the real value")
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
