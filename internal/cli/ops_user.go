package cli

import (
	"strconv"
	"strings"

	"github.com/sgnd/komando/internal/out"
	"github.com/sgnd/komando/internal/sshx"
)

// userListScript prints passwd, the admin groups and (when readable, i.e.
// through sudo) each account's expiry date from shadow, which says whether
// it is locked. Only name and expiry leave the server, never a hash.
const userListScript = `echo '#komando:passwd'; getent passwd
echo '#komando:groups'; for g in sudo wheel admin; do getent group $g; done
echo '#komando:expire'; { cat /etc/shadow 2>/dev/null || getent shadow 2>/dev/null; } | cut -d: -f1,8
echo '#komando:today'; echo $(( $(date +%s) / 86400 )); true`

type userRow struct {
	Name       string `json:"name"`
	UID        int    `json:"uid"`
	Home       string `json:"home"`
	Shell      string `json:"shell"`
	AdminGroup bool   `json:"admin_group"`      // in the sudo, wheel or admin group (sudoers.d is not read)
	Locked     *bool  `json:"locked,omitempty"` // account expired (`user lock`); unknown without sudo
}

func parseUsers(s string, all bool) []userRow {
	sec := sections(s)
	admins := map[string]bool{}
	for _, l := range strings.Split(sec["groups"], "\n") {
		f := strings.Split(strings.TrimSpace(l), ":")
		if len(f) == 4 {
			for _, u := range strings.Split(f[3], ",") {
				admins[u] = true
			}
		}
	}
	today, _ := strconv.Atoi(strings.TrimSpace(sec["today"]))
	locked := map[string]bool{}
	for _, l := range strings.Split(sec["expire"], "\n") {
		f := strings.Split(strings.TrimSpace(l), ":")
		if len(f) != 2 {
			continue
		}
		exp, err := strconv.Atoi(f[1])
		locked[f[0]] = err == nil && today > 0 && exp <= today // usermod -e 1, or an expired account
	}
	rows := []userRow{}
	for _, l := range strings.Split(sec["passwd"], "\n") {
		f := strings.Split(strings.TrimSpace(l), ":")
		if len(f) < 7 {
			continue
		}
		uid, _ := strconv.Atoi(f[2])
		if !all && (uid < 1000 || uid >= 65534) && uid != 0 {
			continue
		}
		r := userRow{Name: f[0], UID: uid, Home: f[5], Shell: f[6], AdminGroup: admins[f[0]] || uid == 0}
		if l, ok := locked[f[0]]; ok {
			r.Locked = &l
		}
		rows = append(rows, r)
	}
	return rows
}

func usersText(data any) string {
	yes := func(b bool) string {
		if b {
			return "yes"
		}
		return "no"
	}
	rows := [][]string{}
	for _, r := range data.([]userRow) {
		lk := ""
		if r.Locked != nil {
			lk = yes(*r.Locked)
		}
		rows = append(rows, []string{r.Name, strconv.Itoa(r.UID), r.Home, r.Shell, yes(r.AdminGroup), lk})
	}
	return textTable([]string{"name", "uid", "home", "shell", "admin-group", "locked"}, rows)
}

// userExists stops a script with a marker when the user does not exist.
func userExists(name string) string {
	return "id " + sshx.Q(name) + " >/dev/null 2>&1 || { echo '#komando:no-user'; exit 0; }\n"
}

func userResult(name, action string, rr *sshx.RunResult) (any, *out.Error) {
	if marker(rr.Stdout) == "no-user" {
		return nil, out.Errf(out.ExitNotFound, "USER_NOT_FOUND", "list the accounts with `komando user list TARGET --all`", "user %s does not exist", name)
	}
	if rr.ExitCode != 0 {
		return nil, nil
	}
	return map[string]any{"user": name, action: true}, nil
}

// cronRemoved reads the "removed N" line of `cron rm`.
func cronRemoved(rr *sshx.RunResult) (any, *out.Error) {
	for _, l := range strings.Split(rr.Stdout, "\n") {
		if n, ok := strings.CutPrefix(strings.TrimSpace(l), "removed "); ok {
			v, _ := strconv.Atoi(n)
			return map[string]any{"removed": v}, nil
		}
	}
	return nil, nil
}
