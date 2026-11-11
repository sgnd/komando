package cli

import (
	"os"
	"path"
	"sort"
	"strconv"
	"strings"

	"github.com/sgnd/komando/internal/out"
	"github.com/sgnd/komando/internal/sshx"
	"github.com/sgnd/komando/internal/store"
	"github.com/spf13/cobra"
	"golang.org/x/crypto/ssh"
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
	sort.SliceStable(rows, func(i, j int) bool { return rows[i].Name < rows[j].Name })
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

// needShadow stops a script on servers without the shadow tools (useradd,
// usermod, userdel): busybox, as on Alpine, has only adduser and deluser.
func needShadow(tool string) string {
	return "command -v " + tool + " >/dev/null 2>&1 || { echo '#komando:no-" + tool + "'; echo '" + tool + " is missing on this server; on Alpine install the shadow package: komando pkg install TARGET shadow' >&2; exit 127; }\n"
}

func userResult(name, action string, rr *sshx.RunResult) (any, *out.Error) {
	switch marker(rr.Stdout) {
	case "no-user":
		return nil, out.Errf(out.ExitNotFound, "USER_NOT_FOUND", "list the accounts with `komando user list TARGET --all`", "user %s does not exist", name)
	case "no-usermod":
		return nil, out.Errf(out.ExitNotFound, "TOOL_MISSING", "on Alpine install the shadow package: `komando pkg install TARGET shadow`", "usermod is missing on this server")
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

// loginShell reports whether a person can log in with shell: not
// nologin, false or true, and a shell by name (bash, sh, zsh, fish ...).
func loginShell(shell string) bool {
	base := path.Base(strings.TrimSpace(shell))
	switch base {
	case "nologin", "false", "true", "", ".", "/":
		return false
	}
	return strings.Contains(base, "sh")
}

// loginUser is the account komando logs in to h as.
func loginUser(st *store.State, h *store.Host) string {
	switch {
	case h.User != "":
		return h.User
	case st.Settings.DefaultUser != "":
		return st.Settings.DefaultUser
	}
	return os.Getenv("USER")
}

// lockoutStop refuses to lock or delete root or the account komando logs
// in as: afterwards nobody gets in to undo it. --allow-dangerous lets it
// through.
func lockoutStop(target, user, verb string) error {
	st, err := loadState()
	if err != nil {
		return err
	}
	hosts, err := resolveTargets(st, target)
	if err != nil {
		return nil // the command itself reports it
	}
	var names []string
	login := false
	for _, h := range hosts {
		if user == loginUser(st, h) {
			login = true
			names = append(names, h.Name)
		} else if user == "root" {
			names = append(names, h.Name)
		}
	}
	if len(names) == 0 {
		return nil
	}
	why := verb + " " + user + " on " + strings.Join(names, ", ") + ": root is the account that repairs a server"
	hint := "only if this is intended: confirm with the user, then re-run with --allow-dangerous"
	if login {
		why = verb + " " + user + " locks komando out of " + strings.Join(names, ", ") + ": it is the user komando logs in as"
		hint = "log in as another user first (`komando host edit NAME --user OTHER`); " + hint
	}
	if dangerOK(why, targetsWhy(st, hosts)) || confirmDangerous(names, why) {
		return nil
	}
	return policyStop(out.Errf(out.ExitPolicy, "POLICY_BLOCKED", hint, "%s", why))
}

func userCmd() *cobra.Command {
	c := &cobra.Command{Use: "user", Aliases: []string{"users"}, Short: "Linux user accounts: list, add, lock, unlock, rm"}
	var noSudo bool
	c.PersistentFlags().BoolVar(&noSudo, "no-sudo", false, "do not use sudo (e.g. when logged in as root)")
	var all bool
	list := &cobra.Command{
		Use:     "list TARGET",
		Aliases: []string{"ls"},
		Short:   "List accounts with admin group and lock state (--all for system)",
		Long: `Lists accounts with their uid, home, shell, whether they are in the sudo,
wheel or admin group (admin_group; rules in sudoers.d are not read) and
whether the account is locked (expired, as ` + "`komando user lock`" + ` does). The lock
state is read through sudo; with --no-sudo it is left out.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runOps(cmd.Context(), opsSpec{name: "user.list", target: args[0], command: userListScript, display: "user list", sudo: !noSudo,
				parse: func(_ *store.Host, rr *sshx.RunResult) (any, *out.Error) { return parseUsers(rr.Stdout, all), nil },
				text:  usersText})
		},
	}
	list.Flags().BoolVar(&all, "all", false, "include system accounts")
	var pubKey, keyName, shell string
	var admin bool
	add := &cobra.Command{
		Use:     "add TARGET USERNAME",
		Short:   "Create a user if missing, with an SSH key and sudo if asked",
		Example: "  komando user add @web deploy --key deploy --admin",
		Args:    cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			u := args[1]
			if !nameRe.MatchString(u) {
				return out.Usage("invalid username %q: start with a letter or digit, then letters, digits, . _ or - (at most 63)", u)
			}
			pubKey, err := userPubKey(keyName, pubKey)
			if err != nil {
				return err
			}
			// an existing user gets --shell too, so a shell nobody can log
			// in with locks out root or komando's own login like `user lock`
			if cmd.Flags().Changed("shell") && !loginShell(shell) {
				if err := lockoutStop(args[0], u, "giving the shell "+shell+" to"); err != nil {
					return err
				}
			}
			q := sshx.Q(u)
			sb := strings.Builder{}
			sb.WriteString(needShadow("useradd") + "set -e; if id " + q + " >/dev/null 2>&1; then echo 'exists' >&2; else useradd -m -s " + sshx.Q(shell) + " " + q + "; echo 'created' >&2; fi; ")
			if cmd.Flags().Changed("shell") {
				// an existing user gets the shell asked for, too
				sb.WriteString("[ \"$(getent passwd " + q + " | cut -d: -f7)\" = " + sshx.Q(shell) + " ] || usermod -s " + sshx.Q(shell) + " " + q + "; ")
			}
			if admin {
				sb.WriteString("if getent group sudo >/dev/null; then usermod -aG sudo " + q + "; else usermod -aG wheel " + q + "; fi; ")
			}
			if pubKey != "" {
				sb.WriteString("h=$(getent passwd " + q + " | cut -d: -f6); install -d -m 700 -o " + q + " -g $(id -gn " + q + ") \"$h/.ssh\"; touch \"$h/.ssh/authorized_keys\"; " +
					"grep -qF " + sshx.Q(pubKey) + " \"$h/.ssh/authorized_keys\" || printf '%s\\n' " + sshx.Q(pubKey) + " >> \"$h/.ssh/authorized_keys\"; " +
					"chown " + q + ": \"$h/.ssh/authorized_keys\"; chmod 600 \"$h/.ssh/authorized_keys\"; ")
			}
			sb.WriteString("id " + q)
			return runOne(cmd.Context(), "user.add", args[0], sb.String(), !noSudo, true)
		},
	}
	add.Flags().StringVar(&pubKey, "pubkey", "", "public key line to authorize")
	add.Flags().StringVar(&keyName, "key", "", "authorize this key from komando's key list")
	add.Flags().StringVar(&shell, "shell", "/bin/bash", "the new user's login shell")
	add.Flags().BoolVar(&admin, "admin", false, "add to the sudo (Debian) or wheel (RHEL, Alpine) group")
	lock := &cobra.Command{
		Use:   "lock TARGET USERNAME",
		Short: "Lock an account so password and SSH keys stop working",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := lockoutStop(args[0], args[1], "locking"); err != nil {
				return err
			}
			return runOps(cmd.Context(), opsSpec{name: "user.lock", target: args[0], command: userExists(args[1]) + needShadow("usermod") + "usermod -L -e 1 " + sshx.Q(args[1]),
				display: "user lock " + args[1], sudo: !noSudo, mutating: true,
				parse: func(_ *store.Host, rr *sshx.RunResult) (any, *out.Error) { return userResult(args[1], "locked", rr) }})
		},
	}
	unlock := &cobra.Command{
		Use:   "unlock TARGET USERNAME",
		Short: "Unlock an account locked with `user lock`",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runOps(cmd.Context(), opsSpec{name: "user.unlock", target: args[0], command: userExists(args[1]) + needShadow("usermod") + "usermod -U -e '' " + sshx.Q(args[1]),
				display: "user unlock " + args[1], sudo: !noSudo, mutating: true,
				parse: func(_ *store.Host, rr *sshx.RunResult) (any, *out.Error) { return userResult(args[1], "unlocked", rr) }})
		},
	}
	c.AddCommand(list, add, lock, unlock, userRmCmd(&noSudo))
	return c
}

func userRmCmd(noSudo *bool) *cobra.Command {
	var removeHome bool
	del := &cobra.Command{
		Use:   "rm TARGET USERNAME",
		Short: "Delete a user (needs --allow-dangerous)",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := lockoutStop(args[0], args[1], "deleting"); err != nil {
				return err
			}
			c := needShadow("userdel") + "userdel "
			if removeHome {
				c += "-r "
			}
			return runOne(cmd.Context(), "user.rm", args[0], c+sshx.Q(args[1]), !*noSudo, true)
		},
	}
	del.Flags().BoolVar(&removeHome, "remove-home", false, "also delete the user's home folder and the files in it")
	return del
}

// userPubKey is the key line user add authorizes: --pubkey as given, or
// the public half of the --key from komando's key list.
func userPubKey(keyName, pubKey string) (string, error) {
	if keyName != "" && pubKey != "" {
		return "", out.Usage("give --key or --pubkey, not both")
	}
	if pubKey != "" {
		if _, _, _, _, err := ssh.ParseAuthorizedKey([]byte(pubKey)); err != nil {
			return "", out.Usage("--pubkey is not an SSH public key line (ssh-ed25519 AAAA... comment): %v", err)
		}
		return pubKey, nil
	}
	if keyName == "" {
		return "", nil
	}
	st, err := loadState()
	if err != nil {
		return "", err
	}
	k, ok := st.Keys[keyName]
	if !ok {
		return "", out.NotFound("key", keyName)
	}
	return k.PublicKey, nil
}
