package cli

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strings"

	"github.com/spf13/cobra"

	"github.com/sgnd/komando/internal/out"
	"github.com/sgnd/komando/internal/store"
	"github.com/sgnd/komando/internal/vault"
)

type doctorCheck struct {
	Name   string `json:"name"`
	OK     bool   `json:"ok"`
	Detail string `json:"detail"`
}

type doctorReport struct {
	Checks    []doctorCheck   `json:"checks"`
	Inventory []securityCheck `json:"inventory"`
	Security  []securityCheck `json:"security"`
	optional  map[string]bool
}

// Text is a list like `brew doctor`: ✓ fine, ✗ to fix, ! worth a look.
// A long detail wraps at 80 columns under the check's name (M-9) at a
// terminal; an AI agent, a pipe or a script reads each check on one line.
func (r doctorReport) Text() string {
	var b strings.Builder
	fails, warns := 0, 0
	width := out.StdoutWidth()
	if isAgent() {
		width = 0
	}
	line := func(mark, name, detail string) {
		head := mark + " " + doctorLabel(name)
		b.WriteString(head)
		if detail != "" {
			b.WriteString(": " + out.Wrap(detail, len([]rune(head))+2, width))
		}
		b.WriteString("\n")
	}
	for _, c := range r.Checks {
		switch {
		case c.OK:
			line("✓", c.Name, c.Detail)
		case r.optional[c.Name]:
			warns++
			line("!", c.Name, c.Detail)
		default:
			fails++
			line("✗", c.Name, c.Detail)
		}
	}
	for _, c := range append(append([]securityCheck{}, r.Inventory...), r.Security...) {
		switch {
		case c.Warning:
			warns++
			line("!", c.Name, c.Detail)
		case !c.OK:
			fails++
			line("✗", c.Name, c.Detail)
		default:
			line("✓", c.Name, c.Detail)
		}
	}
	switch {
	case fails == 0 && warns == 0:
		b.WriteString("\nAll good: komando is ready.\n")
	default:
		fmt.Fprintf(&b, "\n%s to fix, %s.\n", countOf(fails, "problem"), countOf(warns, "warning"))
	}
	return b.String()
}

// inventoryChecks finds settings komando would fail on later: bad ports,
// broken --via paths, missing files and secrets, plain-text passphrases,
// weak keys. Proxy commands are listed so a person knows they run here.
func inventoryChecks(st *store.State) []securityCheck {
	var cs []securityCheck
	fail := func(name, detail string) { cs = append(cs, securityCheck{Name: name, Detail: detail}) }
	warn := func(name, detail string) {
		cs = append(cs, securityCheck{Name: name, OK: true, Warning: true, Detail: detail})
	}
	secrets := map[string]bool{}
	for _, n := range secretNames() {
		secrets[n] = true
	}
	ref := func(name, flag, r string) {
		switch {
		case r == "":
		case !vault.ValidRef(r):
			fail(name, flag+" holds plain text instead of a reference: store it with `komando secret set NAME` and use secret:NAME")
		case strings.HasPrefix(r, "secret:") && !secrets[strings.TrimPrefix(r, "secret:")]:
			warn(name, flag+" "+r+" is not in the vault: `komando secret set "+strings.TrimPrefix(r, "secret:")+"`")
		}
	}
	for _, h := range st.SortedHosts() {
		name := "host:" + h.Name
		if err := validPort(h.Port); err != nil {
			fail(name, toErr(err).Message)
		}
		if err := checkHostVia(st, h); err != nil {
			fail(name, toErr(err).Message)
		}
		if h.Identity != "" {
			if _, err := os.Stat(expandHome(h.Identity)); err != nil {
				fail(name, "identity file "+h.Identity+" not found")
			}
		}
		if h.Key != "" && st.Keys[h.Key] == nil {
			fail(name, "uses missing key "+h.Key)
		}
		ref(name, "password_ref", h.PasswordRef)
		ref(name, "sudo_ref", h.SudoRef)
		if h.ProxyCommand != "" && h.ProxyCommand != ssmProxy {
			warn(name, "runs `"+h.ProxyCommand+"` on this computer to connect")
		}
	}
	for _, c := range st.SortedConns() {
		name := "conn:" + c.Name
		if c.Via != "" {
			if _, _, err := resolveVia(st, c.Via); err != nil {
				fail(name, toErr(err).Message)
			}
		}
		ref(name, "password_ref", c.PasswordRef)
		for _, r := range urlSecretRefs(c.URL) {
			ref(name, "URL option "+r.Option, "secret:"+r.Name)
		}
	}
	connHygiene(st, warn)
	for _, e := range cloudNamed(st) {
		warn(e.kind+":"+e.name, cloudNameText(e))
	}
	for _, n := range mapKeys(st.Keys) {
		k := st.Keys[n]
		name := "key:" + k.Name
		if store.SealedKey(k) {
			// a key komando made lives in the store: it must still open
			if _, err := store.ReadPrivateKey(k); err != nil {
				fail(name, "the key is missing from the store: "+err.Error())
			}
		} else if _, err := os.Stat(k.Path); err != nil {
			fail(name, k.Path+" not found")
		}
		ref(name, "passphrase_ref", k.PassphraseRef)
		if b := rsaBits(k.PublicKey); b > 0 && b < minRSABits {
			warn(name, fmt.Sprintf("RSA %d bits is weak: make a new key with `komando key gen` (ed25519)", b))
		}
	}
	return cs
}

// connHygiene warns about conns that work but are worth a look:
//   - an unprotected conn with the password secret of a protected server
//     or conn: that password is used without a person's yes, and changing
//     it for the protected one breaks this conn;
//   - two conns of the same kind with the same URL (user included) and
//     --via: one is enough;
//   - an unprotected conn with the label host=SERVER of a protected server.
func connHygiene(st *store.State, warn func(name, detail string)) {
	prot := map[string][]string{} // secret name → the protected targets using it
	for _, h := range st.SortedHosts() {
		for _, r := range []string{h.PasswordRef, h.SudoRef} {
			if n, ok := strings.CutPrefix(r, "secret:"); ok && h.Protected && !slices.Contains(prot[n], "server "+h.Name) {
				prot[n] = append(prot[n], "server "+h.Name)
			}
		}
	}
	for _, c := range st.SortedConns() {
		if n, ok := strings.CutPrefix(c.PasswordRef, "secret:"); ok && c.Protected {
			prot[n] = append(prot[n], "conn "+c.Name)
		}
	}
	same := map[string]string{} // kind, URL and via → the first conn with them
	for _, c := range st.SortedConns() {
		name := "conn:" + c.Name
		if n, ok := strings.CutPrefix(c.PasswordRef, "secret:"); ok && !c.Protected && len(prot[n]) > 0 {
			warn(name, fmt.Sprintf("is not protected but shares %s with protected %s: that password is used here without a person's yes, and changing it there breaks this conn; give it its own with `komando secret cp %s NEW` and `komando conn edit %s --password-ref secret:NEW`",
				c.PasswordRef, strings.Join(prot[n], ", "), n, c.Name))
		}
		key := c.Kind + "\x00" + c.URL + "\x00" + c.Via
		if first, ok := same[key]; ok {
			warn(name, "has the same kind, URL and --via as conn "+first+"; if they are the same thing, keep one: `komando conn rm "+c.Name+"`")
		} else {
			same[key] = c.Name
		}
		if h := st.Hosts[c.Labels["host"]]; h != nil && h.Protected && !c.Protected {
			warn(name, "has the label host="+h.Name+", a protected server, but is not protected itself: `komando conn edit "+c.Name+" --protected`")
		}
	}
}

func doctorCmd() *cobra.Command {
	var acceptOld bool
	c := &cobra.Command{
		Use:   "doctor",
		Short: "Check komando's setup, your list and its security",
		Long: `Checks komando's folder, vault, audit log and tools, then your list:
ports, --via paths, key files, secrets that references point at, plain-text
passphrases, weak keys, proxy commands, and conns that share a protected
password, repeat another conn or belong to a protected server without being
protected. ✗ lines need fixing (exit 1); ! lines are worth a look.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if acceptOld {
				return acceptOldCopy()
			}
			defer lookAtOldCopy()() // doctor must be able to say what is wrong
			r := doctorReport{optional: map[string]bool{"ssh_agent": true, "openssh_client": true, "hosts": true, "agent_skill": true, "agent_guard": true}}
			add := func(name string, ok bool, detail string) { r.Checks = append(r.Checks, doctorCheck{name, ok, detail}) }
			st, err := loadState()
			add("state", err == nil, store.Home())
			if err != nil {
				out.P.Print("doctor", r, toErr(err))
				return exitCode(1)
			}
			if st.Settings.Audit {
				add("audit_log", true, "sealed in "+store.Path(store.StoreFile))
			}
			hostDetail := countOf(len(st.Hosts), "server")
			if len(st.Hosts) == 0 {
				hostDetail = "none yet; add with `komando host add` or `komando import ssh-config`"
			}
			add("hosts", len(st.Hosts) > 0, hostDetail)
			add("keys", true, countOf(len(st.Keys), "SSH key"))
			sock := os.Getenv("SSH_AUTH_SOCK")
			add("ssh_agent", sock != "", map[bool]string{true: sock, false: "not running (optional)"}[sock != ""])
			_, sshErr := exec.LookPath("ssh")
			add("openssh_client", sshErr == nil, "optional; komando has a built-in SSH client")
			for _, v := range st.SortedVpns() { // programs the registered VPNs need
				for _, bin := range vpnClients(v) {
					_, err := exec.LookPath(bin)
					add("vpn:"+v.Name+":"+bin, err == nil, map[bool]string{true: "installed", false: installHint(bin)}[err == nil])
				}
			}
			add("platform", true, runtime.GOOS+"/"+runtime.GOARCH)
			// AI agents: the skill komando installs, and whether it is this
			// version's (an update needs `guide install` again)
			installed, stale := skillStatus()
			switch {
			case len(installed) == 0:
				add("agent_skill", false, "no AI agent has komando's skill yet: `komando guide install` teaches Claude Code, Codex, Cursor and Gemini CLI to use komando")
			case len(stale) > 0:
				detail := "from another komando version in " + strings.Join(stale, ", ") + ": run `komando guide install` again, so your AI agents use this version's commands"
				if cites := skillCites(stale); len(cites) > 0 {
					detail += "; it still teaches old spellings that go away in a later release: use " + strings.Join(cites, ", ")
				}
				add("agent_skill", false, detail)
			default:
				add("agent_skill", true, strings.Join(installed, ", "))
			}
			if home, err := os.UserHomeDir(); err == nil && len(installed) > 0 && slices.ContainsFunc(installed, func(p string) bool { return strings.Contains(p, ".claude") }) {
				switch found, problem := claudeGuard(filepath.Join(home, ".claude", "settings.json")); {
				case !found:
					add("agent_guard", false, "Claude Code runs without komando's guard, which keeps it away from secret files: `komando guide install` adds it")
				case problem != "":
					add("agent_guard", false, "komando's guard in Claude Code cannot run, so Claude Code goes on without it: "+problem+"; `komando guide install` sets it up again")
				default:
					add("agent_guard", true, "Claude Code asks komando before reading files or running shell commands")
				}
			}
			r.Inventory = inventoryChecks(st)
			r.Security = securityChecks(st)
			ok := true
			for _, c := range r.Checks {
				if !c.OK && !r.optional[c.Name] {
					ok = false
				}
			}
			for _, c := range append(append([]securityCheck{}, r.Inventory...), r.Security...) {
				if !c.OK {
					ok = false
				}
			}
			if r.Inventory == nil {
				r.Inventory = []securityCheck{}
			}
			var soft *out.Error
			if !ok {
				soft = out.Errf(out.ExitError, "DOCTOR_FAILED", "fix the checks marked ✗ (ok: false in -o json), then run `komando doctor` again", "some checks failed")
			}
			out.P.Print("doctor", r, soft)
			if soft != nil {
				return exitCode(1)
			}
			return nil
		},
	}
	c.Flags().BoolVar(&acceptOld, "accept-old-copy", false, "use the komando folder as it is now after a restore from a backup, though it is older than the keychain remembers (a person only)")
	return c
}
