package cli

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"encoding/base32"
	"encoding/binary"
	"errors"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/sgnd/komando/internal/out"
	"github.com/sgnd/komando/internal/store"
	"github.com/sgnd/komando/internal/vault"
)

// An approval code makes komando's "Allow once" window a second factor: the
// person types the 6-digit code from their authenticator app (TOTP, RFC
// 6238), so one click by whoever sits at the screen, or a program that can
// click, is not enough. The code's secret is in the vault, which AI agents
// cannot read.

const approvalSecret = "komando-approval-totp"

// totp is the RFC 6238 code (HMAC-SHA1, 30 s steps, 6 digits) for step.
func totp(secret []byte, step int64) string {
	var msg [8]byte
	binary.BigEndian.PutUint64(msg[:], uint64(step))
	h := hmac.New(sha1.New, secret)
	h.Write(msg[:])
	sum := h.Sum(nil)
	off := sum[len(sum)-1] & 0x0f
	n := binary.BigEndian.Uint32(sum[off:]) & 0x7fffffff
	return fmt.Sprintf("%06d", n%1000000)
}

// codeOK checks a typed code against the steps around now (a phone's clock
// may be 30 s off).
func codeOK(secret []byte, code string, now time.Time) bool {
	code = strings.ReplaceAll(strings.TrimSpace(code), " ", "")
	if len(code) != 6 {
		return false
	}
	step := now.Unix() / 30
	for d := int64(-1); d <= 1; d++ {
		if hmac.Equal([]byte(totp(secret, step+d)), []byte(code)) {
			return true
		}
	}
	return false
}

// approvalCodeSecret is the enrolled secret, or nil when approval codes are off.
func approvalCodeSecret() []byte {
	st, err := store.Load()
	if err != nil || !st.Settings.ApprovalCode {
		return nil
	}
	v, err := vault.Get(approvalSecret)
	if err != nil {
		return []byte{} // on, but unreadable: no window can allow
	}
	b, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(v)
	if err != nil {
		return []byte{}
	}
	return b
}

// askCodeOnScreen shows the approval window with a hidden field for the
// code. It returns what was typed, whether the person pressed Allow, and
// whether a window could be shown at all.
var askCodeOnScreen = func(cl *call, text string) (code string, allowed, shown bool) {
	if cl.getenv("KOMANDO_NO_DIALOG") != "" || cl.getenv("SSH_CONNECTION") != "" || cl.getenv("SSH_TTY") != "" {
		return "", false, false
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	text += "\n\nType the code from your authenticator app:"
	switch runtime.GOOS {
	case "darwin":
		const script = `on run argv
set r to display dialog (item 1 of argv) with title "komando: allow?" default answer "" with hidden answer buttons {"Deny", "Allow once"} default button "Allow once" cancel button "Deny" giving up after 120 with icon caution
if gave up of r then return "gave up"
return (button returned of r) & linefeed & (text returned of r)
end run`
		b, err := exec.CommandContext(ctx, "/usr/bin/osascript", "-e", script, text).Output()
		var ee *exec.ExitError
		if err != nil && !errors.As(err, &ee) {
			return "", false, false
		}
		btn, typed, _ := strings.Cut(strings.TrimSpace(string(b)), "\n")
		noteGaveUp(text, btn == "gave up")
		return typed, btn == "Allow once", true
	case "linux", "freebsd", "openbsd":
		if cl.getenv("DISPLAY") == "" && cl.getenv("WAYLAND_DISPLAY") == "" {
			return "", false, false
		}
		if z := systemTool("zenity"); z != "" {
			b, err := exec.CommandContext(ctx, z, "--entry", "--hide-text", "--title=komando: allow?", "--text="+text, "--ok-label=Allow once", "--cancel-label=Deny", "--no-markup", "--timeout=120").Output()
			noteGaveUp(text, zenityTimedOut(err))
			return strings.TrimSpace(string(b)), err == nil, true
		}
		if k := systemTool("kdialog"); k != "" {
			b, err := exec.CommandContext(ctx, k, "--title", "komando: allow?", "--password", text).Output()
			return strings.TrimSpace(string(b)), err == nil, true
		}
	case "windows":
		code, allowed, gaveUp, shown := approvalWindow(text, true)
		noteGaveUp(text, gaveUp)
		return code, allowed, shown
	}
	return "", false, false
}

func approvalCodeCmd() *cobra.Command {
	var off bool
	c := &cobra.Command{
		Use:   "approval-code",
		Short: "Ask for an authenticator app code in the approval window",
		Long: `Sets up a one-time code (TOTP, like a bank or GitHub login) for komando's
"Allow once" window: once on, allowing an AI agent's --yes, --allow-dangerous
or --reveal needs the 6-digit code from the authenticator app on your phone,
not just a click. Only a person at a terminal can turn it on (the secret is
shown once, here); turning it off needs --yes, so that code too.`,
		Example: "  komando config approval-code          # shows a secret to add to your authenticator app\n  komando config approval-code --off --yes",
		Args:    cobra.NoArgs,
		RunE: inCall(func(cl *call, cmd *cobra.Command, args []string) error {
			if off {
				if err := guardSafety(cl, "turning off the approval code"); err != nil {
					return err
				}
				err := store.Update(cl.storeWrite(), func(st *store.State) error { st.Settings.ApprovalCode = false; return nil })
				if err == nil {
					_ = vault.Delete(cl.storeWrite(), approvalSecret)
				}
				audit(cl, nil, "config.approval-code", nil, "", err == nil, map[string]any{"approval_code": "off"})
				if err != nil {
					return err
				}
				cl.out.Print("config.approval-code", map[string]any{"approval_code": "off"}, nil)
				return nil
			}
			if cl.isAgent() || !cl.interactive() {
				return out.Errf(out.ExitPolicy, "NEEDS_PERSON", "a person runs `komando config approval-code` in their own terminal",
					"setting up the approval code shows its secret, so only a person at a terminal can do it")
			}
			raw := make([]byte, 20)
			rand.Read(raw)
			b32 := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(raw)
			host, _ := os.Hostname()
			uri := "otpauth://totp/" + url.PathEscape("komando:"+actor(cl)+"@"+host) + "?" + url.Values{"secret": {b32}, "issuer": {"komando"}}.Encode()
			fmt.Fprintf(cl.out.Err, "Add this to your authenticator app (it is shown only now):\n\n  secret: %s\n  or the link: %s\n\n", groupBy4(b32), uri)
			typed := ask(cl, "Type the 6-digit code the app shows now, to check it: ")
			if cl.interrupted { // Ctrl-C: nothing was changed
				return interruptedErr()
			}
			if !codeOK(raw, typed, time.Now()) {
				return out.Errf(out.ExitUsage, "CODE_WRONG", "check the phone's clock and run it again", "that code does not match; nothing was changed")
			}
			if err := vault.Set(cl.storeWrite(), approvalSecret, b32); err != nil {
				return err
			}
			if err := store.Update(cl.storeWrite(), func(st *store.State) error { st.Settings.ApprovalCode = true; return nil }); err != nil {
				return err
			}
			audit(cl, nil, "config.approval-code", nil, "", true, map[string]any{"approval_code": "on"})
			cl.out.Print("config.approval-code", map[string]any{"approval_code": "on"}, nil)
			return nil
		}),
	}
	c.Flags().BoolVar(&off, "off", false, "turn the approval code off (needs --yes)")
	return c
}

func groupBy4(s string) string {
	var parts []string
	for i := 0; i < len(s); i += 4 {
		parts = append(parts, s[i:min(i+4, len(s))])
	}
	return strings.Join(parts, " ")
}
