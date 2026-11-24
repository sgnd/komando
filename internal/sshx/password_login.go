package sshx

import (
	"strconv"
	"strings"
	"unicode"

	"golang.org/x/crypto/ssh"

	"github.com/sgnd/komando/internal/out"
	"github.com/sgnd/komando/internal/store"
)

// passwordLogin answers the server's login questions. The stored password
// goes out at most once per login (the password method and
// keyboard-interactive share it), and in keyboard-interactive only to a
// hidden question that asks for a password: a refused one is not sent
// again, so a wrong password in the vault cannot lock the account. With a
// person to ask (ask), every other question goes to them; without one, a
// one-time code or any other question gets no answer and the login stops
// before a wrong answer counts against the account.
type passwordLogin struct {
	pw string // the stored password, "" when none is stored
	// typed gives the password of a login-ask server: a person types it
	// when the server first asks; it is never stored (LoginPassword)
	typed    func() (string, func(), error)
	got      bool   // typed gave the password (pw), or failed (typedErr)
	typedErr error  // why typed gave none
	refused  func() // tells typed's source the server refused it
	sent     bool
	ask      func(text string, hidden bool) (string, error) // nil: no person at a terminal
	stop     error                                          // the person cancelled: every later question ends the same way
}

// has reports a password to send: a stored one, or one a person types
// (login ask).
func (p *passwordLogin) has() bool { return p.pw != "" || p.typed != nil }

// password is the stored password, or the typed one, asked once.
func (p *passwordLogin) password() (string, error) {
	if p.typed == nil || p.got {
		return p.pw, p.typedErr
	}
	p.got = true
	pw, refused, err := p.typed()
	if err != nil {
		p.typedErr = err
		return "", err
	}
	p.pw, p.refused = pw, refused
	return pw, nil
}

// again is the answer when the server asks for the password once more: it
// refused the one sent, which is not sent again (nor kept for the next
// connection of the command, when a person typed it).
// question is the server's, made safe to show.
func (p *passwordLogin) again(question string) error {
	if p.refused != nil {
		p.refused()
	}
	return &unanswered{question: question, kind: askAgain, typed: p.typed != nil}
}

func (p *passwordLogin) methods() []ssh.AuthMethod {
	if p.ask == nil {
		pwm := p.retry(ssh.PasswordCallback(func() (string, error) {
			if p.sent {
				return "", p.again("Password:")
			}
			pw, err := p.password()
			if err != nil {
				return "", err
			}
			p.sent = true
			return pw, nil
		}))
		return []ssh.AuthMethod{pwm, ssh.KeyboardInteractive(p.answer)}
	}
	// keyboard-interactive first, as OpenSSH tries them: a two-factor
	// server asks the password and the code there, so a person types the
	// password once, not once per method
	return []ssh.AuthMethod{
		ssh.KeyboardInteractive(p.answer),
		p.retry(ssh.PasswordCallback(func() (string, error) {
			switch {
			case !p.has():
				return p.askPerson("Password: ", true)
			case p.sent:
				return "", p.again("Password:")
			}
			pw, err := p.password()
			if err != nil {
				return "", err
			}
			p.sent = true
			return pw, nil
		})),
	}
}

// retry lets the password method of a login-ask server be tried once more
// after the server refused the typed password: that try ends the login
// (again) rather than send it twice, and the command forgets it.
func (p *passwordLogin) retry(m ssh.AuthMethod) ssh.AuthMethod {
	if p.typed == nil {
		return m
	}
	return ssh.RetryableAuthMethod(m, 2)
}

func (p *passwordLogin) answer(_, instruction string, questions []string, echos []bool) ([]string, error) {
	answers := make([]string, len(questions))
	sent := p.sent
	for i, q := range questions {
		echo := i < len(echos) && echos[i]
		kind := questionKind(q, echo)
		switch {
		case kind == askPassword && p.has() && !sent:
			pw, err := p.password()
			if err != nil {
				return nil, err
			}
			answers[i], sent = pw, true
			continue
		case kind == askPassword && p.has():
			return nil, p.again(cleanQuestion(q)) // the stored (or typed) one went out and was refused
		case p.ask != nil:
			text := q
			if i == 0 && strings.TrimSpace(instruction) != "" {
				text = strings.TrimSpace(instruction) + "\n" + q
			}
			a, err := p.askPerson(text, !echo)
			if err != nil {
				return nil, err
			}
			answers[i] = a
			continue
		}
		if kind == askPassword {
			kind = askOther // no password stored and no one to ask
		}
		return nil, &unanswered{question: cleanQuestion(q), kind: kind}
	}
	p.sent = sent
	return answers, nil
}

// askPerson asks the person at the terminal. After a Ctrl-C every later
// question ends the same way at once: the person wants out.
func (p *passwordLogin) askPerson(text string, hidden bool) (string, error) {
	if p.stop != nil {
		return "", p.stop
	}
	a, err := p.ask(text, hidden)
	if err != nil {
		p.stop = err
	}
	return a, err
}

// The kinds of keyboard-interactive question.
const (
	askPassword = iota // a hidden question for the password
	askCode            // a one-time code: a two-factor login
	askAgain           // the password once more: the server refused it
	askOther           // anything else (a shown answer, a username, a menu)
)

var (
	codeWords     = []string{"one-time", "one time", "onetime", "code", "token", "otp", "passcode", "verification"}
	passwordWords = []string{"password", "passwort", "mot de passe", "contraseña", "senha", "wachtwoord"}
)

// questionKind sorts a keyboard-interactive question. A user@host in it
// (OpenSSH shows "(user@host) Password:") does not count.
func questionKind(q string, echo bool) int {
	var words []string
	for _, f := range strings.Fields(strings.ToLower(q)) {
		if !strings.Contains(f, "@") {
			words = append(words, f)
		}
	}
	l := strings.Join(words, " ")
	for _, w := range codeWords {
		if strings.Contains(l, w) {
			return askCode
		}
	}
	if echo {
		return askOther
	}
	for _, w := range passwordWords {
		if strings.Contains(l, w) {
			return askPassword
		}
	}
	return askOther
}

// cleanQuestion makes a server's question safe to show: printable
// characters only, one line, at most 80 characters.
func cleanQuestion(q string) string {
	q = strings.Map(func(r rune) rune {
		if unicode.IsPrint(r) {
			return r
		}
		return ' '
	}, q)
	q = strings.Join(strings.Fields(q), " ")
	if r := []rune(q); len(r) > 80 {
		q = string(r[:79]) + "…"
	}
	return q
}

// unanswered is a keyboard-interactive question komando gave no answer;
// the login stops there.
type unanswered struct {
	question string // the server's words, made safe to show
	kind     int
	typed    bool // askAgain: the refused password was typed (login ask), not stored
}

func (e *unanswered) Error() string { return "the server asks " + strconv.Quote(e.question) }

// authFailed is the AUTH_FAILED error that quotes the question.
func (e *unanswered) authFailed(st *store.State, h *store.Host) *out.Error {
	name := h.Name
	// Asker gave no question: no person at a terminal (an AI agent, a script, a
	// background process). A person who runs the command is asked.
	switch e.kind {
	case askCode:
		return out.Errf(out.ExitConnect, "AUTH_FAILED",
			PersonStep(name)+": komando asks for the code once and keeps the session, so later commands (an AI agent's too) need no code",
			"%s asks %s (two-factor login); only a person can answer it, and none is at a terminal here", name, strconv.Quote(e.question))
	case askAgain:
		if e.typed {
			return out.Errf(out.ExitConnect, "AUTH_FAILED", authFailedHint(st, h),
				"%s refused the password typed for it; komando sends a typed password once per login", name)
		}
		return out.Errf(out.ExitConnect, "AUTH_FAILED", authFailedHint(st, h),
			"%s asks %s again: it refused the stored password, which komando sends only once", name, strconv.Quote(e.question))
	}
	return out.Errf(out.ExitConnect, "AUTH_FAILED",
		PersonStep(name)+": komando shows the question once and keeps the session, so later commands (an AI agent's too) need no answer",
		"%s asks %s; komando answers only a hidden password question by itself, and no person is at a terminal here", name, strconv.Quote(e.question))
}
