package sshx

import (
	"errors"
	"strings"
	"sync"
	"testing"

	"golang.org/x/crypto/ssh"

	"github.com/sgnd/komando/internal/out"
	"github.com/sgnd/komando/internal/store"
)

// askServer is a server that logs in with keyboard-interactive questions,
// round by round, each with its own right answer, and can also offer the
// password method.
type askServer struct {
	rounds   [][]string        // the questions, round by round
	want     map[string]string // question → the answer it takes
	echo     bool
	password string // also offer the password method, which takes this

	mu  sync.Mutex
	got []string // every answer that came, in order
}

func (s *askServer) start(t *testing.T) (string, int) {
	t.Helper()
	cfg := &ssh.ServerConfig{}
	kbd := func(_ ssh.ConnMetadata, ask ssh.KeyboardInteractiveChallenge) (*ssh.Permissions, error) {
		for _, qs := range s.rounds {
			echos := make([]bool, len(qs))
			for i := range echos {
				echos[i] = s.echo
			}
			ans, err := ask("", "Two-factor login for web1", qs, echos)
			if err != nil {
				return nil, err
			}
			s.mu.Lock()
			s.got = append(s.got, ans...)
			s.mu.Unlock()
			for i, q := range qs {
				if i >= len(ans) || ans[i] != s.want[q] {
					return nil, errors.New("wrong")
				}
			}
		}
		return nil, nil
	}
	if len(s.rounds) > 0 {
		cfg.KeyboardInteractiveCallback = kbd
	}
	if s.password != "" {
		cfg.PasswordCallback = func(_ ssh.ConnMetadata, pw []byte) (*ssh.Permissions, error) {
			s.mu.Lock()
			s.got = append(s.got, string(pw))
			s.mu.Unlock()
			if string(pw) == s.password {
				return nil, nil
			}
			return nil, errors.New("wrong")
		}
	}
	return loginSSHD(t, cfg, nil)
}

type asked struct {
	host, text string
	hidden     bool
}

// withPerson runs the rest of a test with a person at the terminal who
// answers each question with the first answer whose key the question
// holds (or with err), and returns what they were asked.
func withPerson(t *testing.T, answers map[string]string, err error) *[]asked {
	t.Helper()
	var mu sync.Mutex
	got := &[]asked{}
	saved := Ask
	Ask = func(host, text string, hidden bool) (string, error) {
		mu.Lock()
		defer mu.Unlock()
		*got = append(*got, asked{host, text, hidden})
		if err != nil {
			return "", err
		}
		for k, v := range answers {
			if strings.Contains(text, k) {
				return v, nil
			}
		}
		return "no answer", nil
	}
	t.Cleanup(func() { Ask = saved })
	return got
}

// A person at the terminal is asked what komando cannot answer by itself,
// as ssh asks: the password when none is stored, a one-time code, any other
// question. The stored password still goes out once, and only to a hidden
// password question.
func TestPersonAnswersTheLogin(t *testing.T) {
	const pw, code = "s3cret-Pass", "492817"
	cases := []struct {
		name   string
		srv    *askServer
		stored string
		answer map[string]string
		ok     bool
		asks   []string // the questions the person saw, in order
		hidden bool
		sent   []string // the answers the server got
	}{
		{name: "no password stored: the person types it",
			srv:    &askServer{rounds: [][]string{{"Password: "}}, want: map[string]string{"Password: ": pw}},
			answer: map[string]string{"Password": pw}, ok: true, asks: []string{"Password: "}, hidden: true, sent: []string{pw}},
		{name: "stored password, then the code from the person",
			srv:    &askServer{rounds: [][]string{{"Password: "}, {"Verification code: "}}, want: map[string]string{"Password: ": pw, "Verification code: ": code}},
			stored: pw, answer: map[string]string{"Verification code": code}, ok: true, asks: []string{"Verification code: "}, hidden: true, sent: []string{pw, code}},
		{name: "password and code in one round",
			srv:    &askServer{rounds: [][]string{{"Password: ", "One-time token: "}}, want: map[string]string{"Password: ": pw, "One-time token: ": code}},
			answer: map[string]string{"Password": pw, "One-time": code}, ok: true, asks: []string{"Password: ", "One-time token: "}, hidden: true, sent: []string{pw, code}},
		{name: "a shown question stays shown",
			srv:    &askServer{rounds: [][]string{{"Passcode or option (1-3): "}}, want: map[string]string{"Passcode or option (1-3): ": "1"}, echo: true},
			answer: map[string]string{"option": "1"}, ok: true, asks: []string{"Passcode or option (1-3): "}, sent: []string{"1"}},
		{name: "the password method, when it is the only one",
			srv:    &askServer{password: pw},
			answer: map[string]string{"Password": pw}, ok: true, asks: []string{"Password: "}, hidden: true, sent: []string{pw}},
		{name: "a refused stored password is not sent again, and the person is not asked for it",
			srv:    &askServer{rounds: [][]string{{"Password: "}}, want: map[string]string{"Password: ": "new-pass"}, password: "new-pass"},
			stored: "old-pass", answer: map[string]string{"Password": "new-pass"}, sent: []string{"old-pass"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dialHome(t)
			who := withPerson(t, tc.answer, nil)
			host, port := tc.srv.start(t)
			h := &store.Host{Name: "web1", Address: host, Port: port, User: "u"}
			if tc.stored != "" {
				t.Setenv("KOMANDO_TEST_PW", tc.stored)
				h.PasswordRef = "env:KOMANDO_TEST_PW"
			}
			err := dialHost(newState(h), h)
			if tc.ok && err != nil {
				t.Fatal(err)
			}
			if !tc.ok {
				if oe := asOutErr(t, err); oe.Code != "AUTH_FAILED" {
					t.Fatalf("got %s: %s", oe.Code, oe.Message)
				}
			}
			var texts []string
			for _, a := range *who {
				// the server's instruction comes with its first question
				texts = append(texts, strings.TrimPrefix(a.text, "Two-factor login for web1\n"))
				if a.host != "web1" || a.hidden != tc.hidden {
					t.Errorf("asked %+v; want host web1, hidden %v", a, tc.hidden)
				}
			}
			if strings.Join(texts, "|") != strings.Join(tc.asks, "|") {
				t.Errorf("the person was asked %q, want %q", texts, tc.asks)
			}
			tc.srv.mu.Lock()
			defer tc.srv.mu.Unlock()
			if strings.Join(tc.srv.got, "|") != strings.Join(tc.sent, "|") {
				t.Errorf("the server got %q, want %q", tc.srv.got, tc.sent)
			}
		})
	}
}

// Ctrl-C at a login question ends the login with CANCELLED, and the person
// is not asked again by the next method.
func TestPersonCancelsTheLogin(t *testing.T) {
	dialHome(t)
	cancelled := &out.Error{Code: "CANCELLED", Message: "interrupted", Exit: out.ExitError}
	who := withPerson(t, nil, cancelled)
	srv := &askServer{rounds: [][]string{{"Verification code: "}}, want: map[string]string{"Verification code: ": "1"}, password: "pw"}
	host, port := srv.start(t)
	h := &store.Host{Name: "web1", Address: host, Port: port, User: "u"}
	if oe := asOutErr(t, dialHost(newState(h), h)); oe.Code != "CANCELLED" {
		t.Fatalf("got %s: %s", oe.Code, oe.Message)
	}
	if len(*who) != 1 {
		t.Errorf("asked %d times after Ctrl-C: %+v", len(*who), *who)
	}
	if len(srv.got) != 0 {
		t.Errorf("the server got answers: %q", srv.got)
	}
}

// With no one at the terminal (an AI agent, a script), nothing is asked: a
// code question stops the login with a hint that sends a person to run it.
func TestNoPersonNoQuestions(t *testing.T) {
	dialHome(t)
	saved := Ask
	Ask = nil
	t.Cleanup(func() { Ask = saved })
	t.Setenv("KOMANDO_TEST_PW", "pw")
	srv := &askServer{rounds: [][]string{{"Password: "}, {"Verification code: "}}, want: map[string]string{"Password: ": "pw", "Verification code: ": "1"}}
	host, port := srv.start(t)
	h := &store.Host{Name: "web1", Address: host, Port: port, User: "u", PasswordRef: "env:KOMANDO_TEST_PW"}
	oe := asOutErr(t, dialHost(newState(h), h))
	if oe.Code != "AUTH_FAILED" || !strings.Contains(oe.Message, "only a person can answer it") ||
		!strings.Contains(oe.Hint, "komando asks you for the code there") || strings.Contains(oe.Hint, "ssh-command") {
		t.Errorf("%s: %s / %s", oe.Code, oe.Message, oe.Hint)
	}
}
