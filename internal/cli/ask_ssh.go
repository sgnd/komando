package cli

import "sync"

// sshAskMu: one login question at a time. Servers that log in at once
// (`komando exec @web`) take turns, so each question stands on its own line
// with the name of the server that asks it.
var sshAskMu sync.Mutex

// askSSH is the question sshx.Asker gives a person at a terminal: what an SSH server's login
// asks (the password when none is stored, a one-time code, any other
// question) is shown with the server's name and answered there, as ssh
// does. Hidden questions stay hidden; Ctrl-C ends the login (CANCELLED).
func askSSH(cl *call, host, text string, hidden bool) (string, error) {
	sshAskMu.Lock()
	defer sshAskMu.Unlock()
	if r := []rune(text); len(r) > 2000 { // a server's question, not a page
		text = string(r[:2000])
	}
	return loginPrompt(cl, cleanText(host)+": "+text, hidden)
}
