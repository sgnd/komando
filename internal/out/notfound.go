package out

import "fmt"

// notFoundCodes is the code of each kind NotFound knows, written out so
// the error catalog and agents can find every code in the source (S-8.1).
var notFoundCodes = map[string]string{
	"host":   "TARGET_NOT_FOUND",
	"conn":   "TARGET_NOT_FOUND",
	"vpn":    "TARGET_NOT_FOUND",
	"job":    "JOB_NOT_FOUND",
	"key":    "SSH_KEY_NOT_FOUND",
	"recipe": "RECIPE_NOT_FOUND",
	"secret": "SECRET_NOT_FOUND",
	"tunnel": "TUNNEL_NOT_FOUND",
	"group":  "GROUP_NOT_FOUND",
}

// NotFoundCode is the code NotFound gives for kind. A server, conn and VPN
// share one: a name komando does not know, whatever kind was meant.
// TestNotFoundKinds keeps every caller's kind in notFoundCodes.
func NotFoundCode(kind string) string {
	if c, ok := notFoundCodes[kind]; ok {
		return c
	}
	panic("out.NotFound: no code for kind " + kind)
}

// KindWord is the word people read for an inventory kind: a host is a
// server, a key an SSH key (S-8.4). Codes and commands keep the kind.
func KindWord(kind string) string {
	switch kind {
	case "host":
		return "server"
	case "vpn":
		return "VPN"
	case "key":
		return "SSH key"
	}
	return kind
}

// listCommand is the command that lists the entries of kind: a server is
// listed by the provider groups, so the plain `komando list` shows all.
func listCommand(kind string) string {
	switch kind {
	case "host":
		return "list"
	case "tunnel":
		return "host ssh tunnel list"
	}
	return kind + " list"
}

// NotFound is the error for a name komando does not know, worded the one
// way S-8.4 asks: no <kind> named "<name>".
func NotFound(kind, name string) *Error {
	e := Errf(ExitNotFound, NotFoundCode(kind),
		"see them with `komando "+listCommand(kind)+"`",
		"no %s named %q", KindWord(kind), name)
	if e.Code == "TARGET_NOT_FOUND" {
		e.wanted = kind
	}
	return e
}
