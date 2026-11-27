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

// listCommands are the list commands of the kinds not listed by `<kind> list`.
// A saved recipe is a snippet to a person.
var listCommands = map[string]string{"key": "credential key list", "secret": "credential list", "recipe": "snippet list"}

// NotFound is the error for a name komando does not know, worded the one
// way S-8.4 asks: no <kind> named "<name>".
func NotFound(kind, name string) *Error {
	list, ok := listCommands[kind]
	if !ok {
		list = kind + " list"
		if kind == "vpn" {
			list = "list" // a VPN is listed under its kind, so `komando list` is the one command for all of them
		}
	}
	e := Errf(ExitNotFound, NotFoundCode(kind),
		fmt.Sprintf("see them with `komando %s`", list),
		"no %s named %q", KindWord(kind), name)
	if e.Code == "TARGET_NOT_FOUND" {
		e.wanted = kind
	}
	return e
}
