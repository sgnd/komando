package out

import "fmt"

// notFoundCodes is the code of each kind NotFound knows, written out so
// the error catalog and agents can find every code in the source (S-8.1).
var notFoundCodes = map[string]string{
	"host":   "HOST_NOT_FOUND",
	"conn":   "CONN_NOT_FOUND",
	"vpn":    "VPN_NOT_FOUND",
	"job":    "JOB_NOT_FOUND",
	"key":    "KEY_NOT_FOUND",
	"recipe": "RECIPE_NOT_FOUND",
	"secret": "SECRET_NOT_FOUND",
	"tunnel": "TUNNEL_NOT_FOUND",
	"group":  "GROUP_NOT_FOUND",
}

// NotFoundCode is the code NotFound gives for kind ("NOT_FOUND" for a kind
// it does not know; TestErrorCodeCatalog keeps every caller's kind known).
func NotFoundCode(kind string) string {
	if c, ok := notFoundCodes[kind]; ok {
		return c
	}
	return "NOT_FOUND"
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

// NotFound is the error for a name komando does not know, worded the one
// way S-8.4 asks: no <kind> named "<name>".
func NotFound(kind, name string) *Error {
	e := Errf(ExitNotFound, NotFoundCode(kind),
		fmt.Sprintf("see them with `komando %s list`", kind),
		"no %s named %q", KindWord(kind), name)
	if t, ok := sharedThings[kind]; ok {
		e.Thing = t
	}
	return e
}

// sharedThings: the kinds whose not-found code another kind of item gives
// too (KEY_NOT_FOUND for cache keys, CONN_NOT_FOUND for a selector that
// picks no conns), so error.thing tells them apart.
var sharedThings = map[string]string{"key": "ssh_key", "conn": "conn"}
