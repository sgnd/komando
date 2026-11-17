package cli

import (
	"encoding/json"
	"errors"
	"strconv"
	"strings"

	"github.com/sgnd/komando/internal/out"
	"github.com/sgnd/komando/internal/store"
)

// tunnelGuard: -R opens a port on the server, a change like any other, so
// a protected server needs a person's yes.
func tunnelGuard(cl *call, st *store.State, h *store.Host, kind string) error {
	if kind != "remote" {
		return nil
	}
	return guard(cl, st, []*store.Host{h}, "", true)
}

// tunnelPort says whether p is a port number from least to 65535.
func tunnelPort(p string, least int) bool {
	n, err := strconv.Atoi(p)
	return err == nil && n >= least && n <= 65535
}

// serveErr is how `tunnel serve` reports why it could not start, on its
// ERROR line, so that start gives the same code, exit and hint
// (HOSTKEY_MISMATCH, NO_AUTH, CONNECTION_REFUSED ...).
type serveErr struct {
	Code    string `json:"code"`
	Message string `json:"message"`
	Hint    string `json:"hint,omitempty"`
	Exit    int    `json:"exit"`
}

// tunnelErr is start's error for the ERROR line of its tunnel process.
func tunnelErr(line, kind, host, bind string) error {
	var e serveErr
	if json.Unmarshal([]byte(line), &e) != nil {
		e = serveErr{Message: line}
	}
	switch {
	case strings.Contains(e.Message, "address already in use"):
		return portInUse(bind, "this computer", errors.New(e.Message))
	case kind == "remote" && strings.Contains(e.Message, "request denied"):
		return out.Errf(out.ExitConflict, "PORT_IN_USE", "the port may be taken on "+host+" (pick another, or 0 for a free one), or sshd there has AllowTcpForwarding off",
			"%s refused to listen on %s: %s", host, bind, e.Message)
	case e.Code != "" && e.Code != "REMOTE_ERROR" && e.Exit != 0:
		return &out.Error{Code: e.Code, Message: e.Message, Hint: e.Hint, Exit: e.Exit}
	}
	return out.Errf(out.ExitConnect, "TUNNEL_FAILED", "check that the server allows forwarding (AllowTcpForwarding in sshd_config) and that the address is right", "%s", e.Message)
}
