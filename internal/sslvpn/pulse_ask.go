package sslvpn

import (
	"encoding/binary"
	"fmt"
	"strconv"
	"strings"
)

// The questions a Pulse login asks a person: which realm or region, and
// whether they accept the sign-in notice. Each is one plain line, typed.

// choose picks one of the server's choices: the only one, or a person's.
// The person sees the choices as numbered lines and answers with the
// number or the name; a wrong answer is asked again, up to 3 times. An
// empty choice means the server takes free text.
func (s *pulseSession) choose(what string, options []string) (string, error) {
	if len(options) == 1 && options[0] != "" {
		return options[0], nil
	}
	if s.o.Prompt == nil {
		return "", ErrNeedsPerson
	}
	if options[0] == "" {
		v, err := s.o.Prompt(what, false)
		return strings.TrimSpace(v), err
	}
	var list strings.Builder
	fmt.Fprintf(&list, "The VPN offers more than one %s:\n", strings.ToLower(what))
	for i, o := range options {
		fmt.Fprintf(&list, "  %d  %s\n", i+1, o)
	}
	question := what + " (number or name)"
	label := list.String() + question
	var v string
	for range 3 {
		var err error
		if v, err = s.o.Prompt(label, false); err != nil {
			return "", err
		}
		if c, ok := pick(options, strings.TrimSpace(v)); ok {
			return c, nil
		}
		label = "Not one of the choices.\n" + question
	}
	return "", &LoginError{Msg: fmt.Sprintf("%q is not one of the VPN's choices (%s)", strings.TrimSpace(v), strings.Join(options, ", "))}
}

// pick finds the choice a person meant: its number in the list, its name,
// or its name in other upper and lower case when only one choice has it.
func pick(options []string, v string) (string, bool) {
	if n, err := strconv.Atoi(v); err == nil && n >= 1 && n <= len(options) {
		return options[n-1], true
	}
	var folded []string
	for _, o := range options {
		if o == v {
			return o, true
		}
		if strings.EqualFold(o, v) {
			folded = append(folded, o)
		}
	}
	if len(folded) == 1 {
		return folded[0], true
	}
	return "", false
}

// banner: a sign-in notice the server wants acknowledged; a person reads it.
func (s *pulseSession) banner(text string) ([]byte, error) {
	if s.o.Prompt == nil {
		return nil, ErrNeedsPerson
	}
	v, err := s.o.Prompt(strings.TrimSpace(text)+"\nAccept the sign-in notice? [y/N]", false)
	if err != nil {
		return nil, err
	}
	if a := strings.ToLower(strings.TrimSpace(v)); a != "y" && a != "yes" {
		return nil, &LoginError{Msg: "the sign-in notice was not accepted"}
	}
	return jnpAVP(nil, avpBannerOK, binary.BigEndian.AppendUint32(nil, 1)), nil
}
