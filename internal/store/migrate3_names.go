package store

import (
	"regexp"
	"strconv"
	"strings"
)

// The names the format-3 migration makes (Audit M5): <key>-<user>,
// <secret>-<user>, <host>-agent, <host>-swarm, <entry>-<field>.

// madeNameRe is the name rule every entry and credential name follows
// (cli validName); a made name also has only [a-z0-9-].
var madeNameRe = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,62}$`)

const maxName = 63

// userSlug is user in lower case with every character outside [a-z0-9-]
// as one "-", no "-" at either end; an empty user is "default".
func userSlug(user string) string {
	var b strings.Builder
	dash := false
	for _, r := range strings.ToLower(user) {
		if r >= 'a' && r <= 'z' || r >= '0' && r <= '9' {
			b.WriteRune(r)
			dash = false
			continue
		}
		if !dash && b.Len() > 0 {
			b.WriteByte('-')
			dash = true
		}
	}
	s := strings.TrimSuffix(b.String(), "-")
	if s == "" {
		return "default"
	}
	return s
}

// nameMaker hands out names that clash with no name it was given or made,
// ignoring case.
type nameMaker struct{ taken map[string]bool }

func newNameMaker(existing []string) *nameMaker {
	m := &nameMaker{taken: map[string]bool{}}
	for _, n := range existing {
		m.taken[strings.ToLower(n)] = true
	}
	return m
}

// keep reserves name as it is (an old name that stays).
func (m *nameMaker) keep(name string) string {
	m.taken[strings.ToLower(name)] = true
	return name
}

// make is base-part under the name rule, with -2, -3, ... on a clash.
func (m *nameMaker) make(base, part string) string {
	n := userSlug(base + "-" + part)
	for i := 1; ; i++ {
		try := n
		if i > 1 {
			suf := "-" + strconv.Itoa(i)
			try = strings.TrimSuffix(cut(n, maxName-len(suf)), "-") + suf
		} else {
			try = strings.TrimSuffix(cut(n, maxName), "-")
		}
		if !m.taken[try] {
			m.taken[try] = true
			return try
		}
	}
}

func cut(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}
