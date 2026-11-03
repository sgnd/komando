package cli

import (
	"fmt"
	"sort"
	"strings"

	"github.com/spf13/pflag"

	"github.com/sgnd/komando/internal/out"
	"github.com/sgnd/komando/internal/store"
)

// Looking up one name the way people type it: exact first, then the one
// entry that differs only in case (Web1 for web1), else a not-found error
// with "did you mean".

// foldMatch returns the only name in names equal to n ignoring case.
func foldMatch(n string, names []string) (string, bool) {
	found := ""
	for _, c := range names {
		if strings.EqualFold(c, n) {
			if found != "" {
				return "", false // web1 and WEB1 both exist: ambiguous
			}
			found = c
		}
	}
	return found, found != ""
}

// notFoundSuggest is out.NotFound with a "did you mean" when a name is
// spelled almost the same.
func notFoundSuggest(kind, name string, names []string) *out.Error {
	e := out.NotFound(kind, name)
	if s := closest(name, names); s != "" {
		e.Hint = fmt.Sprintf("did you mean %q? (%s)", s, e.Hint)
	}
	return e
}

func mapKeys[V any](m map[string]V) []string {
	k := make([]string, 0, len(m))
	for n := range m {
		k = append(k, n)
	}
	sort.Strings(k)
	return k
}

func findHost(s *store.State, name string) (*store.Host, error) {
	if h, ok := s.Hosts[name]; ok {
		return h, nil
	}
	if n, ok := foldMatch(name, mapKeys(s.Hosts)); ok {
		return s.Hosts[n], nil
	}
	return nil, notFoundSuggest("host", name, mapKeys(s.Hosts))
}

func findConn(s *store.State, name string) (*store.Conn, error) {
	if c, ok := s.Conns[name]; ok {
		return c, nil
	}
	if n, ok := foldMatch(name, mapKeys(s.Conns)); ok {
		return s.Conns[n], nil
	}
	return nil, notFoundSuggest("conn", name, mapKeys(s.Conns))
}

func findKey(s *store.State, name string) (*store.Key, error) {
	if k, ok := s.Keys[name]; ok {
		return k, nil
	}
	return nil, keyNotFound(s, name)
}

func keyNotFound(s *store.State, name string) error {
	return notFoundSuggest("key", name, mapKeys(s.Keys))
}

// shortAlias adds --name/-short as another spelling of an existing flag:
// on edit commands -g and -t add a group or tag, like on add.
func shortAlias(fs *pflag.FlagSet, name, short, of string) {
	f := fs.Lookup(of)
	fs.AddFlag(&pflag.Flag{Name: name, Shorthand: short, Value: f.Value, DefValue: f.DefValue, Usage: "same as --" + of})
}
