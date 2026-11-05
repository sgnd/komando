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

// isSelector: arg is a selector (@group, glob, tag:, label:, kind:, all,
// a list) rather than one name.
func isSelector(arg string) bool {
	return arg == "all" || strings.ContainsAny(arg, "@*?[,!") || strings.HasPrefix(arg, "tag:") ||
		strings.HasPrefix(arg, "label:") || strings.HasPrefix(arg, "kind:")
}

// pickHosts turns rm and edit arguments (names or selectors) into inventory hosts,
// each once, in order. Ad-hoc user@host targets are not in the inventory.
func pickHosts(s *store.State, args []string) ([]*store.Host, error) {
	var res []*store.Host
	seen := map[string]bool{}
	add := func(h *store.Host) {
		if !seen[h.Name] {
			seen[h.Name] = true
			res = append(res, h)
		}
	}
	for _, a := range args {
		if h, err := findHost(s, a); err == nil {
			add(h)
			continue
		} else if !isSelector(a) {
			return nil, err
		}
		sel, err := resolveSelection(s, a)
		if err != nil {
			return nil, err
		}
		n := 0
		for _, h := range sel.Hosts {
			if inv, ok := s.Hosts[h.Name]; ok && inv == h {
				add(h)
				n++
			}
		}
		if n == 0 {
			return nil, out.Errf(out.ExitNotFound, "HOST_NOT_FOUND", "run `komando list "+a+"` to see what it picks", "target %q picked no servers in the inventory", a)
		}
	}
	return res, nil
}

// rmConns is pickHosts for conns.
func rmConns(s *store.State, args []string) ([]*store.Conn, error) {
	var res []*store.Conn
	seen := map[string]bool{}
	for _, a := range args {
		var cs []*store.Conn
		if c, err := findConn(s, a); err == nil {
			cs = []*store.Conn{c}
		} else if !isSelector(a) {
			return nil, err
		} else {
			sel, err := resolveSelection(s, a)
			if err != nil {
				return nil, err
			}
			if cs = sel.Conns; len(cs) == 0 {
				return nil, out.Errf(out.ExitNotFound, "CONN_NOT_FOUND", "run `komando list "+a+"` to see what it picks", "target %q picked no conns", a)
			}
		}
		for _, c := range cs {
			if !seen[c.Name] {
				seen[c.Name] = true
				res = append(res, c)
			}
		}
	}
	return res, nil
}

// rmResult is what host rm and conn rm print.
type rmResult struct {
	Removed []string `json:"removed"`
}

func (r rmResult) Text() string {
	if g.dryRun {
		return "would remove: " + strings.Join(r.Removed, ", ")
	}
	return "removed: " + strings.Join(r.Removed, ", ")
}
