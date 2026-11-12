package cli

import (
	"strings"

	"github.com/sgnd/komando/internal/out"
	"github.com/sgnd/komando/internal/store"
)

// --via paths: the VPN and SSH hops in front of a server or conn.

// resolveVia turns a --via chain ("office,bastion,db1") into what to dial:
// the last host, reached through the steps before it (sshx opens a VPN
// first step itself), or, when the path is only a VPN, that VPN. A chain
// given here replaces the last host's own --via; a single host keeps its own.
func resolveVia(st *store.State, via string) (*store.Host, *store.Vpn, error) {
	steps := viaChain(via)
	if len(steps) == 0 {
		return nil, nil, out.Usage("--via is empty: give server or VPN names, e.g. --via bastion")
	}
	if err := viaTwice(steps); err != nil {
		return nil, nil, err
	}
	for i, s := range steps {
		if _, ok := st.Vpns[s]; ok {
			if i > 0 {
				return nil, nil, out.Errf(out.ExitUsage, "VIA_ORDER", "put the VPN first: --via "+s+","+steps[0],
					"a VPN can only be the first step of a --via path")
			}
			continue
		}
		if _, ok := st.Hosts[s]; !ok {
			return nil, nil, out.Errf(out.ExitNotFound, "VIA_NOT_FOUND", "--via takes server and VPN names; see `komando list`",
				"no server or VPN named %q", s)
		}
	}
	last := steps[len(steps)-1]
	if v, ok := st.Vpns[last]; ok {
		return nil, v, nil
	}
	h := st.Hosts[last]
	if len(steps) > 1 {
		cp := *h
		cp.Via = strings.Join(steps[:len(steps)-1], ",")
		h = &cp
	}
	return h, nil, nil
}

// viaTwice refuses a --via path that names a step twice (office,office or
// a,b,a): a typo, and a VPN named twice was told to "put the VPN first".
func viaTwice(steps []string) error {
	seen := map[string]bool{}
	for _, s := range steps {
		k := strings.ToLower(s)
		if seen[k] {
			return out.Errf(out.ExitUsage, "VIA_CYCLE", "name each server or VPN once: --via "+strings.Join(dedupeFold(steps), ","),
				"%s is twice in the --via path %s", s, strings.Join(steps, ","))
		}
		seen[k] = true
	}
	return nil
}

// dedupeFold keeps the first of names that differ only in case.
func dedupeFold(names []string) []string {
	var keep []string
	seen := map[string]bool{}
	for _, n := range names {
		if k := strings.ToLower(n); !seen[k] {
			seen[k] = true
			keep = append(keep, n)
		}
	}
	return keep
}
