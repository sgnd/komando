package inventory

import (
	"strings"

	"github.com/sgnd/komando/internal/store"
)

// ViaChain splits a --via value ("vpn1,bastion") into its steps.
func ViaChain(via string) []string {
	var steps []string
	for _, s := range strings.Split(via, ",") {
		if s = strings.TrimSpace(s); s != "" {
			steps = append(steps, s)
		}
	}
	return steps
}

// WaySteps are the names on a --via path and on the paths of its servers.
func WaySteps(s *store.State, via string, seen map[string]bool) []string {
	var steps []string
	for _, n := range ViaChain(via) {
		if seen[n] {
			continue
		}
		seen[n] = true
		steps = append(steps, n)
		if h, ok := s.Hosts[n]; ok {
			steps = append(steps, WaySteps(s, h.Via, seen)...)
		}
	}
	return steps
}
