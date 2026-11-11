package driver

import "sort"

// SQLKinds are the conn kinds ClassifySQL rates, sorted.
func SQLKinds() []string {
	k := make([]string, 0, len(dialects))
	for n := range dialects {
		k = append(k, n)
	}
	sort.Strings(k)
	return k
}
