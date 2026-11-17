package cli

import "github.com/sgnd/komando/internal/store"

// vetImportVpns returns the VPNs in st that vpns replace, after the
// checks vpn edit makes on such a change: an AI agent may not move a VPN
// whose login a person types (guardTypedLoginMove).
func vetImportVpns(cl *call, st *store.State, vpns []*store.Vpn) ([]*store.Vpn, error) {
	for _, v := range vpns {
		if err := guardTypedLoginMove(cl, st.Vpns[v.Name], v, ""); err != nil {
			return nil, err
		}
	}
	return vpnsReplaced(st, vpns), nil
}

// pickImportVpns are the VPNs of plan an import adds; skip says why one
// is left out, which goes to res.Skipped.
func pickImportVpns(plan *importPlan, skip func(kind, name string) string, res *importResult) []*store.Vpn {
	var vpns []*store.Vpn
	for _, v := range plan.Vpns {
		if r := skip("vpn", v.Name); r != "" {
			res.Skipped = append(res.Skipped, importSkip{v.Name, r})
			continue
		}
		vpns = append(vpns, v)
		res.Vpns = append(res.Vpns, v.Name)
	}
	return vpns
}
