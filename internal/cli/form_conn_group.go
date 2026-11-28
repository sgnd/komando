package cli

// The questions of the conn group, which the per-type paths replace. This
// file goes with the group (row C488, step P6).

func init() {
	promptKinds["conn"] = struct{ noun, add string }{"conns", "komando conn add"}
	edit := invEntryEdit
	edit.hide = []string{"group", "tag"}
	addFormHints(map[string]formHint{
		"conn": {},
		"conn add": {form: func(cl *call) []formGroup {
			var gs []formGroup
			for _, g := range formGroups(cl) {
				if g.label != "Server" && g.label != "VPN" {
					gs = append(gs, g)
				}
			}
			return gs
		}, next: []string{"test {}", "conn show {}"}},
		"conn edit":  edit,
		"conn kinds": {},
		"conn list": {args: []formArg{{ask: "Which conns? (leave empty for all)", pick: "conn", free: true,
			help: "Pick one, or type @group, kind:postgres or several names separated by commas."}}},
		"conn rename": {args: []formArg{{ask: "Which conn do you want to rename?", pick: "conn",
			help: "Groups, notes and everything else that names it are changed too."}, invNewName}},
		"conn rm": {args: []formArg{{ask: "Which conns should come off your list?", pick: "conn", free: true,
			help: "Only komando's list changes; the database, bucket or cluster itself is not touched."}}},
		"conn show": {args: []formArg{invConn}},
		"conn test": {args: []formArg{invConns}, flags: []formFlag{invWait}},
	})
}
