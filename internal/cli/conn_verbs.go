package cli

import (
	"strings"

	"github.com/spf13/cobra"
)

// dataGroups are the command groups for one family of conns. Listing,
// removing, showing, editing and testing those conns is the same for every
// family, so it lives in `komando list`, `komando conn` and `komando test`.
var dataGroups = map[string]bool{"db": true, "cache": true, "queue": true, "storage": true, "cluster": true, "registry": true}

// inventoryVerbHint names the shared command for an inventory verb that a
// data group does not have (`komando db ls`, `komando cache show web1`),
// or "".
func inventoryVerbHint(group *cobra.Command, verb string) string {
	if !group.HasParent() || group.Parent().HasParent() || !dataGroups[group.Name()] {
		return ""
	}
	family := group.Name()
	switch strings.ToLower(verb) {
	case "ls", "list":
		return "list " + family + " conns with `komando list kind:" + family + "`"
	case "rm", "remove", "delete", "del":
		return "remove a conn with `komando conn rm TARGET`"
	case "show":
		return "show a conn's settings with `komando conn show NAME`"
	case "edit":
		return "change a conn with `komando conn edit NAME`"
	case "test":
		return "check that a conn answers with `komando test TARGET`"
	case "mv", "rename":
		return "rename a conn with `komando conn rename OLD NEW`"
	}
	return ""
}
