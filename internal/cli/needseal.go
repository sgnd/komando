package cli

import (
	"strings"

	"github.com/spf13/cobra"

	"github.com/sgnd/komando/internal/store"
)

// komando keeps its data only in the sealed store (store.db). A folder of
// an earlier komando (state.json, vault.json, known_hosts, keys/) is moved
// with `komando seal` first; until then only these commands run, so a
// person can find out what to do and do it.
var sealFree = map[string]bool{
	"seal": true, "doctor": true, "version": true, "help": true, "guide": true,
	"schema": true, "completion": true, "__complete": true, "__completeNoDesc": true,
}

// checkNeedsSeal stops every other command on such a folder, for people,
// scripts and agents alike.
func checkNeedsSeal(cmd *cobra.Command) error {
	top, _, _ := strings.Cut(commandName(cmd), ".")
	if sealFree[top] || leavesHomeNow(cmd) || !store.NeedsSeal() {
		return nil
	}
	return store.ErrNeedsSeal()
}
