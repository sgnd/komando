package cloud

import "os"

// UnlockEnv reads a variable that unlocks a secret store
// (KOMANDO_BW_PASSWORD, KOMANDO_KDBX_PASSWORD, OP_CONNECT_TOKEN,
// VAULT_TOKEN...). komando's vault sets it to also find the values it
// took out of the environment when it started (vault.TakeUnlockEnv), so
// the programs komando starts never inherit them.
var UnlockEnv = os.Getenv
