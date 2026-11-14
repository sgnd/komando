package komandosync

import "errors"

// The errors a device reports. Every attack the hostile server can make
// ends in one of them; none is silently accepted.
var (
	ErrChainBroken     = errors.New("komandosync: device list: wrong number, order or previous hash")
	ErrNotAuthorized   = errors.New("komandosync: device list: entry not signed by a key that may sign it")
	ErrYoungDevice     = errors.New("komandosync: a device added less than 7 days ago cannot remove an older device")
	ErrAccountMismatch = errors.New("komandosync: data from a different account")
	ErrRollback        = errors.New("komandosync: the server served an older state than this device has seen")
	ErrFork            = errors.New("komandosync: the server served a history that splits from what this device has seen")
	ErrListBehind      = errors.New("komandosync: a signed summary or write names a list entry the server did not serve")
	ErrMissingWrites   = errors.New("komandosync: writes named by a signed summary are missing")
	ErrRemoved         = errors.New("komandosync: this device was removed from the account")
	ErrNoKey           = errors.New("komandosync: no account key sealed to this device")
	ErrKeyMismatch     = errors.New("komandosync: the opened key does not match the key ID in the signed list")
	ErrPairingTypo     = errors.New("komandosync: the pairing code has a typo")
	ErrCheckCode       = errors.New("komandosync: pairing check code does not match")
	ErrPairingExpired  = errors.New("komandosync: pairing request older than 10 minutes")
	ErrPairingUsed     = errors.New("komandosync: pairing request already used")
	ErrKitNotConfirmed = errors.New("komandosync: type part of the recovery kit back before sync starts")
	ErrKitUnknown      = errors.New("komandosync: this recovery kit is not a current kit of this account")
	ErrKitTypo         = errors.New("komandosync: the recovery kit letters have a typo")
	ErrKitParts        = errors.New("komandosync: no two of these paper parts belong to one kit")
	ErrWaiting         = errors.New("komandosync: the change is still waiting")
	ErrCancelled       = errors.New("komandosync: the change was cancelled from another device")
	ErrKitReplaced     = errors.New("komandosync: the recovery kit that signed this change was replaced, so the change ended")
	ErrNoAuthority     = errors.New("komandosync: this device has no authority key")
	ErrBadWrite        = errors.New("komandosync: write refused")
	ErrListConflict    = errors.New("komandosync: another device added a list entry first")
	ErrListUnchecked   = errors.New("komandosync: could not check for removed devices before sealing a secret")
	ErrBadSnapshot     = errors.New("komandosync: snapshot refused")
	ErrNoRecord        = errors.New("komandosync: no live record of this type holds this name")
	ErrNameTaken       = errors.New("komandosync: two or more records hold this name; a person picks one first")
)

// protocolErrors are the answers of a check that ran. A list that fails
// one is never saved past; only a list that could not be read is.
var protocolErrors = []error{
	ErrChainBroken, ErrNotAuthorized, ErrAccountMismatch, ErrRollback, ErrFork,
	ErrRemoved, ErrNoKey, ErrKeyMismatch,
}
