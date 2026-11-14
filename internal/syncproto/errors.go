package syncproto

import "errors"

// The errors a device reports. Every attack the hostile server can make
// ends in one of them; none is silently accepted.
var (
	ErrChainBroken     = errors.New("syncproto: device list: wrong number, order or previous hash")
	ErrNotAuthorized   = errors.New("syncproto: device list: entry not signed by a key that may sign it")
	ErrYoungDevice     = errors.New("syncproto: a device added less than 7 days ago cannot remove an older device")
	ErrAccountMismatch = errors.New("syncproto: data from a different account")
	ErrRollback        = errors.New("syncproto: the server served an older state than this device has seen")
	ErrFork            = errors.New("syncproto: the server served a history that splits from what this device has seen")
	ErrListBehind      = errors.New("syncproto: a signed summary or write names a list entry the server did not serve")
	ErrMissingWrites   = errors.New("syncproto: writes named by a signed summary are missing")
	ErrRemoved         = errors.New("syncproto: this device was removed from the account")
	ErrNoKey           = errors.New("syncproto: no account key sealed to this device")
	ErrKeyMismatch     = errors.New("syncproto: the opened key does not match the key ID in the signed list")
	ErrCheckCode       = errors.New("syncproto: pairing check code does not match")
	ErrPairingExpired  = errors.New("syncproto: pairing request older than 10 minutes")
	ErrPairingUsed     = errors.New("syncproto: pairing request already used")
	ErrKitNotConfirmed = errors.New("syncproto: type part of the recovery kit back before sync starts")
	ErrKitUnknown      = errors.New("syncproto: this recovery kit is not a current kit of this account")
	ErrKitTypo         = errors.New("syncproto: the recovery kit letters have a typo")
	ErrWaiting         = errors.New("syncproto: the change is still waiting")
	ErrCancelled       = errors.New("syncproto: the change was cancelled from another device")
	ErrNoAuthority     = errors.New("syncproto: this device has no authority key")
	ErrBadWrite        = errors.New("syncproto: write refused")
	ErrListConflict    = errors.New("syncproto: another device added a list entry first")
)
