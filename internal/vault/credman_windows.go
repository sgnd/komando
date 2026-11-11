//go:build windows

package vault

import (
	"errors"
	"unsafe"

	"golang.org/x/sys/windows"
)

// The vault key in the Windows Credential Manager: a generic credential
// named after this komando home (keychainService), kept for this user on
// this computer only (not roaming), read and written with the advapi32
// calls directly.

var (
	advapi32       = windows.NewLazySystemDLL("advapi32.dll")
	procCredReadW  = advapi32.NewProc("CredReadW")
	procCredWriteW = advapi32.NewProc("CredWriteW")
	procCredDelete = advapi32.NewProc("CredDeleteW")
	procCredFree   = advapi32.NewProc("CredFree")
)

const (
	credTypeGeneric     = 1
	credPersistLocalMac = 2
)

// credential is the Win32 CREDENTIALW structure.
type credential struct {
	Flags              uint32
	Type               uint32
	TargetName         *uint16
	Comment            *uint16
	LastWritten        windows.Filetime
	CredentialBlobSize uint32
	CredentialBlob     *byte
	Persist            uint32
	AttributeCount     uint32
	Attributes         uintptr
	TargetAlias        *uint16
	UserName           *uint16
}

func credAvailable() error {
	if err := procCredReadW.Find(); err != nil {
		return errors.New("the Windows Credential Manager is not available on this computer")
	}
	return nil
}

// credRead is the blob stored under target; errNoKeychainKey when there is none.
func credRead(target string) ([]byte, error) {
	t, err := windows.UTF16PtrFromString(target)
	if err != nil {
		return nil, err
	}
	var c *credential
	r, _, e := procCredReadW.Call(uintptr(unsafe.Pointer(t)), credTypeGeneric, 0, uintptr(unsafe.Pointer(&c)))
	if r == 0 {
		if errors.Is(e, windows.ERROR_NOT_FOUND) {
			return nil, errNoKeychainKey
		}
		return nil, e
	}
	defer procCredFree.Call(uintptr(unsafe.Pointer(c)))
	b := make([]byte, c.CredentialBlobSize)
	if c.CredentialBlobSize > 0 {
		copy(b, unsafe.Slice(c.CredentialBlob, c.CredentialBlobSize))
	}
	return b, nil
}

// credWrite stores blob under target, replacing what is there.
func credWrite(target, user string, blob []byte) error {
	t, err := windows.UTF16PtrFromString(target)
	if err != nil {
		return err
	}
	u, err := windows.UTF16PtrFromString(user)
	if err != nil {
		return err
	}
	c := credential{Type: credTypeGeneric, TargetName: t, UserName: u, Persist: credPersistLocalMac,
		CredentialBlobSize: uint32(len(blob))}
	if len(blob) > 0 {
		c.CredentialBlob = &blob[0]
	}
	if r, _, e := procCredWriteW.Call(uintptr(unsafe.Pointer(&c)), 0); r == 0 {
		return e
	}
	return nil
}

// credDelete removes target; none there is fine.
func credDelete(target string) error {
	t, err := windows.UTF16PtrFromString(target)
	if err != nil {
		return err
	}
	if r, _, e := procCredDelete.Call(uintptr(unsafe.Pointer(t)), credTypeGeneric, 0); r == 0 && !errors.Is(e, windows.ERROR_NOT_FOUND) {
		return e
	}
	return nil
}
