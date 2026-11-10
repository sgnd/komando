package storex

import (
	"context"
	"errors"
	"net"
	"os"
	"strings"

	"github.com/cloudsoda/go-smb2"

	"github.com/sgnd/komando/internal/driver"
	"github.com/sgnd/komando/internal/out"
)

// NTSTATUS codes an SMB server answers with ([MS-ERREF] 2.3).
const (
	ntNoSuchUser         = 0xC0000064
	ntWrongPassword      = 0xC000006A
	ntLogonFailure       = 0xC000006D
	ntAccountRestriction = 0xC000006E
	ntPasswordExpired    = 0xC0000071
	ntAccountDisabled    = 0xC0000072
	ntLogonTypeDenied    = 0xC000015B
	ntAccountLocked      = 0xC0000234
	ntPasswordMustChange = 0xC0000224
	ntSharingViolation   = 0xC0000043
	ntIsADirectory       = 0xC00000BA
	ntBadNetworkName     = 0xC00000CC
	ntDiskFull           = 0xC000007F
	ntNameInvalid        = 0xC0000033
	ntNotEmpty           = 0xC0000101
)

// smbLoginErr explains a failure to connect, log in or mount the share.
func smbLoginErr(err error, t driver.Target) error {
	var re *smb2.ResponseError
	if errors.As(err, &re) {
		switch re.Code {
		case ntNoSuchUser, ntWrongPassword, ntLogonFailure:
			return out.Errf(out.ExitConnect, "STORAGE_AUTH",
				"check the user (and ?domain=) in the conn URL and the password in its --password-ref", "the server refused the login of %s", smbUser(t))
		case ntAccountRestriction, ntPasswordExpired, ntAccountDisabled, ntLogonTypeDenied, ntAccountLocked, ntPasswordMustChange:
			return out.Errf(out.ExitConnect, "STORAGE_AUTH",
				"the account is disabled, locked, or its password has expired: ask the server's administrator", "the server refused the login of %s (%#x)", smbUser(t), re.Code)
		case ntBadNetworkName:
			return out.Errf(out.ExitNotFound, "BUCKET_NOT_FOUND",
				"check the share name, the first part of the path in the conn URL (`komando conn show NAME`)", "the server has no share %q", t.Bucket)
		}
	}
	var ie *smb2.InvalidResponseError
	if errors.As(err, &ie) && (strings.Contains(ie.Message, "sign") || strings.Contains(ie.Message, "guest")) {
		return out.Errf(out.ExitConnect, "STORAGE_AUTH",
			"komando signs every SMB message; the server let the user in as a guest or did not sign its answer. Check the user and password, and that the account exists on the server",
			"the SMB session is not signed: %s", ie.Message)
	}
	return smbErr(err)
}

func smbUser(t driver.Target) string {
	if t.Domain != "" {
		return t.Domain + `\` + t.User
	}
	return t.User
}

// smbErr explains a failed file operation on a share.
func smbErr(err error) error {
	if err == nil {
		return nil
	}
	var oe *out.Error
	if errors.As(err, &oe) {
		return oe
	}
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, os.ErrDeadlineExceeded) {
		return out.Errf(out.ExitTimeout, "TIMEOUT", "raise --timeout, or leave it unset for large transfers", "the SMB server did not answer in time")
	}
	switch {
	case errors.Is(err, os.ErrNotExist):
		return out.Errf(out.ExitNotFound, "OBJECT_NOT_FOUND", "list files with `komando storage ls CONN [FOLDER]`", "file not found")
	case errors.Is(err, os.ErrPermission):
		return out.Errf(out.ExitConnect, "STORAGE_AUTH", "the account may not read or write here; check the share's and the folder's permissions", "access denied")
	}
	var re *smb2.ResponseError
	if errors.As(err, &re) {
		return smbStatusErr(re)
	}
	var te *smb2.TransportError
	var ne net.Error
	if errors.As(err, &te) || errors.As(err, &ne) || strings.Contains(err.Error(), "connection refused") || strings.Contains(err.Error(), "no such host") {
		return out.Errf(out.ExitConnect, "STORAGE_CONNECT",
			"run `komando conn test NAME` to check reachability; port 445 is often blocked across the internet, so reach the server --via an SSH host or a VPN", "%v", err)
	}
	return out.Errf(out.ExitRemote, "STORAGE_ERROR", "run `komando conn test NAME` to check the conn", "%v", err)
}

// smbStatusErr explains an NTSTATUS answer to a file operation.
func smbStatusErr(re *smb2.ResponseError) error {
	switch re.Code {
	case ntSharingViolation:
		return out.Errf(out.ExitRemote, "STORAGE_ERROR", "another program has the file open; close it there and try again", "the file is in use")
	case ntIsADirectory:
		return out.Usage("that name is a folder; give a file")
	case ntDiskFull:
		return out.Errf(out.ExitRemote, "STORAGE_ERROR", "free some space on the share, or ask its administrator for a larger quota", "the share is full")
	case ntNameInvalid:
		return out.Usage("Windows does not allow this file name (it may not contain \\ : * ? \" < > |)")
	case ntNotEmpty:
		return out.Usage("the folder is not empty")
	}
	return out.Errf(out.ExitRemote, "STORAGE_ERROR", "run `komando conn test NAME` to check the conn", "%v", re)
}
