//go:build windows

package cli

import (
	"runtime"
	"strings"
	"sync"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

// The approval window on Windows: a small native window made with user32
// calls (no cgo, no other program), with the request in a read-only text
// box, an optional hidden field for an authenticator code, and the buttons
// Deny and "Allow once". It stays on top, and closes itself after 120
// seconds with no answer, as the macOS and Linux windows do.

var (
	user32               = windows.NewLazySystemDLL("user32.dll")
	gdi32                = windows.NewLazySystemDLL("gdi32.dll")
	procRegisterClassExW = user32.NewProc("RegisterClassExW")
	procCreateWindowExW  = user32.NewProc("CreateWindowExW")
	procDefWindowProcW   = user32.NewProc("DefWindowProcW")
	procDestroyWindow    = user32.NewProc("DestroyWindow")
	procGetMessageW      = user32.NewProc("GetMessageW")
	procIsDialogMessageW = user32.NewProc("IsDialogMessageW")
	procTranslateMessage = user32.NewProc("TranslateMessage")
	procDispatchMessageW = user32.NewProc("DispatchMessageW")
	procPostQuitMessage  = user32.NewProc("PostQuitMessage")
	procSendMessageW     = user32.NewProc("SendMessageW")
	procSetTimer         = user32.NewProc("SetTimer")
	procGetWindowTextW   = user32.NewProc("GetWindowTextW")
	procGetSystemMetrics = user32.NewProc("GetSystemMetrics")
	procSetForegroundWin = user32.NewProc("SetForegroundWindow")
	procShowWindow       = user32.NewProc("ShowWindow")
	procSetFocus         = user32.NewProc("SetFocus")
	procLoadCursorW      = user32.NewProc("LoadCursorW")
	procGetStockObject   = gdi32.NewProc("GetStockObject")
	procCreateFontW      = gdi32.NewProc("CreateFontW")
	procDeleteObject     = gdi32.NewProc("DeleteObject")
	procInputSource      = user32.NewProc("GetCurrentInputMessageSource")
	procSetBkColor       = gdi32.NewProc("SetBkColor")
	procSetTextColor     = gdi32.NewProc("SetTextColor")
	procCreateSolidBrush = gdi32.NewProc("CreateSolidBrush")
)

const (
	wsOverlapped   = 0x00000000
	wsCaption      = 0x00C00000
	wsSysMenu      = 0x00080000
	wsChild        = 0x40000000
	wsVisible      = 0x10000000
	wsTabStop      = 0x00010000
	wsVScroll      = 0x00200000
	wsHScroll      = 0x00100000
	wsBorder       = 0x00800000
	wsExTopmost    = 0x00000008
	wsExDlgModal   = 0x00000001
	esMultiline    = 0x0004
	esReadOnly     = 0x0800
	esPassword     = 0x0020
	esAutoHScroll  = 0x0080
	ssCenter       = 0x0001
	ssNoPrefix     = 0x0080 // a "&" in the text shows as itself
	bsPushButton   = 0x0000
	bsDefPush      = 0x0001
	wmDestroy      = 0x0002
	wmClose        = 0x0010
	wmSetFont      = 0x0030
	emLineScroll   = 0x00B6
	wmCommand      = 0x0111
	wmTimer        = 0x0113
	wmCtlColorEdit = 0x0133
	wmCtlColorStat = 0x0138
	whiteBrush     = 0
	smCxScreen     = 0
	smCyScreen     = 1
	idAllow        = 1
	idDeny         = 2 // IDCANCEL: Esc presses it
	idCode         = 3
	defaultGUIFont = 17
	swShow         = 5
	idcArrow       = 32512
	colorWindow    = 5
)

type wndClassEx struct {
	size       uint32
	style      uint32
	wndProc    uintptr
	clsExtra   int32
	wndExtra   int32
	instance   windows.Handle
	icon       windows.Handle
	cursor     windows.Handle
	background windows.Handle
	menuName   *uint16
	className  *uint16
	iconSm     windows.Handle
}

type winMsg struct {
	hwnd    windows.Handle
	message uint32
	wParam  uintptr
	lParam  uintptr
	time    uint32
	pt      struct{ x, y int32 }
}

// The window's one answer; only one approval window is open at a time.
var (
	winMu       sync.Mutex
	winOnce     sync.Once
	winClass    *uint16
	winRegErr   error
	winAnswer   int // idAllow, idDeny, or 0 when it gave up
	winCodeEdit uintptr
	winAllowBtn uintptr
	winCode     string
	winColour   map[uintptr]uint32 // a label's text colour (0x00BBGGRR)
	winBox      uintptr            // the command box, on its own grey
	winBoxBrush uintptr
)

// The window's colours (COLORREF, 0x00BBGGRR): white content, a light
// grey command card, red risk lines and grey secondary text, each at
// least 4.5:1 on its ground.
const (
	rgbWhite = 0x00FFFFFF
	rgbCard  = 0x00F5F5F5
	rgbRed   = 0x001C2BC4 // #C42B1C
	rgbGrey  = 0x00595959 // #595959
)

// imoHardware is INPUT_MESSAGE_SOURCE's origin for a real keyboard or
// mouse; a message posted by another program has none, and SendInput
// marks its events as injected.
const imoHardware = 1

// pressedByPerson says whether the click being handled came from a real
// keyboard or mouse. Another program can post "Allow" to this window
// (PostMessage) or fake a click (SendInput); neither counts.
func pressedByPerson(lParam uintptr) bool {
	if lParam == 0 || lParam != winAllowBtn || procInputSource.Find() != nil {
		return false
	}
	var src struct{ deviceType, originID uint32 }
	r, _, _ := procInputSource.Call(uintptr(unsafe.Pointer(&src)))
	return r != 0 && src.originID == imoHardware
}

func wndProc(hwnd, msg, wParam, lParam uintptr) uintptr {
	switch msg {
	case wmCommand:
		switch id := wParam & 0xffff; id {
		case idAllow, idDeny:
			if id == idAllow && !pressedByPerson(lParam) {
				return 0 // not a person: the window stays open
			}
			winAnswer = int(id)
			if id == idAllow && winCodeEdit != 0 {
				buf := make([]uint16, 64)
				n, _, _ := procGetWindowTextW.Call(winCodeEdit, uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)))
				winCode = windows.UTF16ToString(buf[:n])
			}
			procDestroyWindow.Call(hwnd)
			return 0
		}
	case wmCtlColorStat, wmCtlColorEdit:
		bg, brush := uintptr(rgbWhite), uintptr(0)
		if lParam == winBox && winBoxBrush != 0 {
			bg, brush = rgbCard, winBoxBrush
		} else {
			brush, _, _ = procGetStockObject.Call(whiteBrush)
		}
		procSetBkColor.Call(wParam, bg)
		if c, ok := winColour[lParam]; ok {
			procSetTextColor.Call(wParam, uintptr(c))
		}
		return brush
	case wmTimer:
		winAnswer = 0 // gave up
		procDestroyWindow.Call(hwnd)
		return 0
	case wmClose:
		winAnswer = idDeny
		procDestroyWindow.Call(hwnd)
		return 0
	case wmDestroy:
		procPostQuitMessage.Call(0)
		return 0
	}
	r, _, _ := procDefWindowProcW.Call(hwnd, msg, wParam, lParam)
	return r
}

// interactiveDesktop says whether this process can show a window to a
// person: session 0 is where services run, with no one to see it.
func interactiveDesktop() bool {
	var sid uint32
	if err := windows.ProcessIdToSessionId(windows.GetCurrentProcessId(), &sid); err != nil || sid == 0 {
		return false
	}
	return user32.Load() == nil && procCreateWindowExW.Find() == nil
}

// winFont is face at 9 pt (12 px), normal or bold; fallback when it
// cannot be made. Segoe UI draws "--" as two hyphens, which the stock GUI
// font ran together into a dash.
func winFont(face string, bold, fixed bool, fallback uintptr) uintptr {
	f16, _ := windows.UTF16PtrFromString(face)
	weight, pitch := uintptr(400), uintptr(0)
	if bold {
		weight = 700
	}
	if fixed {
		pitch = 0x31 // FIXED_PITCH|FF_MODERN
	}
	height := int32(-12)
	f, _, _ := procCreateFontW.Call(uintptr(int64(height)), 0, 0, 0, weight, 0, 0, 0, 1, 0, 0, 5, pitch, uintptr(unsafe.Pointer(f16)))
	if f == 0 {
		return fallback
	}
	return f
}

// approvalWindow shows the window; see askOnScreen. withCode adds the
// hidden field for an authenticator code.
func approvalWindow(v approvalView, withCode bool) (code string, allowed, gaveUp, shown bool) {
	if !interactiveDesktop() {
		return "", false, false, false
	}
	winMu.Lock()
	defer winMu.Unlock()
	runtime.LockOSThread() // a window and its messages belong to one thread
	defer runtime.UnlockOSThread()

	var inst windows.Handle
	if err := windows.GetModuleHandleEx(0, nil, &inst); err != nil {
		return "", false, false, false
	}
	winOnce.Do(func() {
		winClass, _ = windows.UTF16PtrFromString("komandoApproval")
		cur, _, _ := procLoadCursorW.Call(0, idcArrow)
		wc := wndClassEx{wndProc: syscall.NewCallback(wndProc), instance: inst, className: winClass,
			cursor: windows.Handle(cur), background: windows.Handle(colorWindow + 1)}
		wc.size = uint32(unsafe.Sizeof(wc))
		if r, _, e := procRegisterClassExW.Call(uintptr(unsafe.Pointer(&wc))); r == 0 {
			winRegErr = e
		}
	})
	if winRegErr != nil {
		return "", false, false, false
	}
	winAnswer, winCode, winCodeEdit, winAllowBtn = idDeny, "", 0, 0
	winColour, winBox = map[uintptr]uint32{}, 0
	winBoxBrush, _, _ = procCreateSolidBrush.Call(rgbCard)
	defer func() {
		if winBoxBrush != 0 {
			procDeleteObject.Call(winBoxBrush)
			winBoxBrush = 0
		}
	}()
	const pad, btnW, btnH, codeH = winPad, 110, 28, 24

	l := winLayoutFor(v)
	h := l.height + btnH + pad + 40 // 40: the title bar and borders
	if withCode {
		h += codeH + pad
	}
	sw, _, _ := procGetSystemMetrics.Call(smCxScreen)
	sh, _, _ := procGetSystemMetrics.Call(smCyScreen)
	title, _ := windows.UTF16PtrFromString("komando needs your OK")
	hwnd, _, _ := procCreateWindowExW.Call(wsExTopmost|wsExDlgModal, uintptr(unsafe.Pointer(winClass)), uintptr(unsafe.Pointer(title)),
		wsOverlapped|wsCaption|wsSysMenu, (sw-winW)/2, (sh-uintptr(h))/2, winW, uintptr(h), 0, 0, uintptr(inst), 0)
	if hwnd == 0 {
		return "", false, false, false
	}
	stock, _, _ := procGetStockObject.Call(defaultGUIFont)
	font, bold, mono := winFont("Segoe UI", false, false, stock), winFont("Segoe UI", true, false, stock), winFont("Consolas", false, true, stock)
	for _, f := range []uintptr{font, bold, mono} {
		if f != stock {
			defer procDeleteObject.Call(f)
		}
	}
	child := func(class, label string, style, f uintptr, x, y, cw, ch int, id uintptr) uintptr {
		c, _ := windows.UTF16PtrFromString(class)
		lb, _ := windows.UTF16PtrFromString(crlf(label))
		hw, _, _ := procCreateWindowExW.Call(0, uintptr(unsafe.Pointer(c)), uintptr(unsafe.Pointer(lb)),
			wsChild|wsVisible|style, uintptr(x), uintptr(y), uintptr(cw), uintptr(ch), hwnd, id, uintptr(inst), 0)
		procSendMessageW.Call(hw, wmSetFont, f, 1)
		return hw
	}
	y := winContent(v, l, child, font, bold, mono)
	allowStyle, denyStyle := uintptr(bsPushButton), uintptr(bsDefPush)
	if withCode {
		winCodeEdit = child("EDIT", "", esPassword|esAutoHScroll|wsBorder|wsTabStop, font, pad, y, winInner, codeH, idCode)
		y += codeH + pad
		allowStyle, denyStyle = bsDefPush, bsPushButton // as on macOS: Enter after the code allows
	}
	deny := child("BUTTON", "Deny", denyStyle|wsTabStop, font, pad+winInner-2*btnW-pad, y, btnW, btnH, idDeny)
	winAllowBtn = child("BUTTON", "Allow once", allowStyle|wsTabStop, font, pad+winInner-btnW, y, btnW, btnH, idAllow)

	procShowWindow.Call(hwnd, swShow)
	procSetForegroundWin.Call(hwnd)
	if winCodeEdit != 0 {
		procSetFocus.Call(winCodeEdit)
	} else {
		procSetFocus.Call(deny)
	}
	procSetTimer.Call(hwnd, 1, uintptr(windowGiveUp.Milliseconds()), 0)

	var m winMsg
	for {
		r, _, _ := procGetMessageW.Call(uintptr(unsafe.Pointer(&m)), 0, 0, 0)
		if int32(r) <= 0 {
			break
		}
		if d, _, _ := procIsDialogMessageW.Call(hwnd, uintptr(unsafe.Pointer(&m))); d != 0 {
			continue
		}
		procTranslateMessage.Call(uintptr(unsafe.Pointer(&m)))
		procDispatchMessageW.Call(uintptr(unsafe.Pointer(&m)))
	}
	code = strings.TrimSpace(winCode)
	winCode = ""
	return code, winAnswer == idAllow, winAnswer == 0, true
}

// winChild makes a child control: class, text, style, font, x, y, w, h, id.
type winChild func(class, label string, style, f uintptr, x, y, cw, ch int, id uintptr) uintptr

// winContent draws everything above the code field and the buttons, and
// returns where they start.
func winContent(v approvalView, l winLayout, child winChild, font, bold, mono uintptr) int {
	const pad = winPad
	y := pad
	child("STATIC", v.title(), ssNoPrefix, bold, pad, y, winInner, l.titleH, 0)
	y += l.titleH
	if l.subH > 0 {
		winColour[child("STATIC", v.subtitle(), ssNoPrefix, font, pad, y, winInner, l.subH, 0)] = rgbGrey
		y += l.subH
	}
	y += pad
	vx := pad + winLabelW + 8
	for i, gh := range winGridH(v) {
		r := v.grid()[i]
		if r.Label != "" {
			winColour[child("STATIC", r.Label, ssNoPrefix, font, pad, y, winLabelW, winRowH, 0)] = rgbGrey
		}
		switch r.Kind {
		case rowBadge:
			child("STATIC", r.Text, ssNoPrefix|ssCenter|wsBorder, font, vx, y, winBadgeW, winRowH+2, 0)
		case rowRisk:
			winColour[child("STATIC", "\u26a0 "+r.Text, ssNoPrefix, font, vx, y, winInner-winLabelW-8, gh-4, 0)] = rgbRed
		default:
			child("STATIC", r.Text, ssNoPrefix, font, vx, y, winInner-winLabelW-8, gh-4, 0)
		}
		y += gh
	}
	y += pad
	// no ES_AUTOHSCROLL or WS_HSCROLL: boxText() is wrapped, nothing scrolls
	// sideways; a scroll bar only when there is more than the box shows
	boxStyle := uintptr(esMultiline | esReadOnly | wsBorder | wsTabStop)
	if v.boxRows() > boxMaxLines {
		boxStyle |= wsVScroll
	}
	box := child("EDIT", v.boxText(), boxStyle, mono, pad, y, winInner, l.cmdH, 0)
	winBox = box
	if i := v.riskyLine(); i >= boxMaxLines {
		procSendMessageW.Call(box, emLineScroll, 0, uintptr(i-2)) // the line a rule matched, in view (no highlight)
	}
	y += l.cmdH + pad
	if l.notesH > 0 {
		// the hint starts where the card's text does (its border and margin)
		winColour[child("STATIC", v.notes(), ssNoPrefix, font, pad+4, y, winInner-4, l.notesH, 0)] = rgbGrey
		y += l.notesH + pad
	}
	child("STATIC", question, ssNoPrefix, bold, pad, y, winInner, winRowH, 0)
	y += winRowH + pad
	return y
}

// crlf is s with Windows line ends, which an edit control needs.
func crlf(s string) string {
	return strings.ReplaceAll(strings.ReplaceAll(s, "\r\n", "\n"), "\n", "\r\n")
}
