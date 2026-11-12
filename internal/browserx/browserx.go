// Package browserx shows a sign-in page in a browser window and reads the
// address the sign-in ends on. Some logins (a VPN's SAML sign-in) end by
// opening an address only the vendor's own program understands, such as
// globalprotectcallback:...; a normal browser drops it. komando starts a
// Chromium-family browser that is already on the computer, with an empty
// temporary profile, and watches it over the DevTools pipe (two file
// descriptors, no network port) until that address shows up.
package browserx

import (
	"bufio"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"
	"unicode"
)

// ErrClosed: the person closed the window before the sign-in ended.
var ErrClosed = errors.New("the sign-in window was closed before the sign-in finished")

// Stopped is a sign-in that did not finish: the window was closed
// (ErrClosed) or the time ran out. At says where it stood: the site and
// title of the page, which helps the person see what it waited for.
type Stopped struct {
	Err error
	At  string
}

func (e *Stopped) Error() string {
	if e.At == "" {
		return e.Err.Error()
	}
	return e.Err.Error() + " (the window was at " + e.At + ")"
}
func (e *Stopped) Unwrap() error { return e.Err }

// Page is where the sign-in starts: an address, or a page to show.
type Page struct{ URL, HTML string }

// Find returns a Chromium-family browser on this computer, "" when there
// is none (Safari and Firefox cannot be watched this way).
func Find() string {
	if runtime.GOOS == "darwin" {
		roots := []string{"/Applications"}
		if home, err := os.UserHomeDir(); err == nil {
			roots = append(roots, filepath.Join(home, "Applications"))
		}
		for _, app := range []string{"Google Chrome", "Microsoft Edge", "Brave Browser", "Chromium", "Vivaldi"} {
			for _, root := range roots {
				p := filepath.Join(root, app+".app", "Contents", "MacOS", app)
				if st, err := os.Stat(p); err == nil && !st.IsDir() {
					return p
				}
			}
		}
	}
	if runtime.GOOS == "windows" {
		for _, p := range windowsBrowsers(os.Getenv) {
			if st, err := os.Stat(p); err == nil && !st.IsDir() {
				return p
			}
		}
	}
	for _, name := range []string{"google-chrome", "google-chrome-stable", "chromium", "chromium-browser", "microsoft-edge", "brave-browser"} {
		if p, err := exec.LookPath(name); err == nil {
			return p
		}
	}
	return ""
}

// windowsBrowsers are where Chrome, Edge (on every Windows 10 and 11) and
// Brave install themselves on Windows: for all users under Program Files,
// or for one user under their local AppData. They are not on PATH there.
func windowsBrowsers(getenv func(string) string) []string {
	apps := [][]string{
		{"Google", "Chrome", "Application", "chrome.exe"},
		{"Microsoft", "Edge", "Application", "msedge.exe"},
		{"BraveSoftware", "Brave-Browser", "Application", "brave.exe"},
	}
	var out []string
	for _, app := range apps {
		for _, v := range []string{"ProgramFiles", "ProgramFiles(x86)", "LOCALAPPDATA"} {
			if root := getenv(v); root != "" {
				out = append(out, filepath.Join(append([]string{root}, app...)...))
			}
		}
	}
	return out
}

type message struct {
	ID        int             `json:"id,omitempty"`
	Method    string          `json:"method,omitempty"`
	Params    json.RawMessage `json:"params,omitempty"`
	SessionID string          `json:"sessionId,omitempty"`
}

// Browser is a browser window komando opened for sign-ins. One Browser
// can show several sign-ins in a row: what the first one left (the
// sign-in service's own session) lets the next one pass without typing.
type Browser struct {
	dir string
	b   *browser
}

// Open starts the browser exe with a temporary profile, which shares
// nothing with the person's own browser. Close removes it.
func Open(exe string) (*Browser, error) {
	dir, err := os.MkdirTemp("", "komando-signin-")
	if err != nil {
		return nil, err
	}
	b, err := launch(exe, dir)
	if err != nil {
		os.RemoveAll(dir)
		return nil, err
	}
	return &Browser{dir: dir, b: b}, nil
}

// SignIn shows page and returns the first address starting with prefix
// that the sign-in opens, redirects to or links to, and that accept takes
// (nil takes any). A sign-in page may name the prefix alone in a script,
// long before the sign-in ends; accept tells such text from the real
// answer. When the window is closed and only refused addresses were seen,
// the longest of them is returned, so the caller can say what was wrong
// with it. What an earlier SignIn's last page still says is not taken for
// this one's answer.
func (w *Browser) SignIn(ctx context.Context, page Page, prefix string, accept func(string) bool) (string, error) {
	start := page.URL
	if start == "" {
		// a data: address has no origin of its own and cannot read files
		start = "data:text/html;base64," + base64.StdEncoding.EncodeToString([]byte(page.HTML))
	}
	return w.b.watch(ctx, start, prefix, accept)
}

// Close closes the window and removes the profile.
func (w *Browser) Close() {
	w.b.close()
	os.RemoveAll(w.dir)
}

// SignIn is one sign-in in a browser of its own: Open, SignIn, Close.
func SignIn(ctx context.Context, exe string, page Page, prefix string, accept func(string) bool) (string, error) {
	w, err := Open(exe)
	if err != nil {
		return "", err
	}
	defer w.Close()
	return w.SignIn(ctx, page, prefix, accept)
}

// browser is a started browser and its DevTools pipe.
type browser struct {
	cmd         *exec.Cmd
	write, read *os.File
	msgs        chan []byte
	done        chan struct{}
	exited      chan struct{}
	id          int

	discovering bool
	pages       map[string]string // target id -> DevTools session id ("" until attached)
	// marker is the id of the command a second sign-in starts with. Until
	// the browser answers it, events are still about the sign-in before,
	// whose last page holds that sign-in's answer.
	marker int
	// main is the page the sign-ins are shown in, and at where each page
	// stands (site and title).
	main string
	at   map[string]string
}

// launch starts exe with the profile in dir and the DevTools pipe on its
// descriptors 3 and 4.
func launch(exe, dir string) (*browser, error) {
	toBrowser, write, err := os.Pipe()
	if err != nil {
		return nil, err
	}
	read, fromBrowser, err := os.Pipe()
	if err != nil {
		toBrowser.Close()
		write.Close()
		return nil, err
	}
	// mock keychain and basic password store: an empty profile must not ask
	// for the person's keychain
	cmd := exec.Command(exe, "--remote-debugging-pipe", "--user-data-dir="+dir, "--no-first-run",
		"--no-default-browser-check", "--use-mock-keychain", "--password-store=basic", "about:blank")
	cmd.ExtraFiles = []*os.File{toBrowser, fromBrowser}
	err = cmd.Start()
	toBrowser.Close()
	fromBrowser.Close()
	if err != nil {
		write.Close()
		read.Close()
		return nil, err
	}
	b := &browser{cmd: cmd, write: write, read: read, msgs: make(chan []byte, 64), done: make(chan struct{}), exited: make(chan struct{}),
		pages: map[string]string{}, at: map[string]string{}}
	go func() { _ = cmd.Wait(); close(b.exited) }()
	go func() {
		defer close(b.msgs)
		r := bufio.NewReaderSize(read, 1<<16)
		for {
			m, err := r.ReadBytes(0) // each message ends with a zero byte
			if err != nil {
				return
			}
			select {
			case b.msgs <- m[:len(m)-1]:
			case <-b.done: // still read, so the browser can write its last words and exit
			}
		}
	}()
	return b, nil
}

func (b *browser) send(session, method string, params any) int {
	b.id++
	p, _ := json.Marshal(params)
	m, _ := json.Marshal(message{ID: b.id, Method: method, Params: p, SessionID: session})
	_, _ = b.write.Write(append(m, 0))
	return b.id
}

// close asks the browser to quit, and kills it when it does not.
func (b *browser) close() {
	close(b.done)
	b.send("", "Browser.close", struct{}{})
	select {
	case <-b.exited:
	case <-time.After(3 * time.Second):
		_ = b.cmd.Process.Kill()
		<-b.exited
	}
	b.write.Close()
	b.read.Close()
}

// findInPage is a script that returns the address starting with prefix
// that the page links to or names in its text, or "".
func findInPage(prefix string) string {
	look, _ := json.Marshal(prefix)
	return `(function(p){var e=document.querySelectorAll('a[href],form[action],iframe[src]');` +
		`for(var i=0;i<e.length;i++){var h=e[i].getAttribute('href')||e[i].getAttribute('action')||e[i].getAttribute('src')||'';if(h.indexOf(p)===0)return h}` +
		`var d=document.documentElement?document.documentElement.innerHTML:'';var at=d.indexOf(p);if(at<0)return '';` +
		`var m=d.slice(at).match(/^[^"'<>\s\\]+/);return m?m[0]:''})(` + string(look) + `)`
}

// open begins a sign-in. The first one waits for the browser's window
// (a targetCreated event). A later one first sends a command that changes
// nothing: its answer marks where the events of the sign-in before end.
func (b *browser) open() {
	if !b.discovering {
		b.discovering = true
		b.send("", "Target.setDiscoverTargets", map[string]any{"discover": true})
		return
	}
	b.marker = b.send("", "Browser.getVersion", struct{}{})
}

// show shows start in a window that is there. Without one (the person
// closed it) it opens a window, which track then sends to start.
func (b *browser) show(start string) (started bool) {
	// the page the sign-in before was in: another tab may be behind it,
	// where the person would not see the sign-in
	if session := b.pages[b.main]; session != "" {
		b.send(session, "Page.bringToFront", struct{}{})
		b.send(session, "Page.navigate", map[string]any{"url": start})
		return true
	}
	for id, session := range b.pages {
		if session != "" {
			b.main = id
			b.send(session, "Page.bringToFront", struct{}{})
			b.send(session, "Page.navigate", map[string]any{"url": start})
			return true
		}
	}
	if len(b.pages) == 0 {
		b.send("", "Target.createTarget", map[string]any{"url": "about:blank", "newWindow": true})
	}
	return false
}

// watch shows start and reads the browser's events until one carries an
// address starting with prefix. Every page (the first window, and windows
// the sign-in opens) is attached to, so its navigation and network events
// arrive here; once a second each page is also asked for a link to such
// an address.
func (b *browser) watch(ctx context.Context, start, prefix string, accept func(string) bool) (string, error) {
	find := findInPage(prefix)
	b.open()
	started, sawPage, refused := false, len(b.pages) > 0, ""
	stopped := func(err error) (string, error) {
		if refused != "" {
			return refused, nil
		}
		return "", &Stopped{Err: err, At: b.at[b.main]}
	}
	tick := time.NewTicker(time.Second)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return stopped(ctx.Err())
		case <-tick.C:
			for _, session := range b.pages {
				if session != "" {
					b.send(session, "Runtime.evaluate", map[string]any{"expression": find, "returnByValue": true})
				}
			}
		case raw, ok := <-b.msgs:
			if !ok {
				return stopped(ErrClosed)
			}
			var all any
			if json.Unmarshal(raw, &all) != nil {
				continue
			}
			stale := b.marker != 0 // still about the sign-in before this one
			if obj, _ := all.(map[string]any); stale {
				if id, _ := obj["id"].(float64); int(id) == b.marker {
					if b.marker = 0; !started {
						started = b.show(start)
					}
				}
			}
			for _, found := range findStrings(all, prefix, nil) {
				if stale || !started {
					break
				}
				if accept == nil || accept(found) {
					for _, session := range b.pages { // off the page that holds the answer
						if session != "" {
							b.send(session, "Page.navigate", map[string]any{"url": "about:blank"})
						}
					}
					return found, nil
				}
				if len(found) > len(refused) {
					refused = found
				}
			}
			if b.track(raw, start, &started, &sawPage) {
				return stopped(ErrClosed)
			}
		}
	}
}

// track keeps the list of pages from the browser's target events and
// shows start in the first page that is attached. It reports whether the
// last window was closed.
func (b *browser) track(raw []byte, start string, started, sawPage *bool) (closed bool) {
	var m message
	_ = json.Unmarshal(raw, &m)
	var ev struct {
		SessionID  string `json:"sessionId"`
		TargetID   string `json:"targetId"`
		TargetInfo struct {
			TargetID string `json:"targetId"`
			Type     string `json:"type"`
			URL      string `json:"url"`
			Title    string `json:"title"`
		} `json:"targetInfo"`
	}
	_ = json.Unmarshal(m.Params, &ev)
	switch m.Method {
	case "Target.targetInfoChanged":
		if _, known := b.pages[ev.TargetInfo.TargetID]; known {
			b.at[ev.TargetInfo.TargetID] = where(ev.TargetInfo.URL, ev.TargetInfo.Title)
		}
	case "Target.targetCreated":
		if _, known := b.pages[ev.TargetInfo.TargetID]; ev.TargetInfo.Type == "page" && !known {
			b.pages[ev.TargetInfo.TargetID], *sawPage = "", true
			b.send("", "Target.attachToTarget", map[string]any{"targetId": ev.TargetInfo.TargetID, "flatten": true})
		}
	case "Target.attachedToTarget":
		if _, known := b.pages[ev.TargetInfo.TargetID]; !known {
			return false
		}
		b.pages[ev.TargetInfo.TargetID] = ev.SessionID
		b.send(ev.SessionID, "Page.enable", struct{}{})
		b.send(ev.SessionID, "Network.enable", struct{}{})
		if !*started {
			*started, b.main = true, ev.TargetInfo.TargetID
			b.send(ev.SessionID, "Page.navigate", map[string]any{"url": start})
		}
	case "Target.targetDestroyed":
		delete(b.pages, ev.TargetID)
		if ev.TargetID == b.main { // keep where it stood: the reason it was closed
			b.main, b.at[""] = "", b.at[ev.TargetID]
		}
		delete(b.at, ev.TargetID)
		// the last window: on a Mac the browser itself stays open
		return *sawPage && len(b.pages) == 0 && *started
	}
	return false
}

// where is a page's site and title, cleaned: the page wrote the title.
func where(address, title string) string {
	site := "an empty page"
	if u, err := url.Parse(address); err == nil && u.Host != "" {
		site = u.Host
	}
	title = strings.Join(strings.Fields(strings.Map(func(r rune) rune {
		if unicode.IsControl(r) || unicode.Is(unicode.Bidi_Control, r) {
			return ' '
		}
		return r
	}, title)), " ")
	if r := []rune(title); len(r) > 60 {
		title = string(r[:60]) + "..."
	}
	if title == "" || strings.HasPrefix(title, "data:") || title == address {
		return site
	}
	return site + ", \"" + title + "\""
}

// findStrings adds to found every string in v (a decoded JSON value)
// that starts with prefix: an address in any event, header or script
// result.
func findStrings(v any, prefix string, found []string) []string {
	switch x := v.(type) {
	case string:
		if strings.HasPrefix(x, prefix) {
			found = append(found, x)
		}
	case []any:
		for _, e := range x {
			found = findStrings(e, prefix, found)
		}
	case map[string]any:
		for _, e := range x {
			found = findStrings(e, prefix, found)
		}
	}
	return found
}
