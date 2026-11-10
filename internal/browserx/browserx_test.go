package browserx

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"
)

// The test binary doubles as a browser: started with KOMANDO_FAKE_BROWSER
// it speaks the DevTools pipe on descriptors 3 and 4 the way Chromium
// does, and ends the sign-in the way the variable says.
func TestMain(m *testing.M) {
	if mode := os.Getenv("KOMANDO_FAKE_BROWSER"); mode != "" {
		fakeBrowser(mode)
		os.Exit(0)
	}
	os.Exit(m.Run())
}

func fakeBrowser(mode string) {
	in, out := os.NewFile(3, "in"), os.NewFile(4, "out")
	emit := func(v any) {
		b, _ := json.Marshal(v)
		out.Write(append(b, 0))
	}
	event := func(session, method string, params any) {
		emit(map[string]any{"method": method, "params": params, "sessionId": session})
	}
	r := bufio.NewReader(in)
	started := ""
	for {
		b, err := r.ReadBytes(0)
		if err != nil {
			return
		}
		var m struct {
			ID        int    `json:"id"`
			Method    string `json:"method"`
			SessionID string `json:"sessionId"`
			Params    struct {
				URL        string `json:"url"`
				Expression string `json:"expression"`
				TargetID   string `json:"targetId"`
			} `json:"params"`
		}
		json.Unmarshal(b[:len(b)-1], &m)
		result := map[string]any{}
		if m.Method == "Runtime.evaluate" && mode == "link" && started != "" && strings.Contains(m.Params.Expression, `"cb:"`) {
			result = map[string]any{"result": map[string]any{"type": "string", "value": "cb:link " + started}}
		}
		emit(map[string]any{"id": m.ID, "result": result, "sessionId": m.SessionID})
		switch m.Method {
		case "Target.setDiscoverTargets":
			event("", "Target.targetCreated", map[string]any{"targetInfo": map[string]any{"targetId": "W", "type": "service_worker"}})
			event("", "Target.targetCreated", map[string]any{"targetInfo": map[string]any{"targetId": "T", "type": "page"}})
		case "Target.attachToTarget":
			session := "S"
			if m.Params.TargetID != "T" {
				session = "S-" + m.Params.TargetID
			}
			event("", "Target.attachedToTarget", map[string]any{"sessionId": session, "targetInfo": map[string]any{"targetId": m.Params.TargetID, "type": "page"}})
		case "Target.createTarget": // a new window, after the person closed the first
			event("", "Target.targetCreated", map[string]any{"targetInfo": map[string]any{"targetId": "T2", "type": "page"}})
		case "Page.navigate":
			if !strings.HasPrefix(m.SessionID, "S") {
				return
			}
			if m.Params.URL == "about:blank" {
				continue
			}
			started = m.Params.URL
			switch mode {
			case "open":
				event("S", "Page.frameRequestedNavigation", map[string]any{"frameId": "F", "url": "cb:open " + started})
			case "redirect":
				event("S", "Network.responseReceivedExtraInfo", map[string]any{"statusCode": 302, "headers": map[string]any{"location": "cb:redirect " + started}})
			case "reopen": // the answer, then the person closes the window
				event(m.SessionID, "Page.frameRequestedNavigation", map[string]any{"url": "cb:reopen " + started})
				if m.SessionID == "S" {
					event("", "Target.targetDestroyed", map[string]any{"targetId": "T"})
				}
			case "stall": // the sign-in stands at a page, then the window is closed
				event("", "Target.targetInfoChanged", map[string]any{"targetInfo": map[string]any{"targetId": "T", "type": "page",
					"url": "https://login.example/common/login?x=1", "title": "Sign in\tto your\u202e account"}})
				event("", "Target.targetDestroyed", map[string]any{"targetId": "T"})
			case "early": // the page names the prefix in a script, then the sign-in ends
				event("S", "Page.frameRequestedNavigation", map[string]any{"url": "cb:"})
				event("S", "Page.frameRequestedNavigation", map[string]any{"url": "cb:real"})
			case "closed-early":
				event("S", "Page.frameRequestedNavigation", map[string]any{"url": "cb:"})
				event("S", "Page.frameRequestedNavigation", map[string]any{"url": "cb:odd"})
				event("", "Target.targetDestroyed", map[string]any{"targetId": "T"})
			case "closed":
				event("", "Target.targetDestroyed", map[string]any{"targetId": "T"})
			case "quit":
				return
			}
		case "Browser.close":
			return
		}
	}
}

func TestSignIn(t *testing.T) {
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	run := func(mode string, p Page) (string, error) {
		t.Setenv("KOMANDO_FAKE_BROWSER", mode)
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		return SignIn(ctx, self, p, "cb:", nil)
	}
	for _, mode := range []string{"open", "redirect", "link"} {
		got, err := run(mode, Page{URL: "https://idp.example/start"})
		if err != nil || got != "cb:"+mode+" https://idp.example/start" {
			t.Errorf("%s: %q %v", mode, got, err)
		}
	}
	// a page is shown as a data: address
	got, err := run("open", Page{HTML: "<form id=f></form>"})
	if err != nil || got != "cb:open data:text/html;base64,PGZvcm0gaWQ9Zj48L2Zvcm0+" {
		t.Errorf("page: %q %v", got, err)
	}
	for _, mode := range []string{"closed", "quit"} {
		if _, err := run(mode, Page{URL: "https://idp.example/start"}); !errors.Is(err, ErrClosed) {
			t.Errorf("%s: %v", mode, err)
		}
	}
	// a sign-in nobody finishes ends with the context
	t.Setenv("KOMANDO_FAKE_BROWSER", "wait")
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	if _, err := SignIn(ctx, self, Page{URL: "https://idp.example/start"}, "cb:", nil); !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("wait: %v", err)
	}
	// an address accept refuses is not the answer: the sign-in goes on, and
	// when the window closes the refused address is what comes back
	t.Setenv("KOMANDO_FAKE_BROWSER", "early")
	ctx, cancel = context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	real := func(s string) bool { return strings.HasPrefix(s, "cb:real") }
	if got, err := SignIn(ctx, self, Page{URL: "https://idp.example/start"}, "cb:", real); err != nil || got != "cb:real" {
		t.Errorf("early: %q %v", got, err)
	}
	t.Setenv("KOMANDO_FAKE_BROWSER", "closed-early")
	if got, err := SignIn(ctx, self, Page{URL: "https://idp.example/start"}, "cb:", real); err != nil || got != "cb:odd" {
		t.Errorf("closed-early: %q %v", got, err)
	}
}

// Two sign-ins in one browser: the second is shown in the same window,
// and the first one's answer, still in the browser's events, is not
// taken for the second.
func TestSignInTwice(t *testing.T) {
	self, _ := os.Executable()
	t.Setenv("KOMANDO_FAKE_BROWSER", "open")
	w, err := Open(self)
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	// the third answer is the same text as the second: it is still an answer
	for _, u := range []string{"https://idp.example/portal", "https://idp.example/gateway", "https://idp.example/gateway"} {
		if got, err := w.SignIn(ctx, Page{URL: u}, "cb:", nil); err != nil || got != "cb:open "+u {
			t.Errorf("%s: %q %v", u, got, err)
		}
	}
}

// The person closes the window between two sign-ins: the second opens a
// new one.
func TestSignInReopens(t *testing.T) {
	self, _ := os.Executable()
	t.Setenv("KOMANDO_FAKE_BROWSER", "reopen")
	w, err := Open(self)
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	for _, u := range []string{"https://idp.example/portal", "https://idp.example/gateway"} {
		if got, err := w.SignIn(ctx, Page{URL: u}, "cb:", nil); err != nil || got != "cb:reopen "+u {
			t.Errorf("%s: %q %v", u, got, err)
		}
	}
}

// A sign-in that did not finish says where the window stood.
func TestSignInStopped(t *testing.T) {
	self, _ := os.Executable()
	t.Setenv("KOMANDO_FAKE_BROWSER", "stall")
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	_, err := SignIn(ctx, self, Page{URL: "https://idp.example/start"}, "cb:", nil)
	var st *Stopped
	if !errors.As(err, &st) || !errors.Is(err, ErrClosed) || st.At != `login.example, "Sign in to your account"` {
		t.Fatalf("got %v", err)
	}
	if err.Error() != `the sign-in window was closed before the sign-in finished (the window was at login.example, "Sign in to your account")` {
		t.Errorf("text %q", err.Error())
	}
	if got := (&Stopped{Err: ErrClosed}).Error(); got != ErrClosed.Error() {
		t.Errorf("without a page: %q", got)
	}
}

func TestWhere(t *testing.T) {
	for _, tc := range [][3]string{
		{"https://login.example/x", "Sign in", `login.example, "Sign in"`},
		{"about:blank", "", "an empty page"},
		{"data:text/html;base64,AAAA", "data:text/html;base64,AAAA", "an empty page"},
		{"https://idp.example/", strings.Repeat("é", 70), `idp.example, "` + strings.Repeat("é", 60) + `..."`},
		{"https://idp.example/", "https://idp.example/", "idp.example"},
	} {
		if got := where(tc[0], tc[1]); got != tc[2] {
			t.Errorf("where(%q, %q) = %q", tc[0], tc[1], got)
		}
	}
}

func TestFind(t *testing.T) {
	if exe := Find(); exe != "" {
		if st, err := os.Stat(exe); err != nil || st.IsDir() {
			t.Errorf("Find() = %q: %v", exe, err)
		}
	}
}

func TestFindString(t *testing.T) {
	var v any
	json.Unmarshal([]byte(`{"a":[1,{"url":"https://x/?next=cb:no"},{"headers":{"Location":"cb:yes"}}],"b":null}`), &v)
	if got := findStrings(v, "cb:", nil); len(got) != 1 || got[0] != "cb:yes" {
		t.Errorf("got %q", got)
	}
}

// TestRealBrowser drives the Chromium-family browser on this computer
// through the ways a sign-in can end. It opens windows, so it runs only
// when asked: KOMANDO_TEST_BROWSER=1 go test ./internal/browserx -run RealBrowser
func TestRealBrowser(t *testing.T) {
	if os.Getenv("KOMANDO_TEST_BROWSER") == "" {
		t.Skip("set KOMANDO_TEST_BROWSER=1 to open a real browser")
	}
	exe := Find()
	if exe == "" {
		t.Skip("no Chromium-family browser here")
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/redirect":
			w.Header().Set("Location", "testcallback:redirect&token=a+b%2Fc")
			w.WriteHeader(http.StatusFound)
		case "/session":
			to := "testcallback:first"
			if _, err := r.Cookie("idp"); err == nil {
				to = "testcallback:again"
			}
			http.SetCookie(w, &http.Cookie{Name: "idp", Value: "1", Path: "/"}) // a session cookie: gone when the browser quits
			w.Write([]byte(`<html><body><a href="` + to + `">Open GlobalProtect</a></body></html>`))
		case "/posted":
			r.ParseForm()
			w.Write([]byte(`<html><body><script>window.location.href = "testcallback:posted&token=` + r.Form.Get("Token") + `";</script></body></html>`))
		}
	}))
	defer srv.Close()
	// a second sign-in in the same browser passes on the first one's session
	w, err := Open(exe)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
	for _, want := range []string{"testcallback:first", "testcallback:again", "testcallback:again"} {
		if got, err := w.SignIn(ctx, Page{URL: srv.URL + "/session"}, "testcallback:", nil); err != nil || got != want {
			t.Errorf("session: %q %v, want %s", got, err, want)
		}
	}
	cancel()
	w.Close()
	for name, tc := range map[string]struct {
		page Page
		want string
	}{
		"script":   {Page{HTML: `<script>var scheme = "testcallback:"; setTimeout(function () { location.href = scheme + 'script&token=a+b%2Fc' }, 1500)</script>`}, "testcallback:script&token=a+b%2Fc"},
		"link":     {Page{HTML: `<p>done <a href="testcallback:link&amp;token=a+b%2Fc">Open GlobalProtect</a></p>`}, "testcallback:link&token=a+b%2Fc"},
		"refresh":  {Page{HTML: `<meta http-equiv="refresh" content="0;url=testcallback:refresh&amp;token=x">`}, "testcallback:refresh&token=x"},
		"redirect": {Page{URL: srv.URL + "/redirect"}, "testcallback:redirect&token=a+b%2Fc"},
		"form": {Page{HTML: `<html><body><form id="myform" method="POST" action="` + srv.URL + `/posted"><input type="hidden" name="Token" value="tok123" /></form>` +
			`<script>document.getElementById('myform').submit();</script></body></html>`}, "testcallback:posted&token=tok123"},
	} {
		ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
		got, err := SignIn(ctx, exe, tc.page, "testcallback:", func(s string) bool { return len(s) > len("testcallback:") })
		cancel()
		if err != nil || got != tc.want {
			t.Errorf("%s: %q %v", name, got, err)
		}
	}
}
