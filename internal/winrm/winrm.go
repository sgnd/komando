// Package winrm is komando's own WinRM client: it runs one command on a
// Windows server through WS-Management (the Windows Remote Shell protocol,
// MS-WSMV), over HTTPS or HTTP, with NTLM or Basic login. It is what
// Ansible's winrm connection speaks. It only runs commands: WinRM has no
// file transfer or tunnels (komando sends files through the command's
// input and output, see docs/features/windows.md).
package winrm

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	ntlmssp "github.com/Azure/go-ntlmssp"
)

// Config says where the server is and how to log in.
type Config struct {
	// Endpoint is the server's WS-Management URL, e.g.
	// https://10.0.0.9:5986/wsman.
	Endpoint       string
	User, Password string
	// Basic logs in with HTTP Basic (local accounts only, and only
	// over HTTPS); otherwise NTLM, which never sends the password.
	Basic bool
	// TLS checks the server's certificate for an https Endpoint.
	TLS *tls.Config
	// Dial opens the TCP connection: directly, through a VPN or through
	// an SSH bastion. nil: net.Dialer.
	Dial func(ctx context.Context, network, addr string) (net.Conn, error)
	// OperationTimeout is how long the server waits for output before
	// it answers a Receive with nothing (komando then asks again).
	OperationTimeout time.Duration
}

// Client runs commands on one server. It is safe for one command at a time.
type Client struct {
	cfg  Config
	http *http.Client
}

// New makes a client; nothing is sent until Run.
func New(cfg Config) *Client {
	if cfg.OperationTimeout <= 0 {
		cfg.OperationTimeout = 20 * time.Second
	}
	dial := cfg.Dial
	if dial == nil {
		dial = (&net.Dialer{Timeout: 15 * time.Second}).DialContext
	}
	tr := &http.Transport{
		DialContext:     dial,
		TLSClientConfig: cfg.TLS,
		// NTLM logs in one connection, so keep using it; and WinRM is HTTP/1.1
		MaxIdleConnsPerHost: 1,
		IdleConnTimeout:     90 * time.Second,
		TLSNextProto:        map[string]func(string, *tls.Conn) http.RoundTripper{},
	}
	var rt http.RoundTripper = tr
	if !cfg.Basic {
		rt = ntlmssp.Negotiator{RoundTripper: tr}
	}
	return &Client{cfg: cfg, http: &http.Client{Transport: rt, Timeout: cfg.OperationTimeout + 30*time.Second}}
}

// Close lets go of the client's connections.
func (c *Client) Close() error {
	c.http.CloseIdleConnections()
	return nil
}

// Error is a SOAP fault the server answered with.
type Error struct {
	Code    string // the WS-Management fault code, e.g. 2150858793
	Message string
}

func (e *Error) Error() string {
	if e.Code != "" {
		return fmt.Sprintf("WinRM error %s: %s", e.Code, e.Message)
	}
	return "WinRM error: " + e.Message
}

// ErrAuth is a refused login (HTTP 401).
var ErrAuth = errors.New("the WinRM server refused the login (HTTP 401): check the user and password, and that the server allows this login method")

// timedOut is the fault a Receive gets when the command printed nothing
// within OperationTimeout.
const timedOut = "2150858793"

// Run runs command (as cmd.exe would read it) with stdin as its input and
// copies its output to stdout and stderr. It returns the exit code. When
// ctx ends, the command is stopped and the shell is closed.
func (c *Client) Run(ctx context.Context, command string, stdin io.Reader, stdout, stderr io.Writer) (int, error) {
	shell, err := c.createShell(ctx)
	if err != nil {
		return -1, err
	}
	defer func() {
		// a fresh context: the shell is closed even when ctx has ended
		dctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		_, _ = c.call(dctx, actionDelete, shell, "", nil)
	}()
	r, err := c.call(ctx, actionCommand, shell, commandOptions,
		[]byte(`<rsp:CommandLine><rsp:Command>`+esc(command)+`</rsp:Command></rsp:CommandLine>`))
	if err != nil {
		return -1, err
	}
	id := r.commandID
	if id == "" {
		return -1, errors.New("the WinRM server started the command but gave no command id")
	}
	if err := c.send(ctx, shell, id, stdin); err != nil {
		c.terminate(shell, id)
		return -1, err
	}
	for {
		r, err := c.call(ctx, actionReceive, shell, "",
			[]byte(`<rsp:Receive><rsp:DesiredStream CommandId="`+esc(id)+`">stdout stderr</rsp:DesiredStream></rsp:Receive>`))
		var fe *Error
		switch {
		case errors.As(err, &fe) && fe.Code == timedOut:
			continue // no output yet: ask again
		case err != nil:
			c.terminate(shell, id)
			return -1, err
		}
		for _, s := range r.streams {
			w := stdout
			if s.name == "stderr" {
				w = stderr
			}
			if _, err := w.Write(s.data); err != nil {
				c.terminate(shell, id)
				return -1, err
			}
		}
		if r.done {
			return r.exitCode, nil
		}
	}
}

// send writes stdin to the command in pieces, then ends its input.
func (c *Client) send(ctx context.Context, shell, id string, stdin io.Reader) error {
	buf := make([]byte, 32<<10)
	for {
		n, rerr := 0, error(nil)
		if stdin != nil {
			n, rerr = io.ReadFull(stdin, buf)
		} else {
			rerr = io.EOF
		}
		end := rerr == io.EOF || rerr == io.ErrUnexpectedEOF
		if rerr != nil && !end {
			return rerr
		}
		if n == 0 && !end {
			continue
		}
		attr := ""
		if end {
			attr = ` End="true"`
		}
		body := `<rsp:Send><rsp:Stream Name="stdin" CommandId="` + esc(id) + `"` + attr + `>` +
			base64.StdEncoding.EncodeToString(buf[:n]) + `</rsp:Stream></rsp:Send>`
		if _, err := c.call(ctx, actionSend, shell, "", []byte(body)); err != nil {
			return err
		}
		if end {
			return nil
		}
	}
}

// terminate stops a command that is still running.
func (c *Client) terminate(shell, id string) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	_, _ = c.call(ctx, actionSignal, shell, "", []byte(`<rsp:Signal CommandId="`+esc(id)+
		`"><rsp:Code>http://schemas.microsoft.com/wbem/wsman/1/windows/shell/signal/terminate</rsp:Code></rsp:Signal>`))
}

// createShell opens a remote shell with UTF-8 output and returns its id.
func (c *Client) createShell(ctx context.Context) (string, error) {
	r, err := c.call(ctx, actionCreate, "", shellOptions,
		[]byte(`<rsp:Shell><rsp:InputStreams>stdin</rsp:InputStreams><rsp:OutputStreams>stdout stderr</rsp:OutputStreams></rsp:Shell>`))
	if err != nil {
		return "", err
	}
	if r.shellID == "" {
		return "", errors.New("the WinRM server opened a shell but gave no shell id")
	}
	return r.shellID, nil
}

const (
	nsShell       = "http://schemas.microsoft.com/wbem/wsman/1/windows/shell"
	actionCreate  = "http://schemas.xmlsoap.org/ws/2004/09/transfer/Create"
	actionDelete  = "http://schemas.xmlsoap.org/ws/2004/09/transfer/Delete"
	actionCommand = nsShell + "/Command"
	actionSend    = nsShell + "/Send"
	actionReceive = nsShell + "/Receive"
	actionSignal  = nsShell + "/Signal"
	// the shell's output is UTF-8 (code page 65001), with the user's profile
	shellOptions = `<w:OptionSet><w:Option Name="WINRS_NOPROFILE">FALSE</w:Option><w:Option Name="WINRS_CODEPAGE">65001</w:Option></w:OptionSet>`
	// the input is a pipe, not a console: PowerShell reads it as data
	commandOptions = `<w:OptionSet><w:Option Name="WINRS_CONSOLEMODE_STDIN">FALSE</w:Option><w:Option Name="WINRS_SKIP_CMD_SHELL">FALSE</w:Option></w:OptionSet>`
	maxResponse    = 64 << 20
)

// call sends one SOAP request: action on the shell (empty: none yet).
func (c *Client) call(ctx context.Context, action, shell, options string, body []byte) (*response, error) {
	env := c.envelope(action, shell, options, body)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.cfg.Endpoint, bytes.NewReader(env))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/soap+xml;charset=UTF-8")
	req.SetBasicAuth(c.cfg.User, c.cfg.Password) // NTLM reads the login from here; it never sends it
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, maxResponse))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode == http.StatusUnauthorized {
		return nil, ErrAuth
	}
	r, perr := parse(b)
	switch {
	case perr == nil && r.fault != nil:
		return nil, r.fault
	case resp.StatusCode != http.StatusOK && perr == nil:
		return nil, fmt.Errorf("the WinRM server answered HTTP %d", resp.StatusCode)
	case resp.StatusCode != http.StatusOK:
		return nil, fmt.Errorf("the WinRM server answered HTTP %d: %s", resp.StatusCode, snippet(b))
	case perr != nil:
		return nil, fmt.Errorf("the WinRM server's answer is not WS-Management: %v", perr)
	}
	return r, nil
}

// envelope is a WS-Management request.
func (c *Client) envelope(action, shell, options string, body []byte) []byte {
	var b bytes.Buffer
	b.WriteString(`<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" xmlns:a="http://schemas.xmlsoap.org/ws/2004/08/addressing" ` +
		`xmlns:w="http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd" xmlns:p="http://schemas.microsoft.com/wbem/wsman/1/wsman.xsd" xmlns:rsp="` + nsShell + `">`)
	b.WriteString(`<s:Header><a:To>` + esc(c.cfg.Endpoint) + `</a:To>`)
	b.WriteString(`<a:ReplyTo><a:Address s:mustUnderstand="true">http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous</a:Address></a:ReplyTo>`)
	b.WriteString(`<w:ResourceURI s:mustUnderstand="true">http://schemas.microsoft.com/wbem/wsman/1/windows/shell/cmd</w:ResourceURI>`)
	b.WriteString(`<a:Action s:mustUnderstand="true">` + action + `</a:Action>`)
	b.WriteString(`<w:MaxEnvelopeSize s:mustUnderstand="true">153600</w:MaxEnvelopeSize>`)
	b.WriteString(`<a:MessageID>uuid:` + uuid() + `</a:MessageID>`)
	b.WriteString(`<w:Locale xml:lang="en-US" s:mustUnderstand="false"/><p:DataLocale xml:lang="en-US" s:mustUnderstand="false"/>`)
	b.WriteString(`<w:OperationTimeout>PT` + strconv.Itoa(int(c.cfg.OperationTimeout/time.Second)) + `S</w:OperationTimeout>`)
	if shell != "" {
		b.WriteString(`<w:SelectorSet><w:Selector Name="ShellId">` + esc(shell) + `</w:Selector></w:SelectorSet>`)
	}
	b.WriteString(options)
	b.WriteString(`</s:Header><s:Body>`)
	b.Write(body)
	b.WriteString(`</s:Body></s:Envelope>`)
	return b.Bytes()
}

// response is what komando reads from an answer.
type response struct {
	shellID, commandID string
	streams            []stream
	done               bool
	exitCode           int
	fault              *Error
}

type stream struct {
	name string
	data []byte
}

// parse reads an answer by element names, whatever the namespace prefixes.
func parse(b []byte) (*response, error) {
	r := &response{}
	d := xml.NewDecoder(bytes.NewReader(b))
	var path []string
	var attrs []xml.Attr
	var text strings.Builder
	sawEnvelope := false
	for {
		tok, err := d.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
		switch t := tok.(type) {
		case xml.StartElement:
			sawEnvelope = sawEnvelope || t.Name.Local == "Envelope"
			path = append(path, t.Name.Local)
			attrs = t.Attr
			text.Reset()
			r.start(t)
		case xml.CharData:
			text.Write(t)
		case xml.EndElement:
			if err := r.end(path, attrs, strings.TrimSpace(text.String())); err != nil {
				return nil, err
			}
			text.Reset()
			if len(path) > 0 {
				path = path[:len(path)-1]
			}
		}
	}
	if !sawEnvelope {
		return nil, errors.New("no SOAP envelope")
	}
	return r, nil
}

func attr(attrs []xml.Attr, name string) string {
	for _, a := range attrs {
		if a.Name.Local == name {
			return a.Value
		}
	}
	return ""
}

// start reads what an element says in its attributes.
func (r *response) start(t xml.StartElement) {
	switch t.Name.Local {
	case "Fault":
		r.fault = &Error{}
	case "WSManFault":
		if r.fault != nil {
			r.fault.Code = attr(t.Attr, "Code")
		}
	case "CommandState":
		r.done = strings.HasSuffix(attr(t.Attr, "State"), "/Done")
	}
}

// end reads an element's text.
func (r *response) end(path []string, attrs []xml.Attr, text string) error {
	switch path[len(path)-1] {
	case "ShellId":
		r.shellID = text
	case "Selector":
		if attr(attrs, "Name") == "ShellId" && r.shellID == "" {
			r.shellID = text
		}
	case "CommandId":
		r.commandID = text
	case "Stream":
		data, err := base64.StdEncoding.DecodeString(text)
		if err != nil {
			return fmt.Errorf("output stream: %v", err)
		}
		if len(data) > 0 {
			r.streams = append(r.streams, stream{name: attr(attrs, "Name"), data: data})
		}
	case "ExitCode":
		n, err := strconv.Atoi(text)
		if err != nil {
			return fmt.Errorf("exit code %q", text)
		}
		r.exitCode = n
	case "Text", "Message":
		if r.fault != nil && text != "" && (r.fault.Message == "" || path[len(path)-1] == "Message") {
			r.fault.Message = text
		}
	}
	return nil
}

// esc is s as XML text.
func esc(s string) string {
	var b strings.Builder
	_ = xml.EscapeText(&b, []byte(s))
	return b.String()
}

func uuid() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	b[6] = b[6]&0x0f | 0x40
	b[8] = b[8]&0x3f | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:])
}

// snippet is the start of an answer that is not XML, for an error message.
func snippet(b []byte) string {
	s := strings.Join(strings.Fields(string(b)), " ")
	if len(s) > 200 {
		s = s[:200] + "..."
	}
	return s
}
