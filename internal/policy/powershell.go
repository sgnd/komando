package policy

import (
	"fmt"
	"regexp"
	"strings"
	"unicode/utf8"
)

// PowerShell's --read-only check for Windows servers. It fails closed: a
// command passes only when every part of it is something komando fully
// understands and knows to only read. That is a deliberately small subset
// of PowerShell:
//
//   - statements separated by ; or a new line, each a pipeline ( | ) of
//     commands from psReadCommands, or a program from psNatives with the
//     arguments listed there;
//   - arguments that are literals: a bareword of plain characters (C:\x,
//     W3SVC, 50, *.log), a '...' or "..." string with no $ in it, a
//     -Parameter from psSafeParams (no -Name:value), and commas between
//     values;
//   - Where-Object { $_.Prop -op value [-and|-or ...] } and
//     ForEach-Object { $_.Prop }: the only script blocks it reads.
//
// Everything else is refused: other characters, variables, expressions,
// .NET calls, redirection, comments, here-strings, the call operator,
// keywords, and commands, aliases and parameters not on the lists. A
// denylist over a partial tokenizer kept leaking where PowerShell reads a
// script differently; a subset this small is read the same way by both.

// PSReadOnly is why a PowerShell script is not accepted under --read-only,
// or "" when it is in the read-only subset.
func PSReadOnly(script string) string {
	toks, why := psLex(script)
	if why != "" {
		return why
	}
	cmds, why := psCommands(toks)
	if why != "" {
		return why
	}
	for _, c := range cmds {
		if why := psCheckCommand(c); why != "" {
			return why
		}
	}
	return ""
}

// PSOnlyReads reports a script whose every command komando knows to only
// read, so a protected server skips its --yes. The subset PSReadOnly
// accepts holds only such commands, so PSOnlyReads is exactly as strict.
func PSOnlyReads(script string) bool {
	return PSReadOnly(script) == ""
}

// psTok is one token of the subset: a bareword ('w'), a -Parameter ('p'),
// a quoted string ('s', the text inside the quotes), a comma, a script
// block ('b', the text inside the braces), a pipe or a statement end (';').
type psTok struct {
	kind byte
	text string
}

// psForbidden says why a character refuses the script wherever it stands,
// even inside a string.
var psForbidden = map[byte]string{
	'`': "a backtick (escape characters and line continuations)",
	'@': "@ (arrays, hash tables, splatting and here-strings)",
	'&': "& (the call operator, background jobs and &&)",
}

// psOutside says why a character outside a string is refused.
var psOutside = map[byte]string{
	'$': "$ (variables and expressions)",
	'#': "# (comments)",
	'<': "< (redirection and block comments)",
	'>': "> (redirection into a file)",
	'(': "( (expressions and method calls)",
	')': ") (expressions and method calls)",
	'[': "[ (types and static .NET calls)",
	']': "] (types and static .NET calls)",
	'}': "} without a script block komando reads",
	'=': "= (assignments)",
}

// psWordChar: the characters of a bareword.
func psWordChar(c byte) bool {
	return isLetter(c) || c >= '0' && c <= '9' || strings.IndexByte(`_.:\/*?~%+-`, c) >= 0
}

func isLetter(c byte) bool { return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' }

// psBoundary: what may follow a token. A bareword may also run into a
// script block (%{ $_.Name }).
func psBoundary(s string, i int, word bool) bool {
	return i >= len(s) || strings.IndexByte(" \t\r\n;|,", s[i]) >= 0 || word && s[i] == '{'
}

// psLex reads the script into tokens, or says why it is not in the subset.
func psLex(s string) ([]psTok, string) {
	if why := psChars(s); why != "" {
		return nil, why
	}
	var toks []psTok
	for i := 0; i < len(s); {
		c, start := s[i], i
		switch {
		case c == ' ' || c == '\t' || c == '\r':
			i++
			continue
		case c == '\n' || c == ';':
			toks = append(toks, psTok{';', ""})
			i++
			continue
		case c == '|':
			if i+1 < len(s) && s[i+1] == '|' {
				return nil, "|| (a second command that runs when the first fails)"
			}
			toks = append(toks, psTok{'|', ""})
			// a new line after | goes on with the pipeline
			for i++; i < len(s) && strings.IndexByte(" \t\r\n", s[i]) >= 0; i++ {
			}
			continue
		case c == ',':
			toks = append(toks, psTok{',', ""})
			i++
			continue
		case c == '\'' || c == '"':
			j := strings.IndexByte(s[i+1:], c)
			if j < 0 {
				return nil, "a string without its closing quote"
			}
			if text := s[i+1 : i+1+j]; strings.Contains(text, "$") {
				return nil, "$ inside a string (PowerShell fills in variables and expressions there)"
			}
			toks = append(toks, psTok{'s', s[i+1 : i+1+j]})
			i += j + 2
		case c == '{':
			j := strings.IndexByte(s[i+1:], '}')
			if j < 0 {
				return nil, "a script block without its closing }"
			}
			toks = append(toks, psTok{'b', s[i+1 : i+1+j]})
			i += j + 2
		case c == '-' && i+1 < len(s) && isLetter(s[i+1]):
			for i++; i < len(s) && (isLetter(s[i]) || s[i] >= '0' && s[i] <= '9'); i++ {
			}
			if i < len(s) && s[i] == ':' {
				return nil, s[start:i] + ": (a parameter with its value attached)"
			}
			toks = append(toks, psTok{'p', s[start:i]})
		case c != '-' && psWordChar(c):
			for i < len(s) && psWordChar(s[i]) {
				i++
			}
			toks = append(toks, psTok{'w', s[start:i]})
		default:
			if why, ok := psOutside[c]; ok {
				return nil, why
			}
			return nil, fmt.Sprintf("%q where komando expects a command or an argument", c)
		}
		if !psBoundary(s, i, toks[len(toks)-1].kind == 'w') {
			if why, ok := psOutside[s[i]]; ok {
				return nil, why
			}
			return nil, fmt.Sprintf("%q right after %s (komando reads only words, strings and parameters with spaces between them)", s[i], s[start:i])
		}
	}
	return toks, ""
}

// psChars refuses a character outside plain printable ASCII, space, tab
// and new line (\r only before \n), and the characters of psForbidden.
func psChars(s string) string {
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 0x80:
			r, _ := utf8.DecodeRuneInString(s[i:])
			return fmt.Sprintf("a character outside plain ASCII (%U); PowerShell reads some of them as quotes or dashes", r)
		case c == '\r' && (i+1 == len(s) || s[i+1] != '\n'), c < 0x20 && c != '\t' && c != '\n' && c != '\r', c == 0x7f:
			return fmt.Sprintf("a control character (%U)", rune(c))
		}
		if why, ok := psForbidden[c]; ok {
			return why
		}
	}
	return ""
}

// psCommands splits the tokens into the commands of the pipelines: every
// command starts with a bareword, and a pipe stands between two commands.
func psCommands(toks []psTok) ([][]psTok, string) {
	var cmds [][]psTok
	var cur []psTok
	afterPipe := false
	for _, t := range toks {
		switch t.kind {
		case ';', '|':
			if len(cur) == 0 && (afterPipe || t.kind == '|') {
				return nil, "| without a command on both sides"
			}
			if len(cur) > 0 {
				cmds = append(cmds, cur)
			}
			cur, afterPipe = nil, t.kind == '|'
		default:
			if len(cur) == 0 && t.kind != 'w' {
				return nil, "a statement that does not start with a command name (a value, a string or an expression)"
			}
			cur = append(cur, t)
		}
	}
	if afterPipe && len(cur) == 0 {
		return nil, "| without a command on both sides"
	}
	if len(cur) > 0 {
		cmds = append(cmds, cur)
	}
	return cmds, ""
}

// psCheckCommand says why one command of a pipeline is not in the subset.
func psCheckCommand(c []psTok) string {
	name, args := strings.ToLower(c[0].text), c[1:]
	if allowed, ok := psNatives[strings.TrimSuffix(name, ".exe")]; ok {
		return psCheckNative(c[0].text, allowed, args)
	}
	canon, ok := psReadCommands[name]
	switch {
	case name == ".":
		return ". (dot-sourcing runs a script in the session)"
	case psKeywords[name]:
		return c[0].text + " is a PowerShell keyword; --read-only accepts only commands"
	case !ok && (strings.HasPrefix(name, ".") || strings.ContainsAny(name, `\/`)):
		return c[0].text + " runs a script or program by its path, which komando cannot read"
	case !ok:
		return c[0].text + " is not on komando's list of read commands"
	case canon == "":
		canon = name
	}
	if canon == "foreach-object" {
		if len(args) != 1 || args[0].kind != 'b' || !psPropBlock.MatchString(args[0].text) {
			return c[0].text + " is accepted only as { $_.Property } (a member name or other code may call a method)"
		}
		return ""
	}
	for i, a := range args {
		switch a.kind {
		case 'b':
			if canon != "where-object" || len(args) != 1 || !psWhereBlock.MatchString(a.text) {
				return "the script block {" + a.text + "}: komando reads only Where-Object { $_.Property -op value } and ForEach-Object { $_.Property }"
			}
		case 'p':
			if !psSafeParams[strings.ToLower(a.text[1:])] {
				return a.text + " is not a parameter komando knows to be safe (write parameter names in full)"
			}
		case ',':
			if i == 0 || i == len(args)-1 || args[i-1].kind == ',' || args[i+1].kind == 'p' || args[i+1].kind == ',' {
				return "a comma without a value on both sides"
			}
		default:
			if why := psPathArg(a.text); why != "" {
				return why
			}
		}
	}
	return ""
}

// psPathArg refuses a path to another computer (reading \\server\share
// logs in there with the user's credentials; Windows reads / as \, so
// \/server is one too) and a provider-qualified one.
func psPathArg(a string) string {
	if strings.Contains(strings.ReplaceAll(a, "/", `\`), `\\`) {
		return a + `: a path to another computer (\\server) or a device`
	}
	if strings.Contains(a, "::") {
		return a + ": :: (provider paths and static .NET members)"
	}
	return ""
}

// psCheckNative accepts a program with only the arguments listed for it.
func psCheckNative(name string, allowed *regexp.Regexp, args []psTok) string {
	for _, a := range args {
		if a.kind != 'w' && a.kind != 'p' || allowed == nil || !allowed.MatchString(a.text) {
			return name + " is accepted under --read-only only with arguments that read"
		}
	}
	return ""
}

// The script blocks komando reads: properties of $_ (or $PSItem), and
// comparisons of them with a literal, joined by -and or -or.
var (
	psPropRe  = `\$(_|psitem)(\.[a-z_][a-z0-9_]*)*`
	psValueRe = `([0-9]+(\.[0-9]+)?|'[^'$]*'|"[^"$]*"|\$(true|false|null))`
	psOpRe    = `-[ci]?(eq|ne|gt|ge|lt|le|like|notlike|match|notmatch|contains|notcontains|in|notin)`
	psCondRe  = psPropRe + `(\s+` + psOpRe + `\s+` + psValueRe + `)?`

	psPropBlock  = regexp.MustCompile(`(?i)^\s*` + psPropRe + `\s*$`)
	psWhereBlock = regexp.MustCompile(`(?i)^\s*` + psCondRe + `(\s+-(and|or)\s+` + psCondRe + `)*\s*$`)
)

// psNatives are the Windows programs accepted, each with the arguments it
// may get (nil: none; hostname NAME would rename the computer).
var psNatives = map[string]*regexp.Regexp{
	"hostname":   nil,
	"quser":      nil,
	"whoami":     regexp.MustCompile(`(?i)^(/(all|user|groups|priv|upn|fqdn|logonid|claims|fo|nh)|csv|table|list)$`),
	"ipconfig":   regexp.MustCompile(`(?i)^/(all|displaydns)$`),
	"systeminfo": regexp.MustCompile(`(?i)^(/(fo|nh)|csv|table|list)$`),
	"tasklist":   regexp.MustCompile(`(?i)^(/(v|svc|m|nh|fo)|csv|table|list)$`),
	"netstat":    regexp.MustCompile(`(?i)^(-[abefnopqrstxy]+|tcp|udp|tcpv6|udpv6|ip|ipv6|icmp|icmpv6)$`),
}

// psReadCommands are the cmdlets accepted and their aliases (alias ->
// cmdlet, cmdlet -> ""). The list is explicit, not Get-*: some Get-
// cmdlets change something (Get-Certificate enrolls a certificate,
// Get-PackageProvider can install one, module cmdlets may install updates).
var psReadCommands = psCommandSet(map[string]string{
	// files, the registry and PowerShell's drives
	"get-childitem": "gci ls dir", "get-item": "gi", "get-itemproperty": "gp", "get-itempropertyvalue": "gpv",
	"get-content": "gc cat type", "get-location": "gl pwd", "get-psdrive": "gdr", "get-psprovider": "",
	"get-acl": "", "get-filehash": "", "test-path": "", "select-string": "sls",
	"set-location": "cd chdir sl", "push-location": "pushd", "pop-location": "popd",
	// processes, services, events, the system
	"get-process": "gps ps", "get-service": "gsv", "get-eventlog": "", "get-winevent": "", "get-hotfix": "",
	"get-computerinfo": "", "get-date": "", "get-timezone": "", "get-culture": "", "get-uptime": "",
	"get-counter": "", "get-ciminstance": "gcim", "get-cimclass": "", "get-wmiobject": "gwmi",
	"get-scheduledtask": "", "get-scheduledtaskinfo": "", "get-windowsfeature": "",
	"get-localuser": "", "get-localgroup": "", "get-localgroupmember": "",
	"get-disk": "", "get-volume": "", "get-partition": "", "get-physicaldisk": "", "get-smbshare": "",
	"get-website": "", "get-webbinding": "", "get-iissite": "", "get-iisapppool": "",
	// network
	"get-nettcpconnection": "", "get-netudpendpoint": "", "get-netipaddress": "", "get-netipconfiguration": "",
	"get-netadapter": "", "get-netroute": "", "get-netfirewallrule": "", "get-netfirewallprofile": "",
	"get-dnsclientserveraddress": "", "get-dnsclientcache": "", "resolve-dnsname": "",
	"test-connection": "", "test-netconnection": "",
	// PowerShell itself
	"get-command": "gcm", "get-member": "gm", "get-alias": "gal", "get-module": "", "get-executionpolicy": "",
	"get-host": "", "get-history": "h history",
	// shaping the output
	"select-object": "select", "where-object": "where ?", "foreach-object": "%", "sort-object": "sort",
	"group-object": "group", "measure-object": "measure", "get-unique": "gu",
	"format-table": "ft", "format-list": "fl", "format-wide": "fw",
	"out-string": "", "out-host": "oh", "out-null": "", "convertto-json": "", "convertto-csv": "",
	"write-output": "echo write", "write-host": "",
})

// psSafeParams are the parameters accepted, by their full names only: an
// abbreviation could stand for another parameter. None of them sends
// credentials elsewhere (-ComputerName, -Credential, -CimSession, and
// -Source, where Test-Connection pings from another computer) or runs
// code (-ScriptBlock, -FilterScript, -Process, -MemberName).
var psSafeParams = words(
	// common to many cmdlets
	"path literalpath name displayname id include exclude filter erroraction ea warningaction wa " +
		// files and the registry
		"recurse depth force file directory hidden attributes tail totalcount head readcount raw encoding delimiter stream " +
		"pattern simplematch notmatch allmatches casesensitive context quiet list algorithm pathtype isvalid " +
		// selecting, sorting, measuring, formatting
		"property expandproperty excludeproperty first last skip skiplast unique index descending ascending stable top bottom " +
		"noelement asstring sum average maximum minimum line word character autosize wrap hidetableheaders groupby " +
		"width compress notypeinformation nonewline foregroundcolor " +
		// Where-Object's comparison form
		"value not eq ne gt ge lt le like notlike match contains notcontains in notin is isnot " +
		"ceq cne cgt cge clt cle clike cnotlike cmatch cnotmatch ccontains cnotcontains cin cnotin " +
		// events, services, processes, WMI and CIM
		"logname newest after before entrytype instanceid message maxevents oldest listlog listprovider providername " +
		"filterxpath dependentservices requiredservices includeusername module fileversioninfo " +
		"classname class namespace query keyonly shallow format uformat date counter listset sampleinterval maxsamples " +
		"taskname taskpath group member membertype static commandtype verb noun syntax all listavailable " +
		// network
		"port informationlevel traceroute detailed count type server state localport remoteport localaddress remoteaddress " +
		"owningprocess addressfamily interfacealias interfaceindex protocol direction enabled action driveletter number")

var psKeywords = words("if elseif else foreach for while do until switch return break continue param begin process end " +
	"function filter try catch finally throw exit in trap data dynamicparam class enum using")

// psCommandSet makes the alias -> cmdlet map of psReadCommands.
func psCommandSet(cmdlets map[string]string) map[string]string {
	m := map[string]string{}
	for c, aliases := range cmdlets {
		m[c] = ""
		for _, a := range strings.Fields(aliases) {
			m[a] = c
		}
	}
	return m
}

// words is a set of the space-separated words in s.
func words(s string) map[string]bool {
	m := map[string]bool{}
	for _, w := range strings.Fields(s) {
		m[w] = true
	}
	return m
}
