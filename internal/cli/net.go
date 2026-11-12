package cli

import (
	"net"
	"regexp"
	"strconv"
	"strings"

	"github.com/spf13/cobra"

	"github.com/sgnd/komando/internal/out"
	"github.com/sgnd/komando/internal/sshx"
	"github.com/sgnd/komando/internal/store"
)

// netCheckFn tries one TCP connection with one method, so a filtered port
// costs 5 seconds, not 10, and says why it failed where it can tell:
// refused, timeout, dns or unreachable.
const netCheckFn = `chk() {
  s=$(date +%s%N 2>/dev/null)
  if command -v bash >/dev/null 2>&1 && command -v timeout >/dev/null 2>&1; then
    e=$(timeout 5 bash -c 'exec 3<>/dev/tcp/$0/$1' "$1" "$2" 2>&1); rc=$?
    if [ $rc -eq 0 ]; then r="open -"
    elif [ $rc -eq 124 ] || [ $rc -eq 143 ]; then r="closed timeout"
    else case "$e" in
      *[Rr]efused*) r="closed refused" ;;
      *"not known"*|*"resolve"*|*"No address"*|*"Name or service"*) r="closed dns" ;;
      *[Uu]nreachable*) r="closed unreachable" ;;
      *) r="closed error" ;;
    esac; fi
  elif command -v nc >/dev/null 2>&1; then
    if nc -z -w 5 "$1" "$2" >/dev/null 2>&1; then r="open -"; else r="closed -"; fi
  else r="closed no-tool"; fi
  t=$(date +%s%N 2>/dev/null)
  echo "$3 $r $(( (t-s)/1000000 ))"
}
`

// parseNetCheck reads "TARGET open|closed REASON MS" lines.
func parseNetCheck(s string) ([]map[string]any, *out.Error) {
	rows := []map[string]any{}
	var closed []string
	for _, line := range strings.Split(strings.TrimSpace(s), "\n") {
		f := strings.Fields(line)
		if len(f) < 2 {
			continue
		}
		r := map[string]any{"target": f[0], "open": f[1] == "open"}
		if len(f) > 2 && f[2] != "-" {
			r["reason"] = f[2]
		}
		if len(f) > 3 {
			if ms, err := strconv.Atoi(f[3]); err == nil && ms >= 0 {
				r["ms"] = ms
			}
		}
		if f[1] != "open" {
			c := f[0]
			if r["reason"] != nil {
				c += " (" + r["reason"].(string) + ")"
			}
			closed = append(closed, c)
		}
		rows = append(rows, r)
	}
	// like nc -z: a closed port fails, so `net check ... && deploy` works
	if len(closed) > 0 {
		return rows, out.Errf(out.ExitRemote, "PORT_CLOSED", "check the address, firewall or service on the other side", "cannot connect to %s", strings.Join(closed, ", "))
	}
	return rows, nil
}

func netCheckText(data any) string {
	rows := [][]string{}
	for _, r := range data.([]map[string]any) {
		rows = append(rows, []string{cell(r["target"]), yesCell(r["open"] == true), cell(r["reason"]), cell(r["ms"])})
	}
	return textTable([]string{"target", "open", "reason", "ms"}, rows)
}

func netCheckRun(cmd *cobra.Command, args []string) error {
	var sb strings.Builder
	sb.WriteString(netCheckFn)
	for _, hp := range args[1:] {
		h, p, err := net.SplitHostPort(hp)
		if err != nil {
			return out.Usage("expected HOST:PORT (or [IPv6]:PORT), got %q", hp)
		}
		if n, err := strconv.Atoi(p); err != nil || n < 1 || n > 65535 {
			return out.Usage("the port in %q is not a number from 1 to 65535", hp)
		}
		if h == "" || strings.ContainsAny(h, " \t'\"$`;&|\\/") {
			return out.Usage("the address in %q is not a name or IP address: no spaces, quotes or shell characters", hp)
		}
		sb.WriteString("chk " + sshx.Q(h) + " " + p + " " + sshx.Q(hp) + "\n")
	}
	return runOps(cmd.Context(), opsSpec{name: "net.check", target: args[0], command: sb.String(), display: "net check " + strings.Join(args[1:], " "),
		parse: func(_ *store.Host, rr *sshx.RunResult) (any, *out.Error) {
			rows, err := parseNetCheck(rr.Stdout)
			return rows, err
		}, text: netCheckText})
}

// net ports.

const netPortsScript = `if command -v ss >/dev/null 2>&1; then echo '#komando:ss'; ss -tulpnH
elif command -v netstat >/dev/null 2>&1; then echo '#komando:netstat'; netstat -tulpn 2>/dev/null
else echo '#komando:no-tool'; fi`

var reSSUser = regexp.MustCompile(`\("([^"]+)",pid=(\d+)`)

// splitAddrPort splits "0.0.0.0:22", "[::]:22", ":::22" and "*:22".
func splitAddrPort(s string) (string, int) {
	i := strings.LastIndex(s, ":")
	if i < 0 {
		return s, 0
	}
	port, _ := strconv.Atoi(s[i+1:])
	addr := strings.Trim(s[:i], "[]")
	if addr == "::" || addr == "" {
		addr = "::"
	}
	return addr, port
}

// parsePorts reads `ss -tulpnH` or (busybox) `netstat -tulpn` output.
func parsePorts(s string) ([]map[string]any, *out.Error) {
	sec := sections(s)
	if _, ok := sec["no-tool"]; ok {
		return nil, out.Errf(out.ExitNotFound, "TOOL_MISSING", "install iproute2 (ss) or net-tools (netstat)", "neither ss nor netstat is installed")
	}
	rows := []map[string]any{}
	add := func(proto, state, local, proc string) {
		addr, port := splitAddrPort(local)
		r := map[string]any{"proto": strings.TrimSuffix(proto, "6"), "state": state, "address": addr, "port": port}
		if m := reSSUser.FindAllStringSubmatch(proc, -1); len(m) > 0 {
			r["process"] = m[0][1]
			r["pid"], _ = strconv.Atoi(m[0][2])
		} else if pid, prog, ok := strings.Cut(proc, "/"); ok { // netstat: 123/sshd
			r["process"] = prog
			if n, err := strconv.Atoi(pid); err == nil {
				r["pid"] = n
			}
		}
		rows = append(rows, r)
	}
	for _, line := range strings.Split(sec["ss"], "\n") {
		f := strings.Fields(line)
		if len(f) < 5 {
			continue
		}
		proc := ""
		if len(f) > 6 {
			proc = strings.Join(f[6:], " ")
		}
		add(f[0], f[1], f[4], proc)
	}
	for _, line := range strings.Split(sec["netstat"], "\n") {
		f := strings.Fields(line)
		if len(f) < 6 || !(strings.HasPrefix(f[0], "tcp") || strings.HasPrefix(f[0], "udp")) {
			continue
		}
		state, proc := "UNCONN", ""
		rest := f[5:]
		if len(rest) > 0 && strings.ToUpper(rest[0]) == rest[0] && !strings.Contains(rest[0], "/") && rest[0] != "-" {
			state, rest = rest[0], rest[1:]
		}
		if len(rest) > 0 && rest[0] != "-" {
			proc = rest[0]
		}
		add(f[0], state, f[3], proc)
	}
	return rows, nil
}

func netPortsText(data any) string {
	rows := [][]string{}
	for _, r := range data.([]map[string]any) {
		rows = append(rows, []string{cell(r["proto"]), cell(r["address"]), cell(r["port"]), cell(r["process"]), cell(r["pid"])})
	}
	return textTable([]string{"proto", "address", "port", "process", "pid"}, rows)
}

func netPortsRun(cmd *cobra.Command, target string, sudo bool, limit int) error {
	return runOps(cmd.Context(), opsSpec{name: "net.ports", target: target, command: netPortsScript, display: "net ports", sudo: sudo, limit: limit,
		parse: func(_ *store.Host, rr *sshx.RunResult) (any, *out.Error) {
			rows, err := parsePorts(rr.Stdout)
			if err != nil {
				return nil, err
			}
			if !sudo {
				for _, r := range rows {
					if r["process"] == nil {
						return opsWarnings{data: rows, warnings: []string{"some processes are hidden; add --sudo to see them all"}}, nil
					}
				}
			}
			return rows, nil
		}, text: netPortsText})
}

// net dns.

var dnsTypes = map[string]bool{"A": true, "AAAA": true, "CNAME": true, "MX": true, "NS": true, "TXT": true, "SOA": true, "SRV": true, "PTR": true, "CAA": true}

// dnsCommand resolves name; with a record type it needs dig, except for A
// and AAAA, which getent answers too.
// dnsNameRe is a name (or an address, for PTR) to look up. Nothing else
// gets to dig or getent: a name starting with - would be an option there
// (dig -f FILE reads a file on the server).
var dnsNameRe = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9_.:-]{0,252}$`)

func dnsCommand(name, typ string) (string, error) {
	if !dnsNameRe.MatchString(name) {
		return "", out.Usage("%q is not a host name or IP address: give one like db.internal or 10.0.0.5", name)
	}
	q := sshx.Q(name)
	if typ == "" {
		return "getent ahosts " + q + " | awk '{print $1}' | sort -u", nil
	}
	typ = strings.ToUpper(typ)
	if !dnsTypes[typ] {
		return "", out.Usage("unknown record type %q: use A, AAAA, CNAME, MX, NS, TXT, SOA, SRV, PTR or CAA", typ)
	}
	c := "if command -v dig >/dev/null 2>&1; then dig +short -t " + typ + " " + q + "\n"
	switch typ {
	case "A":
		c += "else getent ahostsv4 " + q + " | awk '{print $1}' | sort -u\n"
	case "AAAA":
		c += "else getent ahostsv6 " + q + " | awk '{print $1}' | sort -u\n"
	default:
		c += "else echo '#komando:no-dig'\n"
	}
	return c + "fi", nil
}

func dnsResult(name, typ, s string) (any, *out.Error) {
	if marker(s) == "no-dig" {
		return nil, out.Errf(out.ExitNotFound, "DIG_MISSING", "install dig (Debian/Ubuntu: dnsutils, Alpine: bind-tools, RHEL: bind-utils), for example `komando pkg install TARGET dnsutils`; A and AAAA work without it",
			"%s records need dig, which is not installed on this server", strings.ToUpper(typ))
	}
	var recs []string
	for _, l := range strings.Split(s, "\n") {
		if l = strings.TrimSpace(l); l != "" && !strings.HasPrefix(l, ";") {
			recs = append(recs, l)
		}
	}
	if typ == "" {
		res := map[string]any{"name": name, "addresses": strings.Fields(s)}
		if len(recs) == 0 {
			return res, out.Errf(out.ExitNotFound, "NXDOMAIN", "check the name, and the server's DNS (/etc/resolv.conf)", "%s does not resolve from this server", name)
		}
		return res, nil
	}
	res := map[string]any{"name": name, "type": strings.ToUpper(typ), "records": recs}
	if len(recs) == 0 {
		res["records"] = []string{}
		return res, out.Errf(out.ExitNotFound, "NO_RECORDS", "check the name and type, and the server's DNS (/etc/resolv.conf)",
			"%s has no %s records (or does not exist) from this server", name, strings.ToUpper(typ))
	}
	return res, nil
}

func dnsText(data any) string {
	m, _ := data.(map[string]any)
	var l []string
	switch v := m["records"].(type) {
	case []string:
		l = v
	}
	if a, ok := m["addresses"].([]string); ok {
		l = a
	}
	if len(l) == 0 {
		return ""
	}
	return strings.Join(l, "\n") + "\n"
}
