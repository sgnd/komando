package cli

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

// factsText is the short -o text view of `komando facts`: a few lines per
// server, warnings last. JSON has every detail.
func factsText(d probeData) string {
	var b strings.Builder
	for _, r := range d.Results {
		f, _ := r.Data.(map[string]any)
		if !r.OK || f == nil {
			msg := "failed"
			if r.Error != nil {
				msg = r.Error.Message
			} else if r.Stderr != "" {
				msg = r.Stderr
			}
			fmt.Fprintf(&b, "● %s  FAILED: %s\n", r.Host, msg)
			continue
		}
		writeFactsHost(&b, r.Host, f)
	}
	if len(d.Results) > 1 {
		fmt.Fprintf(&b, "\n%d ok, %d failed\n", d.Summary.OK, d.Summary.Failed)
	}
	return b.String()
}

func writeFactsHost(b *strings.Builder, host string, f map[string]any) {
	str := func(k string) string { s, _ := f[k].(string); return s }
	num := func(k string) (int64, bool) { n, ok := f[k].(int64); return n, ok }

	head := []string{}
	osName := str("os_pretty")
	if osName == "" {
		osName = strings.TrimSpace(str("os") + " " + str("os_version"))
	}
	head = append(head, osName)
	if a := str("arch"); a != "" {
		head = append(head, a)
	}
	if n, ok := num("cpus"); ok {
		head = append(head, fmt.Sprintf("%d cpu", n))
	}
	if n, ok := num("mem_total_mb"); ok {
		head = append(head, fmt.Sprintf("%.1f GB RAM", float64(n)/1024))
	}
	if n, ok := num("disk_root_used_pct"); ok {
		head = append(head, fmt.Sprintf("disk / %d%%", n))
	}
	if l, ok := f["load"].([]float64); ok && len(l) > 0 {
		head = append(head, fmt.Sprintf("load %.2f", l[0]))
	}
	if n, ok := num("uptime_sec"); ok {
		head = append(head, "up "+humanAge(time.Duration(n)*time.Second))
	}
	fmt.Fprintf(b, "● %s  %s\n", host, strings.Join(head, " · "))

	line := func(label, v string) {
		if v != "" {
			fmt.Fprintf(b, "  %-10s %s\n", label+":", v)
		}
	}

	if s, ok := f["os_support"].(osSupport); ok {
		line("support", supportText(s))
	}

	// updates, reboot, restarts
	var up []string
	if u, ok := f["updates"].(pendingUpdates); ok {
		up = append(up, countText(u.Total, "pending")+", "+countText(u.Security, "security"))
		if u.IndexAgeDays != nil {
			up = append(up, fmt.Sprintf("index %dd old", *u.IndexAgeDays))
		}
	}
	switch r := f["reboot_required"].(type) {
	case bool:
		if r {
			up = append(up, "REBOOT REQUIRED")
		}
	case nil:
		up = append(up, "reboot unknown")
	}
	if s, ok := f["services_need_restart"].([]string); ok && len(s) > 0 {
		up = append(up, "restart needed: "+strings.Join(s, ", "))
	}
	line("updates", strings.Join(up, " · "))

	var acc []string
	if u := str("login_user"); u != "" {
		acc = append(acc, "user "+u)
	}
	switch s := f["sudo_nopasswd"].(type) {
	case bool:
		acc = append(acc, "sudo "+map[bool]string{true: "without password", false: "needs a password"}[s])
	default:
		acc = append(acc, "sudo unknown")
	}
	if n, ok := num("failed_units"); ok {
		acc = append(acc, fmt.Sprintf("%d failed units", n))
	}
	line("access", strings.Join(acc, " · "))

	if d, ok := f["docker"].(map[string]any); ok && d["installed"] == true {
		v := "docker"
		if s, ok := d["version"].(string); ok && s != "" {
			v += " " + s
		}
		if d["daemon_reachable"] == true {
			v += fmt.Sprintf(" · swarm %v · %v running", d["swarm"], d["containers_running"])
		} else {
			v += " · daemon not reachable as this user"
		}
		line("docker", v)
	}

	if p, ok := f["pm2"].(pm2Facts); ok && len(p.DaemonUsers) > 0 {
		var parts []string
		if p.Apps != nil {
			for _, a := range p.Apps {
				parts = append(parts, a.Name+" "+a.Status)
			}
			if len(parts) == 0 {
				parts = append(parts, "no apps")
			}
			parts[0] = "(" + p.AppsOf + ") " + parts[0]
		}
		if len(p.OtherUsers) > 0 {
			parts = append(parts, "daemons of "+strings.Join(p.OtherUsers, ", ")+" (apps not listed)")
		} else if p.Apps == nil {
			parts = append(parts, "apps unknown")
		}
		line("pm2", strings.Join(parts, ", "))
	}

	if l, ok := f["listening"].(listenFacts); ok {
		line("ports", portsText(l))
	}

	if us, ok := f["custom_units"].([]customUnit); ok && len(us) > 0 {
		var parts []string
		for _, u := range us {
			parts = append(parts, u.Unit+" ("+dash(u.Active)+")")
		}
		line("units", strings.Join(parts, ", "))
	}

	if ws, ok := f["warnings"].([]string); ok {
		for _, w := range ws {
			fmt.Fprintf(b, "  warning: %s\n", w)
		}
	}
}

func supportText(s osSupport) string {
	switch s.Status {
	case "supported":
		return "supported until " + *s.StandardUntil
	case "extended":
		return "extended support (" + s.ExtendedBy + ") until " + *s.ExtendedUntil + ", standard support ended " + *s.StandardUntil
	case "unsupported":
		return "UNSUPPORTED: no security updates"
	}
	return "unknown"
}

func countText(n *int, what string) string {
	if n == nil {
		return what + " unknown"
	}
	return strconv.Itoa(*n) + " " + what
}

// portsText lists the listening ports in one line: "22 sshd, 80 nginx,
// 3000 node (127.0.0.1)"; a port on several addresses shows once.
func portsText(l listenFacts) string {
	if len(l.Ports) == 0 {
		return ""
	}
	type key struct {
		port int
		proc string
	}
	var order []key
	addrs := map[key][]string{}
	for _, p := range l.Ports {
		k := key{p.Port, p.Process}
		if _, ok := addrs[k]; !ok {
			order = append(order, k)
		}
		addrs[k] = append(addrs[k], p.Address)
	}
	var parts []string
	for _, k := range order {
		s := strconv.Itoa(k.port)
		if k.proc != "" {
			s += " " + k.proc
		}
		local := true
		for _, a := range addrs[k] {
			if !strings.HasPrefix(a, "127.") && a != "::1" && a != "localhost" {
				local = false
			}
		}
		if local {
			s += " (local only)"
		}
		parts = append(parts, s)
	}
	return strings.Join(parts, ", ")
}
