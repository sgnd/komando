package cli

import (
	"sort"
	"time"

	"github.com/spf13/cobra"

	"github.com/sgnd/komando/internal/netx"
	"github.com/sgnd/komando/internal/out"
	"github.com/sgnd/komando/internal/store"
)

// komando status lists what komando left running: VPN sessions and tunnels
// on this computer, and the jobs it started on servers. It contacts nothing
// (docs/design/session-status.md): sessions and tunnels are checked here,
// and jobs are only listed, because whether one still runs is known on its
// server (`job list --refresh` asks).

type runningVpn struct {
	Name     string    `json:"name"`
	Kind     string    `json:"kind"`
	Since    time.Time `json:"since"`
	LastUsed time.Time `json:"last_used"`
	ClosesAt time.Time `json:"closes_at,omitzero"` // if nothing uses it before then (vpn_idle)
	UsedBy   []string  `json:"used_by,omitempty"`
}

// runningLogin is a server login kept by `komando login HOST`.
type runningLogin struct {
	Host  string    `json:"host"`
	Since time.Time `json:"since"`
	Until time.Time `json:"until"`
}

type runningData struct {
	Vpns    []runningVpn   `json:"vpns"`
	Logins  []runningLogin `json:"logins"`
	Tunnels []tunnelRow    `json:"tunnels"`
	Jobs    []*store.Job   `json:"jobs"`
}

func statusCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "status",
		Short: "What komando left running: VPNs, logins, tunnels, jobs",
		Long: `Lists what still runs after the command that started it ended: VPN
sessions (from vpn up, or started by a command), server logins kept by
` + "`komando login HOST`" + `, tunnels, and the jobs
started on servers. Nothing is contacted, so it is quick and works offline.
A job is listed until ` + "`komando job rm`" + `; whether it still runs is known on
its server: ` + "`komando job list --refresh`" + ` asks.`,
		Example: `  komando status
  komando status -o json`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			st, err := loadState()
			if err != nil {
				return err
			}
			out.P.Print("status", runningStatus(st), nil)
			return nil
		},
	}
}

// sessionAlive is netx.SessionAlive; tests replace it.
var sessionAlive = netx.SessionAlive

func runningStatus(st *store.State) runningData {
	d := runningData{Vpns: []runningVpn{}, Logins: []runningLogin{}, Tunnels: []tunnelRow{}, Jobs: []*store.Job{}}
	idle, _ := time.ParseDuration(st.Settings.VpnIdle)
	for _, v := range st.SortedVpns() {
		s := st.Sessions[v.Name]
		if s == nil || !sessionAlive(s) {
			continue
		}
		r := runningVpn{Name: v.Name, Kind: v.Kind, Since: s.StartedAt, LastUsed: s.LastUsed, UsedBy: vpnUsers(st, v.Name)}
		if idle > 0 {
			r.ClosesAt = s.LastUsed.Add(idle)
		}
		d.Vpns = append(d.Vpns, r)
	}
	for _, n := range mapKeys(st.Logins) {
		l := st.Logins[n]
		if time.Now().Before(l.Until) && sessionAlive(&store.VpnSession{PID: l.PID, Exe: l.Exe}) {
			d.Logins = append(d.Logins, runningLogin{Host: l.Host, Since: l.StartedAt, Until: l.Until})
		}
	}
	for _, t := range st.Tunnels {
		if alive(t.PID) {
			d.Tunnels = append(d.Tunnels, tunnelRow{Tunnel: t, Alive: true, Listen: tunnelListen(t)})
		}
	}
	sort.Slice(d.Tunnels, func(i, j int) bool { return d.Tunnels[i].StartedAt.Before(d.Tunnels[j].StartedAt) })
	for _, j := range st.Jobs {
		d.Jobs = append(d.Jobs, j)
	}
	sort.Slice(d.Jobs, func(a, b int) bool { return d.Jobs[a].StartedAt.After(d.Jobs[b].StartedAt) })
	return d
}

func (d runningData) Text() string {
	if len(d.Vpns)+len(d.Logins)+len(d.Tunnels)+len(d.Jobs) == 0 {
		return "nothing running: no VPN sessions, server logins, tunnels or jobs\n"
	}
	now := time.Now()
	rows := [][]string{}
	for _, v := range d.Vpns {
		detail := "used " + humanAge(now.Sub(v.LastUsed)) + " ago"
		if !v.ClosesAt.IsZero() {
			if left := v.ClosesAt.Sub(now); left > 0 {
				detail += ", closes in " + humanAge(left) + " if unused"
			} else {
				detail += ", closes at the next command"
			}
		}
		rows = append(rows, []string{"vpn", v.Name, detail, humanAge(now.Sub(v.Since))})
	}
	for _, l := range d.Logins {
		rows = append(rows, []string{"login", cleanText(l.Host), "kept for " + humanAge(l.Until.Sub(now)) + " more (`komando logout " + cleanText(l.Host) + "` ends it)", humanAge(now.Sub(l.Since))})
	}
	for _, t := range d.Tunnels {
		listen, to := tunnelEnds(t)
		rows = append(rows, []string{"tunnel", t.ID, cleanText(listen + " → " + to), humanAge(now.Sub(t.StartedAt))})
	}
	for _, j := range d.Jobs {
		command := cleanText(j.Command)
		if len([]rune(command)) > 50 {
			command = string([]rune(command)[:47]) + "..."
		}
		rows = append(rows, []string{"job", j.ID, cleanText(j.Host) + ": " + command, humanAge(now.Sub(j.StartedAt))})
	}
	s := textTable([]string{"kind", "name", "detail", "since"}, rows)
	if len(d.Jobs) > 0 {
		s += "jobs run on their servers: `komando job list --refresh` shows which still run\n"
	}
	return s
}
