package cli

import (
	"context"
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"
	"sync"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	"github.com/sgnd/komando/internal/driver"
	"github.com/sgnd/komando/internal/out"
	"github.com/sgnd/komando/internal/store"
)

// `komando list` and `komando test` work on servers and conns together, so
// one command shows or checks everything in a group (`komando test @prod`).

type targetRow struct {
	Name      string   `json:"name"`
	Kind      string   `json:"kind"` // host, or the conn kind
	Where     string   `json:"where"`
	Via       string   `json:"via,omitempty"` // the --via path (bastions)
	Groups    []string `json:"groups,omitempty"`
	Tags      []string `json:"tags,omitempty"`
	Protected bool     `json:"protected"`
}

type targetList struct {
	Count   int         `json:"count"`
	Targets []targetRow `json:"targets"`
	empty   bool        // the inventory itself is empty
}

// emptyInventory is what a person reads when there is nothing yet.
const emptyInventory = "No servers or conns yet. Add a server: komando host add web1 deploy@10.0.0.5 (or import ~/.ssh/config: komando import ssh-config)\n" +
	"A database, cache or bucket: komando conn add app-db postgres://app@10.0.0.5/app --ask-password"

func (l targetList) Text() string {
	if l.empty {
		return emptyInventory + "\n"
	}
	var sb strings.Builder
	tw := tabwriter.NewWriter(&sb, 0, 2, 2, ' ', 0)
	fmt.Fprintln(tw, "NAME\tKIND\tWHERE\tVIA\tGROUPS\tTAGS\tPROTECTED")
	for _, r := range l.Targets {
		prot := "-" // a column of "false" hides the few that say yes
		if r.Protected {
			prot = "yes"
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\t%s\n", r.Name, r.Kind, r.Where, dash(r.Via),
			dash(strings.Join(r.Groups, ",")), dash(strings.Join(r.Tags, ",")), prot)
	}
	tw.Flush()
	return sb.String()
}

// only narrows list and test to one type: "host", "conn", or "" for both.
// `host list`, `conn test` and the like are these commands with only set.
func keepOnly(sel selection, only string) selection {
	switch only {
	case "host":
		sel.Conns, sel.Vpns = nil, nil
	case "conn":
		sel.Hosts, sel.Vpns = nil, nil
	case "vpn":
		sel.Hosts, sel.Conns = nil, nil
	}
	return sel
}

func listCmd() *cobra.Command { return listCmdFor("") }

func listCmdFor(only string) *cobra.Command {
	var target string
	c := &cobra.Command{
		Use:     "list [TARGET]",
		Aliases: []string{"ls"},
		Short:   "List servers, conns and VPNs (all, or what TARGET picks)",
		Example: "  komando list\n  komando list @prod\n  komando list kind:db",
		Args:    cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			st, err := loadState()
			if err != nil {
				return err
			}
			if len(args) == 1 {
				target = args[0]
			}
			sel := selection{Hosts: st.SortedHosts(), Conns: st.SortedConns(), Vpns: st.SortedVpns()}
			if target != "" {
				if sel, err = resolveSelection(st, target); err != nil {
					return err
				}
			}
			sel = keepOnly(sel, only)
			l := targetList{Targets: []targetRow{}, empty: len(st.Hosts)+len(st.Conns)+len(st.Vpns) == 0}
			for _, h := range sel.Hosts {
				l.Targets = append(l.Targets, targetRow{Name: h.Name, Kind: "host",
					Where: net.JoinHostPort(h.Address, strconv.Itoa(h.EffectivePort())), Via: h.Via,
					Groups: h.Groups, Tags: h.Tags, Protected: h.Protected})
			}
			for _, c := range sel.Conns {
				where := c.URL
				if t, err := driver.Parse(c.URL); err == nil {
					where = t.Where()
				}
				l.Targets = append(l.Targets, targetRow{Name: c.Name, Kind: c.Kind, Where: where, Via: c.Via,
					Groups: c.Groups, Tags: c.Tags, Protected: c.Protected})
			}
			for _, v := range sel.Vpns {
				l.Targets = append(l.Targets, targetRow{Name: v.Name, Kind: "vpn:" + v.Kind, Where: vpnWhere(v),
					Groups: v.Groups, Tags: v.Tags})
			}
			// one list by name, not servers first: the KIND column tells
			// servers, conns and VPNs apart
			sort.SliceStable(l.Targets, func(i, j int) bool { return l.Targets[i].Name < l.Targets[j].Name })
			l.Count = len(l.Targets)
			out.P.Print("list", l, nil)
			return nil
		},
	}
	c.Flags().StringVar(&target, "target", "", "same as the TARGET argument")
	_ = c.Flags().MarkHidden("target")
	return c
}

type targetTest struct {
	// Host names the target, like results[].host of facts, exec and the
	// other multi-target commands; use it. Name is the same value, kept
	// for scripts written before host was added (contract 1).
	Host      string     `json:"host"`
	Name      string     `json:"name"`
	Kind      string     `json:"kind"`
	OK        bool       `json:"ok"`
	LatencyMS int64      `json:"latency_ms,omitempty"`
	Detail    any        `json:"detail,omitempty"` // the host test or conn test result
	Error     *out.Error `json:"error,omitempty"`
}

type testData struct {
	Results  []targetTest `json:"results"`
	Summary  fleetSummary `json:"summary"`
	WaitedMS int64        `json:"waited_ms,omitempty"` // with --wait: how long komando tested
}

func (d testData) Text() string {
	var sb strings.Builder
	var rows [][]string
	var hints []string
	for _, r := range d.Results {
		user, sudo, note := "", "", ""
		switch det := r.Detail.(type) {
		case testResult:
			user = det.RemoteUser
			if det.SudoNoPasswd != nil {
				sudo = map[bool]string{true: "yes", false: "password"}[*det.SudoNoPasswd]
			}
		case connTestResult:
			note = det.Version
		case map[string]any:
			if c, ok := det["checked"].(string); ok {
				note = "checked through the VPN with " + c
			} else if n, ok := det["note"].(string); ok {
				note = n
			}
		}
		if r.OK {
			rows = append(rows, []string{r.Name, r.Kind, "ok", fmt.Sprintf("%dms", r.LatencyMS), user, sudo, note})
			continue
		}
		rows = append(rows, []string{r.Name, r.Kind, r.Error.Code, "", "", "", ""})
		hints = append(hints, withHost(r.Name, r.Error.Message))
		if r.Error.Hint != "" {
			hints = append(hints, "  hint: "+r.Error.Hint)
		}
	}
	sb.WriteString(textTable([]string{"NAME", "KIND", "RESULT", "LATENCY", "USER", "SUDO", "NOTE"}, rows))
	for _, h := range hints {
		sb.WriteString(h + "\n")
	}
	return sb.String()
}

// fixTestError gives errors from the connection layer the exit code and
// hint that fit `komando test`: a broken --via path or key file is a
// setting to fix (1, 4), not a usage error; an ad-hoc target has no
// inventory entry to show.
func fixTestError(st *store.State, name string, e *out.Error) *out.Error {
	c := *e
	switch c.Code {
	case "VIA_CYCLE":
		c.Exit = out.ExitError
	case "KEY_UNREADABLE":
		c.Exit = out.ExitConnect
		if st.Hosts[name] != nil {
			c.Hint = "check the key file with `komando host show " + name + "`, or pick another with `komando host edit " + name + " --key NAME`"
		}
	}
	return &c
}

// vpnTest is testVpn with an error that says the --check address was
// tried through the VPN (it is not a conn of its own).
func vpnTest(ctx context.Context, st *store.State, v *store.Vpn) targetTest {
	r := testVpn(ctx, st, v)
	if r.Error != nil && v.Check != "" && strings.Contains(r.Error.Message, v.Check) {
		e := *r.Error
		e.Message = "checking through the VPN with " + v.Check + " (its --check address): " + e.Message
		r.Error = &e
	}
	return r
}

func testCmd() *cobra.Command { return testCmdFor("") }

func testCmdFor(only string) *cobra.Command {
	var wait time.Duration
	c := &cobra.Command{
		Use:     "test TARGET",
		Aliases: []string{"ping"},
		Short:   "Check that servers, conns and VPNs answer and accept the login",
		Long: `Logs in to each server (and checks who it is and whether sudo needs a
password), connects to each conn and checks each VPN.

--wait 5m waits for new servers: komando tests again every few seconds
until every target passes or the time is up, for example right after a
cloud server was created or rebuilt. It does not wait out a changed host
key (HOSTKEY_MISMATCH), a refused login (AUTH_FAILED: retrying could get
your address banned), a VPN that needs a login, or a local key or secret
problem: those fail at once. To wait for the server's own start-up too,
run ` + "`komando exec TARGET --read-only -- cloud-init status --wait`" + ` next.`,
		Example: "  komando test @prod\n  komando test all\n  komando test @new --wait 5m   # right after creating servers",
		Args:    cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			st, err := loadState()
			if err != nil {
				return err
			}
			sel, err := resolveSelection(st, args[0])
			if err != nil {
				return err
			}
			if sel = keepOnly(sel, only); len(sel.Hosts)+len(sel.Conns)+len(sel.Vpns) == 0 {
				return out.Errf(out.ExitNotFound, "NO_MATCHING_TARGETS", "use `komando test "+args[0]+"` to test everything it picks",
					"target %q picked no %ss", args[0], only)
			}
			t0 := time.Now()
			res := testRound(cmd.Context(), st, sel)
			if wait > 0 {
				res = waitForTargets(cmd.Context(), st, sel, res, t0.Add(wait))
			}
			data := testData{Results: res}
			if wait > 0 {
				data.WaitedMS = time.Since(t0).Milliseconds()
			}
			worst := 0
			var names []string
			for _, r := range res {
				names = append(names, r.Name)
				if r.OK {
					data.Summary.OK++
					continue
				}
				data.Summary.Failed++
				data.Summary.FailedHosts = append(data.Summary.FailedHosts, r.Name)
				worst = worse(worst, r.Error.Exit)
			}
			data.Summary.Total = len(res)
			audit(st, "test", names, "", data.Summary.Failed == 0, nil)
			if data.Summary.Failed == 0 {
				out.P.Print("test", data, nil)
				return nil
			}
			soft := &out.Error{Code: "PARTIAL_FAILURE", Exit: worst,
				Message: failedOf(data.Summary.Failed, data.Summary.Total) + ": " + strings.Join(data.Summary.FailedHosts, ", "),
				Hint:    "see each result's error and hint"}
			if len(res) == 1 && res[0].Error != nil { // one target: its own error code, as exec gives
				soft.Code, soft.Message = res[0].Error.Code, res[0].Name+" failed"
			}
			out.P.Print("test", data, soft)
			return exitCode(worst)
		},
	}
	c.Flags().DurationVar(&wait, "wait", 0, "test again every few seconds until every target passes, for up to this long (5m)")
	return c
}

// testConns runs testConn on each conn in parallel, bounded by --parallel.
func testConns(ctx context.Context, st *store.State, conns []*store.Conn) []targetTest {
	res := make([]targetTest, len(conns))
	sem := make(chan struct{}, max(1, parallelism(st)))
	var wg sync.WaitGroup
	for i, c := range conns {
		wg.Add(1)
		go func(i int, c *store.Conn) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			d := testConn(ctx, st, c)
			res[i] = targetTest{Name: c.Name, Kind: c.Kind, OK: d.OK, LatencyMS: d.LatencyMS, Detail: d, Error: d.Error}
		}(i, c)
	}
	wg.Wait()
	return res
}
