package cli

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"text/tabwriter"

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
	Via       string   `json:"via,omitempty"` // jump host or --via host
	Groups    []string `json:"groups,omitempty"`
	Tags      []string `json:"tags,omitempty"`
	Protected bool     `json:"protected"`
}

type targetList struct {
	Count   int         `json:"count"`
	Targets []targetRow `json:"targets"`
}

func (l targetList) Text() string {
	var sb strings.Builder
	tw := tabwriter.NewWriter(&sb, 0, 2, 2, ' ', 0)
	fmt.Fprintln(tw, "NAME\tKIND\tWHERE\tVIA\tGROUPS\tTAGS\tPROTECTED")
	for _, r := range l.Targets {
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\t%v\n", r.Name, r.Kind, r.Where, dash(r.Via),
			dash(strings.Join(r.Groups, ",")), dash(strings.Join(r.Tags, ",")), r.Protected)
	}
	tw.Flush()
	return sb.String()
}

func listCmd() *cobra.Command {
	return &cobra.Command{
		Use:     "list [TARGET]",
		Aliases: []string{"ls"},
		Short:   "List servers and conns together (everything, or what TARGET picks)",
		Example: "  komando list\n  komando list @prod\n  komando list kind:db",
		Args:    cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			st, err := loadState()
			if err != nil {
				return err
			}
			sel := selection{Hosts: st.SortedHosts(), Conns: st.SortedConns()}
			if len(args) == 1 {
				if sel, err = resolveSelection(st, args[0]); err != nil {
					return err
				}
			}
			l := targetList{Targets: []targetRow{}}
			for _, h := range sel.Hosts {
				l.Targets = append(l.Targets, targetRow{Name: h.Name, Kind: "host",
					Where: fmt.Sprintf("%s:%d", h.Address, h.EffectivePort()), Via: h.Jump,
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
			l.Count = len(l.Targets)
			out.P.Print("list", l, nil)
			return nil
		},
	}
}

type targetTest struct {
	Name      string     `json:"name"`
	Kind      string     `json:"kind"`
	OK        bool       `json:"ok"`
	LatencyMS int64      `json:"latency_ms,omitempty"`
	Detail    any        `json:"detail,omitempty"` // the host test or conn test result
	Error     *out.Error `json:"error,omitempty"`
}

type testData struct {
	Results []targetTest `json:"results"`
	Summary fleetSummary `json:"summary"`
}

func (d testData) Text() string {
	var sb strings.Builder
	tw := tabwriter.NewWriter(&sb, 0, 2, 2, ' ', 0)
	fmt.Fprintln(tw, "NAME\tKIND\tRESULT\tLATENCY")
	var hints []string
	for _, r := range d.Results {
		if r.OK {
			fmt.Fprintf(tw, "%s\t%s\tok\t%dms\n", r.Name, r.Kind, r.LatencyMS)
			continue
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t-\n", r.Name, r.Kind, r.Error.Code)
		hints = append(hints, fmt.Sprintf("%s: %s", r.Name, r.Error.Message))
		if r.Error.Hint != "" {
			hints = append(hints, "  hint: "+r.Error.Hint)
		}
	}
	tw.Flush()
	for _, h := range hints {
		sb.WriteString(h + "\n")
	}
	return sb.String()
}

func testCmd() *cobra.Command {
	return &cobra.Command{
		Use:     "test TARGET",
		Aliases: []string{"ping"},
		Short:   "Check that servers and conns can be reached and logged in to",
		Example: "  komando test @prod\n  komando test all",
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
			var res []targetTest
			for _, o := range fanout(cmd.Context(), st, sel.Hosts, testHost) {
				r := targetTest{Name: o.Host.Name, Kind: "host"}
				if o.Err != nil {
					r.Error = toErr(o.Err)
				} else {
					d := o.Value.(testResult)
					d.Host = o.Host.Name
					r.OK, r.LatencyMS, r.Detail = true, d.LatencyMS, d
				}
				res = append(res, r)
			}
			res = append(res, testConns(cmd.Context(), st, sel.Conns)...)

			data := testData{Results: res}
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
			out.P.Print("test", data, &out.Error{Code: "PARTIAL_FAILURE", Exit: worst,
				Message: fmt.Sprintf("%d of %d failed: %s", data.Summary.Failed, data.Summary.Total, strings.Join(data.Summary.FailedHosts, ", ")),
				Hint:    "see each result's error and hint"})
			return exitCode(worst)
		},
	}
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
