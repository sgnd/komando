package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/sgnd/komando/internal/capability"
	"github.com/sgnd/komando/internal/out"
	"github.com/sgnd/komando/internal/snippet"
	"github.com/sgnd/komando/internal/sshx"
)

type pruneOpts struct {
	olderThan time.Duration
	ageText   string
	all       bool
	volumes   bool
}

// args is the docker command the real run uses.
func (o pruneOpts) args() []string {
	a := []string{"system", "prune", "-f"}
	if o.all {
		a = append(a, "-a")
	}
	if o.volumes && o.olderThan <= 0 { // with an age komando removes the volumes itself (agedVolumes)
		a = append(a, "--volumes")
	}
	if o.olderThan > 0 {
		a = append(a, "--filter", "until="+goDuration(o.olderThan))
	}
	return a
}

// agedVolumes is --volumes with --older-than: docker's prune cannot filter
// volumes by age, so komando picks them (volumeScript) and removes them.
func (o pruneOpts) agedVolumes() bool { return o.volumes && o.olderThan > 0 }

// goDuration writes a duration the way docker's until= filter reads it
// (720h, not 720h0m0s).
func goDuration(d time.Duration) string {
	if d%time.Hour == 0 {
		return strconv.FormatInt(int64(d/time.Hour), 10) + "h"
	}
	if d%time.Minute == 0 {
		return strconv.FormatInt(int64(d/time.Minute), 10) + "m"
	}
	return d.String()
}

func dockerPruneCmd(sudo *bool) *cobra.Command {
	var o pruneOpts
	c := &cobra.Command{
		Use:   "prune TARGET",
		Short: "Free disk space: stopped containers, unused images, build cache",
		Long: `Runs docker system prune on the server. It removes stopped containers,
dangling images (--all: every image no container uses), unused networks
and build cache; with --volumes also unused anonymous volumes and the data
in them.
--older-than 30d keeps everything made in the last 30 days. Docker has no
age filter for volumes, so with --volumes komando reads each unused
anonymous volume's creation time and removes only the older ones
(docker volume rm NAME), after the prune.

--dry-run changes nothing: it lists what would go, with sizes and a total,
read from docker on the server. The real run deletes and needs
--allow-dangerous; a protected server needs --yes too.`,
		Example: `  komando docker prune web1 --dry-run
  komando docker prune web1 --older-than 30d --all --dry-run
  komando docker prune web1 --older-than 30d --allow-dangerous
  komando docker prune web1 --volumes --older-than 30d --dry-run`,
		Args: cobra.ExactArgs(1),
		RunE: inCall(func(cl *call, cmd *cobra.Command, args []string) error {
			if o.ageText != "" {
				d, err := parseAge(o.ageText, "--older-than")
				if err != nil {
					return err
				}
				o.olderThan = d
			}
			pa := o.args()
			if _, err := guardDocker(cl, args[0], pa); err != nil {
				return err
			}
			line := "docker " + strings.Join(pa, " ") // fixed words and a number: nothing to quote
			if o.agedVolumes() {
				line += "; docker volume rm (each unused anonymous volume older than " + o.ageText + ")"
			}
			if cl.flags.dryRun {
				return previewPrune(cl, cmd.Context(), args[0], line, o, *sudo)
			}
			if o.agedVolumes() {
				return runPruneAged(cl, cmd.Context(), args[0], line, o, *sudo)
			}
			return runDocker(cl, cmd.Context(), "docker.prune", args[0], line, *sudo, true)
		}),
	}
	spanText(c.Flags(), &o.ageText, "older-than", "", true, "only what is older than this (like 30d, 12h)")
	c.Flags().BoolVarP(&o.all, "all", "a", false, "every image no container uses, not only dangling ones")
	c.Flags().BoolVar(&o.volumes, "volumes", false, "also unused anonymous volumes (their data is lost)")
	return c
}

// pruneItem is one thing a prune would remove.
type pruneItem struct {
	ID      string    `json:"id,omitempty"`
	Name    string    `json:"name"`
	Detail  string    `json:"detail,omitempty"` // image of a container, status
	Created time.Time `json:"created,omitzero"`
	Size    string    `json:"size,omitempty"`
	Bytes   int64     `json:"bytes"`
}

type prunePreview struct {
	Host        string      `json:"host"`
	WouldRun    string      `json:"would_run"`
	Containers  []pruneItem `json:"containers"`
	Images      []pruneItem `json:"images"`
	Volumes     []pruneItem `json:"volumes,omitzero"`      // with --volumes always there, empty when none would go
	BuildCache  string      `json:"build_cache,omitempty"` // docker builder du's reclaimable
	CacheBytes  int64       `json:"build_cache_bytes"`
	TotalBytes  int64       `json:"total_bytes"`
	Total       string      `json:"total"`
	DockerDF    []any       `json:"docker_df,omitempty"` // docker system df, for comparison
	Notes       []string    `json:"notes,omitempty"`
	OK          bool        `json:"ok"`
	Error       *out.Error  `json:"error,omitempty"`
	volumesWant bool
}

// prunePreviewResult is one host's preview as the docker-prune-preview
// snippet gives it: prunePreview's fields, in its order, without host, ok
// and error, which the snippet's answer carries itself.
type prunePreviewResult struct {
	WouldRun   string      `json:"would_run"`
	Containers []pruneItem `json:"containers"`
	Images     []pruneItem `json:"images"`
	Volumes    []pruneItem `json:"volumes,omitzero"`
	BuildCache string      `json:"build_cache,omitempty"`
	CacheBytes int64       `json:"build_cache_bytes"`
	TotalBytes int64       `json:"total_bytes"`
	Total      string      `json:"total"`
	DockerDF   []any       `json:"docker_df,omitempty"`
	Notes      []string    `json:"notes,omitempty"`
}

type prunePreviewData struct {
	DryRun         bool           `json:"dry_run"`
	Results        []prunePreview `json:"results"`
	WouldBeBlocked *out.Error     `json:"would_be_blocked,omitempty"`
}

func (d prunePreviewData) Text() string {
	var b strings.Builder
	for i, r := range d.Results {
		if i > 0 {
			b.WriteString("\n")
		}
		if r.Error != nil {
			fmt.Fprintf(&b, "%s: failed: %s\n", r.Host, r.Error.Message)
			continue
		}
		fmt.Fprintf(&b, "%s: %s would free about %s\n", r.Host, r.WouldRun, r.Total)
		section := func(title string, items []pruneItem) {
			fmt.Fprintf(&b, "  %s: %d\n", title, len(items))
			for _, it := range items {
				line := "    " + it.Name
				if it.Detail != "" {
					line += "  " + it.Detail
				}
				if !it.Created.IsZero() {
					line += "  created " + it.Created.Format("2006-01-02")
				}
				if it.Size != "" {
					line += "  " + it.Size
				}
				b.WriteString(line + "\n")
			}
		}
		section("stopped containers", r.Containers)
		section("images", r.Images)
		if r.volumesWant {
			section("volumes", r.Volumes)
		}
		cache := r.BuildCache
		if cache == "" {
			cache = "unknown"
		}
		fmt.Fprintf(&b, "  build cache: %s\n", cache)
		for _, n := range r.Notes {
			fmt.Fprintf(&b, "  note: %s\n", n)
		}
	}
	return b.String()
}

// prunePreviewScript reads, without changing anything, what a prune would
// remove. Every docker command here only lists.
func prunePreviewScript(o pruneOpts) string {
	until := ""
	if o.olderThan > 0 {
		until = " --filter until=" + goDuration(o.olderThan)
	}
	s := `v=$(docker version --format '{{.Server.APIVersion}}' 2>&1) || { rc=$?; echo "$v" >&2; exit $rc; }
echo "== api"; echo "$v"
echo "== containers"; docker container ls -a --no-trunc --size --filter status=exited --filter status=created --filter status=dead --format '{{json .}}' 2>&1
echo "== images"; docker image ls --no-trunc --format '{{json .}}' 2>&1
echo "== uses"; docker container ls -aq --no-trunc 2>/dev/null | xargs -r docker container inspect --format '{{.Id}} {{.Image}}' 2>&1
echo "== cache"; docker builder du` + until + ` 2>&1 | grep -iE '^(reclaimable|total):'
echo "== df"; docker system df --format '{{json .}}' 2>&1
`
	if o.volumes {
		s += volumeScript
	}
	return s + "true\n"
}

// volumeScript lists the unused volumes, their sizes and when each was
// made. It only reads. ("== api" comes first in the script it is part of.)
const volumeScript = `echo "== volumes"; docker volume ls --filter dangling=true --format '{{json .}}' 2>&1
echo "== volume-sizes"; docker system df -v 2>&1 | sed -n '/^VOLUME NAME/,/^$/p'
echo "== volume-created"; docker volume ls -q --filter dangling=true | xargs -r docker volume inspect --format '{{.Name}} {{.CreatedAt}}' 2>&1
`

func previewPrune(cl *call, ctx context.Context, target, line string, o pruneOpts, sudo bool) error {
	st, err := loadState()
	if err != nil {
		return err
	}
	hosts, err := resolveTargets(cl, st, target)
	if err != nil {
		return err
	}
	_ = GuardScript(cl, st, hosts, line, true) // under --dry-run a stop only lands in meta.would_be_blocked
	script := prunePreviewScript(o)
	data := prunePreviewData{DryRun: true, Results: []prunePreview{}, WouldBeBlocked: cl.out.Blocked()}
	for _, oc := range fanout(cl, ctx, st, hosts, func(ctx context.Context, c *sshx.Client) (any, error) {
		return sshx.Run(ctx, c, sshx.RunRequest{Command: script, Sudo: sudo, Timeout: cmdTimeout(cl, st), MaxOutput: max(maxOutput(cl, st), 8<<20)})
	}) {
		r := prunePreview{Host: oc.Host.Name, WouldRun: line, Containers: []pruneItem{}, Images: []pruneItem{}}
		if oc.Err != nil {
			r.Error = toErr(oc.Err)
		} else if rr := oc.Value.(*sshx.RunResult); rr.TimedOut {
			r.Error = out.Errf(out.ExitTimeout, "TIMEOUT", "raise --timeout", "reading docker's disk use timed out")
		} else if rr.ExitCode != 0 {
			r.Error = dockerErr(rr.Stderr, rr.ExitCode)
		} else {
			p := parsePrunePreview(rr.Stdout, o, time.Now())
			p.Host, p.WouldRun = r.Host, line
			r = p
		}
		data.Results = append(data.Results, r)
	}
	worst := 0
	var fails []hostFail
	for _, r := range data.Results {
		if r.Error != nil {
			worst = worse(worst, r.Error.Exit)
			fails = append(fails, hostFail{host: r.Host, reason: failReason(0, r.Error), err: r.Error})
		}
	}
	audit(cl, st, "docker.prune", hostNames(hosts), "preview: "+line, len(fails) == 0, nil)
	sum := runSummary{fleetSummary: fleetSummary{Total: len(data.Results), OK: len(data.Results) - len(fails), Failed: len(fails)}}
	return finishFleet(cl, "docker.prune", data, sum, worst, fails)
}

// dockerTime reads docker's CreatedAt ("2026-10-01 10:00:00 +0200 CEST").
func dockerTime(s string) time.Time {
	for _, layout := range []string{"2006-01-02 15:04:05 -0700 MST", "2006-01-02 15:04:05 -0700", time.RFC3339Nano} {
		if t, err := time.Parse(layout, s); err == nil {
			return t
		}
	}
	return time.Time{}
}

var sizeRe = regexp.MustCompile(`^([0-9.]+)\s*([kKMGTP]?i?B)`)

// dockerSize reads docker's sizes ("77.8MB", "1.2kB (virtual 80MB)",
// "0B"). Docker counts in powers of 1000.
func dockerSize(s string) int64 {
	m := sizeRe.FindStringSubmatch(strings.TrimSpace(s))
	if m == nil {
		return 0
	}
	f, err := strconv.ParseFloat(m[1], 64)
	if err != nil {
		return 0
	}
	unit := strings.ToUpper(m[2])
	base := 1000.0
	if strings.Contains(unit, "I") {
		base = 1024
	}
	mult := 1.0
	switch unit[0] {
	case 'K':
		mult = base
	case 'M':
		mult = base * base
	case 'G':
		mult = base * base * base
	case 'T':
		mult = base * base * base * base
	case 'P':
		mult = base * base * base * base * base
	}
	return int64(f * mult)
}

func jsonRows(s string) []map[string]any {
	var rows []map[string]any
	for _, l := range lines(s) {
		var m map[string]any
		if json.Unmarshal([]byte(l), &m) == nil {
			rows = append(rows, m)
		}
	}
	return rows
}

// parsePrunePreview turns the preview script's output into what docker
// system prune would remove: the stopped containers (older than the
// cut-off), then the images no remaining container uses (dangling ones
// only, unless --all), the anonymous unused volumes (--volumes) and the
// build cache docker says it can reclaim.
func parsePrunePreview(s string, o pruneOpts, now time.Time) prunePreview {
	m := sectionMap(s)
	p := prunePreview{OK: true, Containers: []pruneItem{}, Images: []pruneItem{}, volumesWant: o.volumes}
	old := func(t time.Time) bool {
		return o.olderThan <= 0 || (!t.IsZero() && t.Before(now.Add(-o.olderThan)))
	}
	going := map[string]bool{}
	for _, r := range jsonRows(m["containers"]) {
		created := dockerTime(str(r["CreatedAt"]))
		if !old(created) {
			continue
		}
		size, _, _ := strings.Cut(str(r["Size"]), " (")
		it := pruneItem{ID: shortID(str(r["ID"])), Name: strings.TrimPrefix(str(r["Names"]), "/"), Detail: str(r["Image"]) + ", " + str(r["Status"]),
			Created: created, Size: size, Bytes: dockerSize(size)}
		going[str(r["ID"])] = true
		p.Containers = append(p.Containers, it)
	}
	used := map[string]bool{}
	for _, l := range lines(m["uses"]) {
		if id, img, ok := strings.Cut(l, " "); ok && !going[id] {
			used[img] = true
		}
	}
	for _, r := range jsonRows(m["images"]) {
		id := str(r["ID"])
		repo, tag := str(r["Repository"]), str(r["Tag"])
		dangling := repo == "<none>" && tag == "<none>"
		created := dockerTime(str(r["CreatedAt"]))
		if used[id] || (!dangling && !o.all) || !old(created) {
			continue
		}
		name := repo + ":" + tag
		if dangling {
			name = "<none> (dangling)"
		}
		p.Images = append(p.Images, pruneItem{ID: shortID(id), Name: name, Created: created, Size: str(r["Size"]), Bytes: dockerSize(str(r["Size"]))})
	}
	if o.volumes {
		p.Volumes = []pruneItem{}
		sizes := map[string]string{}
		for _, l := range lines(m["volume-sizes"]) {
			if f := strings.Fields(l); len(f) >= 3 && f[0] != "VOLUME" {
				sizes[f[0]] = f[len(f)-1]
			}
		}
		made := map[string]time.Time{}
		for _, l := range lines(m["volume-created"]) {
			if name, at, ok := strings.Cut(l, " "); ok {
				made[name] = dockerTime(strings.TrimSpace(at))
			}
		}
		api, _ := strconv.ParseFloat(strings.TrimSpace(m["api"]), 64)
		anonOnly := api >= 1.42 // docker 23 and later keep named volumes
		for _, r := range jsonRows(m["volumes"]) {
			name := str(r["Name"])
			anon := strings.Contains(str(r["Labels"]), "com.docker.volume.anonymous")
			if anonOnly && !anon || !old(made[name]) { // an unknown age is kept
				continue
			}
			detail := "named"
			if anon {
				detail = "anonymous"
			}
			p.Volumes = append(p.Volumes, pruneItem{Name: name, Detail: detail, Created: made[name], Size: sizes[name], Bytes: dockerSize(sizes[name])})
		}
		if !anonOnly {
			p.Notes = append(p.Notes, "this docker is older than 23.0: --volumes removes named volumes too")
		}
	}
	for _, l := range lines(m["cache"]) {
		k, v, _ := strings.Cut(l, ":")
		if strings.EqualFold(strings.TrimSpace(k), "reclaimable") {
			p.BuildCache = strings.TrimSpace(v)
			p.CacheBytes = dockerSize(p.BuildCache)
		}
	}
	if p.BuildCache == "" {
		p.Notes = append(p.Notes, "the build cache size is unknown (docker builder du is not available)")
	}
	for _, r := range jsonRows(m["df"]) {
		p.DockerDF = append(p.DockerDF, r)
	}
	for _, list := range [][]pruneItem{p.Containers, p.Images, p.Volumes} {
		for _, it := range list {
			p.TotalBytes += it.Bytes
		}
	}
	p.TotalBytes += p.CacheBytes
	p.Total = decimalBytes(p.TotalBytes)
	if len(p.Images) > 1 {
		p.Notes = append(p.Notes, "image sizes count shared layers in each image, so the space freed can be less than the total")
	}
	sort.SliceStable(p.Images, func(i, j int) bool { return p.Images[i].Bytes > p.Images[j].Bytes })
	return p
}

// decimalBytes writes a size the way docker does (powers of 1000: 2.8GB).
func decimalBytes(n int64) string {
	f := float64(n)
	for _, u := range []string{"B", "kB", "MB", "GB", "TB"} {
		if f < 1000 || u == "TB" {
			if u == "B" {
				return strconv.FormatInt(n, 10) + "B"
			}
			return strconv.FormatFloat(f, 'f', 1, 64) + u
		}
		f /= 1000
	}
	return ""
}

func shortID(id string) string {
	id = strings.TrimPrefix(id, "sha256:")
	if len(id) > 12 {
		return id[:12]
	}
	return id
}

// prunedHost is one server's answer to a prune with --volumes --older-than.
type prunedHost struct {
	Host           string     `json:"host"`
	OK             bool       `json:"ok"`
	Stdout         string     `json:"stdout"`
	VolumesRemoved []string   `json:"volumes_removed"`
	Error          *out.Error `json:"error,omitempty"`
}

// runPruneAged is docker prune --volumes --older-than: docker system prune
// with the age filter, then on each server the unused anonymous volumes
// older than the cut-off, read as the dry run reads them, removed by name.
// docker volume rm refuses a volume a container took meanwhile.
func runPruneAged(cl *call, ctx context.Context, target, line string, o pruneOpts, sudo bool) error {
	st, err := loadState()
	if err != nil {
		return err
	}
	hosts, err := resolveTargets(cl, st, target)
	if err != nil {
		return err
	}
	if err := GuardScript(cl, st, hosts, line, true); err != nil {
		audit(cl, st, "docker.prune", hostNames(hosts), line, false, map[string]any{"blocked": toErr(err).Code})
		return err
	}
	run := func(ctx context.Context, c *sshx.Client, command string) (*sshx.RunResult, error) {
		rr, err := sshx.Run(ctx, c, sshx.RunRequest{Command: command, Sudo: sudo, Timeout: cmdTimeout(cl, st), MaxOutput: max(maxOutput(cl, st), 8<<20)})
		switch {
		case err != nil:
			return nil, err
		case rr.TimedOut:
			return nil, out.Errf(out.ExitTimeout, "TIMEOUT", "raise --timeout", "docker did not finish in time")
		}
		if e := dockerExit(c.Host.Name, sudo, rr); e != nil {
			return rr, e // docker volume rm names what it did remove
		}
		return rr, nil
	}
	data := struct {
		Results []prunedHost `json:"results"`
	}{Results: []prunedHost{}}
	for _, oc := range fanout(cl, ctx, st, hosts, func(ctx context.Context, c *sshx.Client) (any, error) {
		r := prunedHost{Host: c.Host.Name, VolumesRemoved: []string{}}
		rr, err := run(ctx, c, "docker "+strings.Join(o.args(), " "))
		if err != nil {
			return r, err
		}
		r.Stdout = rr.Stdout
		lr, err := run(ctx, c, "echo \"== api\"; docker version --format '{{.Server.APIVersion}}'\n"+volumeScript+"true\n")
		if err != nil {
			return r, err
		}
		var names []string
		for _, v := range parsePrunePreview(lr.Stdout, o, time.Now()).Volumes {
			names = append(names, shellQuote(v.Name))
		}
		if len(names) == 0 {
			return r, nil
		}
		rm, err := run(ctx, c, "docker volume rm "+strings.Join(names, " "))
		if rm != nil {
			r.VolumesRemoved = append(r.VolumesRemoved, lines(rm.Stdout)...)
		}
		return r, err
	}) {
		r, _ := oc.Value.(prunedHost)
		r.Host = oc.Host.Name
		if r.VolumesRemoved == nil {
			r.VolumesRemoved = []string{}
		}
		r.OK = oc.Err == nil
		if oc.Err != nil {
			r.Error = toErr(oc.Err)
		}
		data.Results = append(data.Results, r)
	}
	worst := 0
	var fails []hostFail
	var removed []string
	for _, r := range data.Results {
		removed = append(removed, r.VolumesRemoved...)
		if r.Error != nil {
			worst = worse(worst, r.Error.Exit)
			fails = append(fails, hostFail{host: r.Host, reason: failReason(0, r.Error), err: r.Error})
		}
	}
	audit(cl, st, "docker.prune", hostNames(hosts), line, len(fails) == 0, map[string]any{"volumes_removed": removed})
	sum := runSummary{fleetSummary: fleetSummary{Total: len(data.Results), OK: len(data.Results) - len(fails), Failed: len(fails)}}
	return finishFleet(cl, "docker.prune", data, sum, worst, fails)
}

// dockerPruneSnippets are the ready-made snippets of docker prune: the
// preview of the plain prune (design 2.1, rule 3.8: a preview that only
// reads is a read). They move with the host commands' package (M11).
// Written losses, decided by CLI-5: no --older-than, --all or --volumes
// preview; no would_be_blocked (the real prune keeps its own guard); the
// normal output cap, not the preview's 8 MiB.
func dockerPruneSnippets() []snippet.Builtin {
	var o pruneOpts
	line := "docker " + strings.Join(o.args(), " ")
	return []snippet.Builtin{{
		Name: "docker-prune-preview", Type: "host", Replaces: "docker prune --dry-run",
		Reader: "ContainersSheets.swift:14-100; Models/Docker.swift:235", Tier: capability.Read, Shape: "docker-prune-preview/1",
		Checks: []string{"TestParsePrunePreview", "TestDockerSize", "TestPrunePreviewEmptyVolumes", "TestSnippetDockerPrunePreview"},
		Text:   map[snippet.Family]string{snippet.Unix: prunePreviewScript(o)},
		Parse: func(res snippet.Output, _ snippet.Family) (any, error) {
			if res.ExitCode != 0 {
				return nil, dockerSnippetExit(res)
			}
			p := parsePrunePreview(res.Stdout, o, time.Now())
			return prunePreviewResult{WouldRun: line, Containers: p.Containers, Images: p.Images, Volumes: p.Volumes, BuildCache: p.BuildCache,
				CacheBytes: p.CacheBytes, TotalBytes: p.TotalBytes, Total: p.Total, DockerDF: p.DockerDF, Notes: p.Notes}, nil
		},
	}}
}
