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

	"github.com/sgnd/komando/internal/out"
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
	if o.volumes {
		a = append(a, "--volumes")
	}
	if o.olderThan > 0 {
		a = append(a, "--filter", "until="+goDuration(o.olderThan))
	}
	return a
}

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
--older-than 30d keeps everything made in the last 30 days.

--dry-run changes nothing: it lists what would go, with sizes and a total,
read from docker on the server. The real run deletes and needs
--allow-dangerous; a protected server needs --yes too.`,
		Example: `  komando docker prune web1 --dry-run
  komando docker prune web1 --older-than 30d --all --dry-run
  komando docker prune web1 --older-than 30d --allow-dangerous`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if o.ageText != "" {
				d, err := parseAge(o.ageText, "--older-than")
				if err != nil {
					return err
				}
				o.olderThan = d
			}
			if o.volumes && o.olderThan > 0 {
				return out.Usage("docker cannot combine --volumes with --older-than (volumes have no age filter); run them as two prunes")
			}
			pa := o.args()
			if _, err := guardDocker(pa); err != nil {
				return err
			}
			line := "docker " + strings.Join(pa, " ") // fixed words and a number: nothing to quote
			if g.dryRun {
				return previewPrune(cmd.Context(), args[0], line, o, *sudo)
			}
			return runDocker(cmd.Context(), "docker.prune", args[0], line, *sudo, true)
		},
	}
	c.Flags().StringVar(&o.ageText, "older-than", "", "only what is older than this (30d, 12h)")
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
	Volumes     []pruneItem `json:"volumes,omitempty"`
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
			fmt.Fprintf(&b, "%s: error: %s\n", r.Host, r.Error.Message)
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
		s += `echo "== volumes"; docker volume ls --filter dangling=true --format '{{json .}}' 2>&1
echo "== volume-sizes"; docker system df -v 2>&1 | sed -n '/^VOLUME NAME/,/^$/p'
`
	}
	return s + "true\n"
}

func previewPrune(ctx context.Context, target, line string, o pruneOpts, sudo bool) error {
	st, err := loadState()
	if err != nil {
		return err
	}
	hosts, err := resolveTargets(st, target)
	if err != nil {
		return err
	}
	_ = guard(st, hosts, line, true) // under --dry-run a stop only lands in meta.would_be_blocked
	script := prunePreviewScript(o)
	data := prunePreviewData{DryRun: true, Results: []prunePreview{}, WouldBeBlocked: out.P.Blocked()}
	for _, oc := range fanout(ctx, st, hosts, func(ctx context.Context, c *sshx.Client) (any, error) {
		return sshx.Run(ctx, c, sshx.RunRequest{Command: script, Sudo: sudo, Timeout: cmdTimeout(st), MaxOutput: max(maxOutput(st), 8<<20)})
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
	audit(st, "docker.prune", hostNames(hosts), "preview: "+line, len(fails) == 0, nil)
	sum := runSummary{fleetSummary: fleetSummary{Total: len(data.Results), OK: len(data.Results) - len(fails), Failed: len(fails)}}
	return finishFleet("docker.prune", data, sum, worst, fails)
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
		api, _ := strconv.ParseFloat(strings.TrimSpace(m["api"]), 64)
		anonOnly := api >= 1.42 // docker 23 and later keep named volumes
		for _, r := range jsonRows(m["volumes"]) {
			name := str(r["Name"])
			anon := strings.Contains(str(r["Labels"]), "com.docker.volume.anonymous")
			if anonOnly && !anon {
				continue
			}
			detail := "named"
			if anon {
				detail = "anonymous"
			}
			p.Volumes = append(p.Volumes, pruneItem{Name: name, Detail: detail, Size: sizes[name], Bytes: dockerSize(sizes[name])})
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
