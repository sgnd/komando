package cachex

import (
	"encoding/base64"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
)

// Text output in the style of redis-cli: numbered items, nested replies
// indented under their number, strings quoted when they hold spaces,
// quotes or control characters, so a value never breaks the layout.

// Quote shows s on one line: as it is when that is unambiguous, else in
// double quotes with \n, \t, \" and \xNN escapes.
func Quote(s string) string {
	if s != "" && !needsQuotes(s) {
		return s
	}
	var b strings.Builder
	b.WriteByte('"')
	for i := 0; i < len(s); {
		r, size := utf8.DecodeRuneInString(s[i:])
		switch {
		case r == utf8.RuneError && size <= 1:
			fmt.Fprintf(&b, `\x%02x`, s[i])
		case r == '"' || r == '\\':
			b.WriteByte('\\')
			b.WriteRune(r)
		case r == '\n':
			b.WriteString(`\n`)
		case r == '\r':
			b.WriteString(`\r`)
		case r == '\t':
			b.WriteString(`\t`)
		case !unicode.IsPrint(r) || r < 0x80 && unicode.IsControl(r):
			if r < 0x100 {
				fmt.Fprintf(&b, `\x%02x`, r)
			} else {
				fmt.Fprintf(&b, `\u%04x`, r)
			}
		default:
			b.WriteRune(r)
		}
		i += size
	}
	b.WriteByte('"')
	return b.String()
}

func needsQuotes(s string) bool {
	if !utf8.ValidString(s) {
		return true
	}
	for _, r := range s {
		if r == ' ' || r == '"' || r == '\'' || r == '\\' || !unicode.IsPrint(r) {
			return true
		}
	}
	return false
}

// valueText shows one JSON-safe value (a string, or {"base64": ...} for
// binary) quoted as needed.
func valueText(v any) string {
	switch x := v.(type) {
	case nil:
		return "(nil)"
	case string:
		return Quote(x)
	case map[string]string:
		if b64, ok := x["base64"]; ok {
			if b, err := base64.StdEncoding.DecodeString(b64); err == nil {
				return Quote(string(b))
			}
		}
	case int64:
		return "(integer) " + strconv.FormatInt(x, 10)
	case int:
		return "(integer) " + strconv.Itoa(x)
	case float64:
		return "(double) " + strconv.FormatFloat(x, 'g', -1, 64)
	case bool:
		return fmt.Sprintf("(%t)", x)
	}
	return fmt.Sprint(v)
}

// ReplyText renders a reply from Run like redis-cli does.
func ReplyText(v any) string {
	return strings.Join(replyLines(v), "\n") + "\n"
}

func replyLines(v any) []string {
	switch x := v.(type) {
	case []any:
		if len(x) == 0 {
			return []string{"(empty array)"}
		}
		items := make([][]string, len(x))
		for i, e := range x {
			items[i] = replyLines(e)
		}
		return numbered(items, ")")
	case map[string]any:
		if len(x) == 0 {
			return []string{"(empty hash)"}
		}
		keys := make([]string, 0, len(x))
		for k := range x {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		items := make([][]string, len(keys))
		for i, k := range keys {
			sub := replyLines(x[k])
			head := Quote(k) + " => "
			lines := []string{head + sub[0]}
			for _, l := range sub[1:] {
				lines = append(lines, strings.Repeat(" ", len(head))+l)
			}
			items[i] = lines
		}
		return numbered(items, "#")
	}
	return []string{valueText(v)}
}

// numbered puts "1) ", "2) " ... in front of each item; the lines of a
// nested item are indented under its first line.
func numbered(items [][]string, mark string) []string {
	w := len(strconv.Itoa(len(items)))
	var res []string
	for i, lines := range items {
		n := strconv.Itoa(i + 1)
		prefix := strings.Repeat(" ", w-len(n)) + n + mark + " "
		res = append(res, prefix+lines[0])
		for _, l := range lines[1:] {
			res = append(res, strings.Repeat(" ", len(prefix))+l)
		}
	}
	return res
}

// Text shows a key for people: what it is, when it expires, and its
// content one item per line.
func (v *Value) Text() string {
	var b strings.Builder
	fmt.Fprintf(&b, "key:   %s\n", Quote(v.Key))
	fmt.Fprintf(&b, "type:  %s\n", v.Type)
	if v.TTL == nil {
		b.WriteString("ttl:   none\n")
	} else {
		fmt.Fprintf(&b, "ttl:   %ds\n", *v.TTL)
	}
	unit := "items"
	switch v.Type {
	case "string":
		unit = "bytes"
	case "hash":
		unit = "fields"
	case "stream":
		unit = "entries"
	}
	fmt.Fprintf(&b, "size:  %d %s\n", v.Size, unit)
	var items [][]string
	switch x := v.Value.(type) {
	case nil:
		b.WriteString("value: (not shown for this type; read it with `komando cache run`)\n")
		return b.String()
	case map[string]any: // hash
		for _, k := range sortedKeys(x) {
			items = append(items, []string{Quote(k) + " => " + valueText(x[k])})
		}
	case []any: // list, set
		for _, e := range x {
			items = append(items, []string{valueText(e)})
		}
	case []map[string]any: // zset, stream
		for _, e := range x {
			if id, ok := e["id"]; ok {
				line := fmt.Sprint(id)
				if f, ok := e["fields"].(map[string]any); ok {
					for _, k := range sortedKeys(f) {
						line += "  " + Quote(k) + "=" + valueText(f[k])
					}
				}
				items = append(items, []string{line})
				continue
			}
			items = append(items, []string{valueText(e["member"]) + "  (score " + strconv.FormatFloat(toFloat(e["score"]), 'g', -1, 64) + ")"})
		}
	default: // string
		fmt.Fprintf(&b, "value: %s\n", valueText(x))
		if v.Truncated {
			b.WriteString("(value cut at the output size cap; raise --max-output)\n")
		}
		return b.String()
	}
	if len(items) == 0 {
		b.WriteString("value: (empty)\n")
		return b.String()
	}
	b.WriteString("value:\n")
	for _, l := range numbered(items, ")") {
		b.WriteString("  " + l + "\n")
	}
	if v.Truncated {
		fmt.Fprintf(&b, "(showing %d of %d; raise --limit)\n", len(items), v.Size)
	}
	return b.String()
}

func toFloat(v any) float64 {
	f, _ := v.(float64)
	return f
}

func sortedKeys(m map[string]any) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// InfoSections are the sections INFO accepts.
var InfoSections = []string{"server", "clients", "memory", "persistence", "threads", "stats", "replication", "cpu",
	"commandstats", "latencystats", "sentinel", "cluster", "modules", "keyspace", "errorstats", "keysizes",
	"all", "default", "everything"}

// Summary is the INFO reply boiled down to what people check first.
type Summary struct {
	Version        string           `json:"version"`
	Mode           string           `json:"mode,omitempty"`
	Role           string           `json:"role"`
	UptimeSeconds  int64            `json:"uptime_seconds"`
	UsedMemory     int64            `json:"used_memory_bytes"`
	MaxMemory      int64            `json:"maxmemory_bytes"` // 0 = no limit
	EvictionPolicy string           `json:"eviction_policy,omitempty"`
	Clients        int64            `json:"connected_clients"`
	Keys           map[string]int64 `json:"keys"`     // per database: db0 -> count
	Expires        map[string]int64 `json:"expires"`  // keys with a time to live, per database
	Hits           int64            `json:"hits"`     // keyspace hits since start
	Misses         int64            `json:"misses"`   // keyspace misses since start
	HitRate        *float64         `json:"hit_rate"` // hits / (hits + misses); null before any read
}

// Summarize picks the summary out of parsed INFO sections.
func Summarize(info map[string]map[string]string) Summary {
	get := func(section, key string) string { return info[section][key] }
	n := func(section, key string) int64 {
		v, _ := strconv.ParseInt(get(section, key), 10, 64)
		return v
	}
	s := Summary{
		Version: get("server", "redis_version"), Mode: get("server", "redis_mode"), Role: get("replication", "role"),
		UptimeSeconds: n("server", "uptime_in_seconds"), UsedMemory: n("memory", "used_memory"), MaxMemory: n("memory", "maxmemory"),
		EvictionPolicy: get("memory", "maxmemory_policy"), Clients: n("clients", "connected_clients"),
		Keys: map[string]int64{}, Expires: map[string]int64{}, Hits: n("stats", "keyspace_hits"), Misses: n("stats", "keyspace_misses"),
	}
	if v := get("server", "valkey_version"); v != "" {
		s.Version = v + " (valkey)"
	}
	for db, line := range info["keyspace"] { // db0:keys=12,expires=3,avg_ttl=0
		for _, kv := range strings.Split(line, ",") {
			k, v, _ := strings.Cut(kv, "=")
			c, _ := strconv.ParseInt(v, 10, 64)
			switch k {
			case "keys":
				s.Keys[db] = c
			case "expires":
				s.Expires[db] = c
			}
		}
	}
	if s.Hits+s.Misses > 0 {
		r := float64(s.Hits) / float64(s.Hits+s.Misses)
		s.HitRate = &r
	}
	return s
}
