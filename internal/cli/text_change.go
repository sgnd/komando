package cli

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/sgnd/komando/internal/out"
)

// Every change command has its own text (S-9.7); the generic renderer
// is a fallback. changeText is the text of a change to one record (host
// add, conn edit, key gen): what happened first, in words, then each field
// as words ("password ref: secret:web1-pass", not password_ref), warnings
// last. The command to run next is data.next and the Next: line.
func changeText(data any) string {
	b, err := json.Marshal(data)
	if err != nil {
		return fmt.Sprint(data)
	}
	var m map[string]any
	if json.Unmarshal(b, &m) != nil {
		return string(b)
	}
	var sb strings.Builder
	if h := out.Headline(m, g.dryRun); h != "" {
		sb.WriteString(h + "\n")
	}
	warnings, _ := m["warnings"].([]any)
	keys := make([]string, 0, len(m))
	for k := range m {
		switch k {
		case "action", "changed", "name", "created_at", "updated_at", "next", "warnings":
			continue
		}
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		if v := fieldWords(m[k]); v != "" {
			fmt.Fprintf(&sb, "  %s: %s\n", strings.ReplaceAll(k, "_", " "), v)
		}
	}
	for _, w := range warnings {
		fmt.Fprintf(&sb, "warning: %v\n", w)
	}
	return sb.String()
}

// fieldWords is a field's value in a line of text; "" for nothing worth
// a line (false, empty).
func fieldWords(v any) string {
	switch v := v.(type) {
	case nil:
		return ""
	case bool:
		return map[bool]string{true: "yes"}[v]
	case string:
		return v
	case []any:
		parts := make([]string, 0, len(v))
		for _, e := range v {
			if s := fieldWords(e); s != "" {
				parts = append(parts, s)
			}
		}
		return strings.Join(parts, ", ")
	case map[string]any:
		keys := make([]string, 0, len(v))
		for k := range v {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		parts := make([]string, 0, len(v))
		for _, k := range keys {
			parts = append(parts, k+"="+fieldWords(v[k]))
		}
		return strings.Join(parts, ", ")
	}
	return fmt.Sprint(v)
}

// textFn is a Text method made of a function, for textAs.
type textFn func() string

func (f textFn) Text() string { return f() }

func (r hostResult) Text() string { return changeText(r) }
func (r connResult) Text() string { return changeText(r) }
func (r keyResult) Text() string  { return changeText(r) }
