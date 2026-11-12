package cli

import (
	"cmp"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/sgnd/komando/internal/kube"
)

// explain reads the cluster's OpenAPI v3 schema, as kubectl explain does:
// explain TYPE[.FIELD.PATH] [--recursive].
func (r *kctlRun) explain() error {
	if len(r.a.pos) == 0 {
		return kfail("you must specify the type of resource to explain")
	}
	typ, fieldPath, _ := strings.Cut(r.a.pos[0], ".")
	rt, err := r.k.Resource(r.ctx, typ)
	if err != nil {
		// TYPE.GROUP spellings: deployments.apps.spec is ambiguous, try
		// the first two parts as the type
		return kindErr(err, "the server doesn't have a resource type %q", typ)
	}
	var index struct {
		Paths map[string]struct {
			ServerRelativeURL string `json:"serverRelativeURL"`
		} `json:"paths"`
	}
	if err := r.k.Get(r.ctx, "/openapi/v3", nil, &index); err != nil {
		return err
	}
	gvPath := strings.TrimPrefix(rt.Path, "/")
	p, ok := index.Paths[gvPath]
	if !ok {
		return kfail("the server has no OpenAPI schema for %s", rt.APIVersion())
	}
	u := p.ServerRelativeURL
	path, query, _ := strings.Cut(u, "?")
	q := map[string][]string{}
	for _, kv := range strings.Split(query, "&") {
		if k, v, ok := strings.Cut(kv, "="); ok {
			q[k] = append(q[k], v)
		}
	}
	var doc struct {
		Components struct {
			Schemas map[string]map[string]any `json:"schemas"`
		} `json:"components"`
	}
	b, err := r.k.Do(r.ctx, "GET", path, q, nil, "")
	if err != nil {
		return err
	}
	if err := json.Unmarshal(b, &doc); err != nil {
		return err
	}
	schemas := doc.Components.Schemas
	var schema map[string]any
	for _, s := range schemas {
		gvks, _ := s["x-kubernetes-group-version-kind"].([]any)
		for _, x := range gvks {
			m, _ := x.(map[string]any)
			if str(m["kind"]) == rt.Kind && str(m["group"]) == rt.Group() && str(m["version"]) == rt.Version() {
				schema = s
			}
		}
	}
	if schema == nil {
		return kfail("no schema for %s", rt.Kind)
	}
	resolve := func(s map[string]any) map[string]any {
		for i := 0; i < 5 && s != nil; i++ {
			ref := str(s["$ref"])
			if ref == "" {
				if all, ok := s["allOf"].([]any); ok && len(all) == 1 {
					s, _ = all[0].(map[string]any)
					continue
				}
				return s
			}
			s = schemas[strings.TrimPrefix(ref, "#/components/schemas/")]
		}
		return s
	}
	schema = resolve(schema)
	fieldName := ""
	if fieldPath != "" {
		for _, f := range strings.Split(fieldPath, ".") {
			props, _ := schema["properties"].(map[string]any)
			next, ok := props[f].(map[string]any)
			if !ok {
				return kfail("field %q does not exist", f)
			}
			schema, fieldName = resolveItems(resolve(next), resolve), f
		}
	}
	fmt.Fprintf(&r.stdout, "GROUP:      %s\nKIND:       %s\nVERSION:    %s\n\n", rt.Group(), rt.Kind, rt.Version())
	if fieldName != "" {
		fmt.Fprintf(&r.stdout, "FIELD: %s <%s>\n\n", fieldName, schemaType(schema))
	}
	fmt.Fprintf(&r.stdout, "DESCRIPTION:\n%s\n", indentText(cmp.Or(str(schema["description"]), "<empty>"), "    "))
	props, _ := schema["properties"].(map[string]any)
	if len(props) > 0 {
		r.stdout.WriteString("\nFIELDS:\n")
		required := map[string]bool{}
		if req, ok := schema["required"].([]any); ok {
			for _, x := range req {
				required[str(x)] = true
			}
		}
		r.fields(props, resolve, "  ", r.a.bools["recursive"], required, 0)
	}
	return nil
}

func (r *kctlRun) fields(props map[string]any, resolve func(map[string]any) map[string]any, indent string, recursive bool, required map[string]bool, depth int) {
	var names []string
	for n := range props {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		s := resolveItems(resolve(props[n].(map[string]any)), resolve)
		req := ""
		if required[n] {
			req = " -required-"
		}
		fmt.Fprintf(&r.stdout, "%s%s\t<%s>%s\n", indent, n, schemaType(s), req)
		if recursive && depth < 12 {
			if sub, ok := s["properties"].(map[string]any); ok {
				r.fields(sub, resolve, indent+"  ", true, map[string]bool{}, depth+1)
			}
			continue
		}
		if d := str(s["description"]); d != "" && !recursive {
			line := strings.SplitN(d, "\n", 2)[0]
			fmt.Fprintf(&r.stdout, "%s  %s\n\n", indent, line)
		}
	}
}

// resolveItems steps into an array's items schema (FIELDS lists those).
func resolveItems(s map[string]any, resolve func(map[string]any) map[string]any) map[string]any {
	if str(s["type"]) == "array" {
		if it, ok := s["items"].(map[string]any); ok {
			inner := resolve(it)
			out := map[string]any{}
			for k, v := range inner {
				out[k] = v
			}
			out["type"] = "[]" + schemaType(inner)
			if d := str(s["description"]); d != "" {
				out["description"] = d
			}
			return out
		}
	}
	return s
}

func schemaType(s map[string]any) string {
	t := str(s["type"])
	switch {
	case strings.HasPrefix(t, "[]"):
		return t
	case t == "object" && s["properties"] == nil && s["additionalProperties"] != nil:
		return "map[string]" + cmp.Or(schemaType(asMap(s["additionalProperties"])), "string")
	case t == "object" || (t == "" && s["properties"] != nil):
		return "Object"
	case t == "integer":
		return "integer"
	case t == "":
		if s["x-kubernetes-int-or-string"] == true {
			return "IntOrString"
		}
		return "Object"
	}
	return t
}

func asMap(v any) map[string]any {
	m, _ := v.(map[string]any)
	return m
}

var _ = kube.Table{}
