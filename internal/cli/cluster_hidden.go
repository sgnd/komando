package cli

import (
	"encoding/json"
	"strings"

	"github.com/sgnd/komando/internal/out"
)

// redact keeps the keys of a Secret and drops their values: secret values
// never reach komando's output.
func redact(o map[string]any) {
	if o["kind"] != "Secret" {
		return
	}
	for _, f := range []string{"data", "stringData"} {
		if d, ok := o[f].(map[string]any); ok {
			for k := range d {
				d[k] = "(hidden)"
			}
		}
	}
	if m, ok := o["metadata"].(map[string]any); ok {
		if a, ok := m["annotations"].(map[string]any); ok {
			delete(a, "kubectl.kubernetes.io/last-applied-configuration")
		}
	}
}

// maskObject hides from an AI agent (cl.out.Mask) what output masking
// cannot see once an object is printed whole: a Secret's values, and the
// values of env vars named like secrets (hideSecretEnv).
func maskObject(cl *call, o map[string]any) {
	if !cl.out.Mask {
		return
	}
	redact(o)
	hideSecretEnv(o)
}

// refuseHidden stops objects that still hold a value komando hid from an
// agent ([hidden] from maskObject or output masking, "(hidden)" from
// redact): sending them would write that text over the real value, the
// usual round trip being `get -o yaml`, an edit, then apply.
func refuseHidden(docs []kubeDoc) error {
	for _, d := range docs {
		var o any
		if json.Unmarshal(d.JSON, &o) == nil && holdsHidden(o) {
			return out.Errf(out.ExitUsage, "HIDDEN_VALUE",
				"leave the hidden entries out of the file (or use valueFrom.secretKeyRef), or change only what you need with `cluster run TARGET --write -- set image|patch ...`",
				"%s/%s holds a value komando hid from you ([hidden] or (hidden)); sending it would write that text over the real value", strings.ToLower(d.Kind), d.Name)
		}
	}
	return nil
}

func holdsHidden(v any) bool {
	switch x := v.(type) {
	case string:
		return out.HasHidden(x) || x == "(hidden)" || strings.HasPrefix(x, "(hidden, ")
	case map[string]any:
		for k, c := range x {
			if out.HasHidden(k) || holdsHidden(c) {
				return true
			}
		}
	case []any:
		for _, c := range x {
			if holdsHidden(c) {
				return true
			}
		}
	}
	return false
}

const lastApplied = "kubectl.kubernetes.io/last-applied-configuration"

// hideSecretEnv hides the value of every {name, value} pair whose name
// says it is a secret ({name: DB_PASSWORD, value: x} in a container's env,
// an Authorization header in a probe), also in the copy kubectl keeps in
// the last-applied-configuration annotation. Text masking sees NAME=value
// but not a name and a value in two fields. valueFrom (a reference) stays.
func hideSecretEnv(v any) {
	switch x := v.(type) {
	case map[string]any:
		if n, ok := x["name"].(string); ok {
			if val, ok := x["value"].(string); ok && val != "" && secretValue(n, val) {
				x["value"] = out.Hidden
			}
		}
		if s, ok := x[lastApplied].(string); ok {
			var cfg any
			if json.Unmarshal([]byte(s), &cfg) == nil {
				hideSecretEnv(cfg)
				if b, err := json.Marshal(cfg); err == nil {
					x[lastApplied] = string(b)
				}
			}
		}
		for _, c := range x {
			hideSecretEnv(c)
		}
	case []any:
		for _, c := range x {
			hideSecretEnv(c)
		}
	}
}

// secretValue: the NAME=value line of this pair has its value masked, so
// a {name, value} pair is hidden by exactly the same rule (true, a path or
// a placeholder stays, as in text).
func secretValue(name, val string) bool {
	line := name + "=" + val
	return out.MaskSecrets(line) != line
}
