package cli

import (
	"reflect"
	"testing"
)

// parseJSONLines reads docker's `--format '{{json .}}'` output, one JSON
// value per line. Anything that is not JSON on every line is returned as
// the original text, never as a half-parsed list.
func TestParseJSONLines(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want any
	}{
		{
			name: "two rows",
			in:   `{"Names":"web","Image":"nginx","Status":"Up 2 hours"}` + "\n" + `{"Names":"db","Image":"postgres","Status":"Up 3 days"}` + "\n",
			want: []any{
				map[string]any{"Names": "web", "Image": "nginx", "Status": "Up 2 hours"},
				map[string]any{"Names": "db", "Image": "postgres", "Status": "Up 3 days"},
			},
		},
		{
			name: "blank lines and padding are skipped",
			in:   "\n  {\"Name\":\"a\"}  \n\n{\"Name\":\"b\"}\n\n",
			want: []any{map[string]any{"Name": "a"}, map[string]any{"Name": "b"}},
		},
		{name: "no output is an empty list", in: "", want: []any{}},
		{
			name: "one bad line returns the whole text",
			in:   "{\"Name\":\"a\"}\nWarning: no swap limit support\n",
			want: "{\"Name\":\"a\"}\nWarning: no swap limit support\n",
		},
		{name: "plain text returns the text", in: "Cannot connect to the Docker daemon\n", want: "Cannot connect to the Docker daemon\n"},
		{
			name: "stats rows keep their strings",
			in:   `{"Name":"web","CPUPerc":"0.12%","MemUsage":"20MiB / 1GiB","MemPerc":"1.95%"}` + "\n",
			want: []any{map[string]any{"Name": "web", "CPUPerc": "0.12%", "MemUsage": "20MiB / 1GiB", "MemPerc": "1.95%"}},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := parseJSONLines(nil, tt.in); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("parseJSONLines(%q)\n got  %#v\n want %#v", tt.in, got, tt.want)
			}
		})
	}
}
