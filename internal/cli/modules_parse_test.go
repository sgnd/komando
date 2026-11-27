package cli

import (
	"reflect"
	"testing"
)

// parseSvcShow reads `systemctl show` blocks (one per unit, a blank line
// between them) into one map per unit.
func TestParseSvcShow(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want []map[string]any
	}{
		{
			name: "one running unit",
			in: "Id=nginx.service\nDescription=A high performance web server\nLoadState=loaded\nActiveState=active\n" +
				"SubState=running\nUnitFileState=enabled\nMainPID=812\nActiveEnterTimestamp=Mon 2026-11-02 08:00:01 UTC\n" +
				"NRestarts=2\nMemoryCurrent=52428800\nResult=success\nExecMainStatus=0\n",
			want: []map[string]any{{
				"id": "nginx.service", "description": "A high performance web server", "load_state": "loaded",
				"active_state": "active", "sub_state": "running", "unit_file_state": "enabled", "main_pid": int64(812),
				"active_enter_timestamp": "Mon 2026-11-02 08:00:01 UTC", "nrestarts": int64(2),
				"memory_current": int64(52428800), "result": "success", "exec_main_status": int64(0), "healthy": true,
			}},
		},
		{
			name: "two units, the second failed",
			in:   "Id=a.service\nActiveState=active\n\nId=b.service\nActiveState=failed\n",
			want: []map[string]any{
				{"id": "a.service", "active_state": "active", "healthy": true},
				{"id": "b.service", "active_state": "failed", "healthy": false},
			},
		},
		{
			name: "an Id that is all digits stays text",
			in:   "Id=12345\nActiveState=active\n",
			want: []map[string]any{{"id": "12345", "active_state": "active", "healthy": true}},
		},
		{
			name: "not set and empty values are left out",
			in:   "Id=x.service\nMemoryCurrent=[not set]\nDescription=\nActiveState=inactive\n",
			want: []map[string]any{{"id": "x.service", "active_state": "inactive", "healthy": false}},
		},
		{
			name: "a unit that is not found",
			in:   "Id=nope.service\nLoadState=not-found\nActiveState=inactive\n",
			want: []map[string]any{{"id": "nope.service", "load_state": "not-found", "active_state": "inactive", "healthy": false}},
		},
		{
			name: "a value may hold an equals sign",
			in:   "Id=a.service\nDescription=key=value thing\nActiveState=active\n",
			want: []map[string]any{{"id": "a.service", "description": "key=value thing", "active_state": "active", "healthy": true}},
		},
		{
			name: "a line without an equals sign is skipped",
			in:   "Id=a.service\nstray line\nActiveState=active\n",
			want: []map[string]any{{"id": "a.service", "active_state": "active", "healthy": true}},
		},
		{name: "empty output", in: "", want: nil},
		{name: "only blank lines", in: "\n\n\n", want: nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, _ := parseSvcShow(nil, tt.in).([]map[string]any)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("parseSvcShow(%q)\n got  %#v\n want %#v", tt.in, got, tt.want)
			}
		})
	}
}

func TestSnake(t *testing.T) {
	for in, want := range map[string]string{
		"Id":                   "id",
		"LoadState":            "load_state",
		"NRestarts":            "nrestarts", // pinned as it is today: consecutive capitals get no underscore (modules_svc.go:58 reads n_restarts, so the text table shows no restarts)
		"MainPID":              "main_pid",
		"ActiveEnterTimestamp": "active_enter_timestamp",
		"ExecMainStatus":       "exec_main_status",
		"":                     "",
	} {
		if got := snake(in); got != want {
			t.Errorf("snake(%q) = %q, want %q", in, got, want)
		}
	}
}
