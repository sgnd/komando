package cli

import (
	"reflect"
	"testing"

	"github.com/sgnd/komando/internal/sshx"
)

// winServices reads the services from the `#komando:json=` marker. A name
// that was not found fails the host with UNIT_NOT_FOUND, and the services
// that were read still come back.
func TestWinServices(t *testing.T) {
	const two = `#komando:json=[{"name":"Spooler","display_name":"Print Spooler","state":"Running","start_mode":"Auto","delayed_start":true,"pid":1234,"account":"LocalSystem","found":true},` +
		`{"name":"W32Time","display_name":"Windows Time","state":"Stopped","start_mode":"Manual","found":true}]` + "\n"
	tests := []struct {
		name     string
		rr       sshx.RunResult
		want     []winService
		wantCode string
		wantMsg  string
	}{
		{
			name: "two services",
			rr:   sshx.RunResult{Stdout: "#komando:rc=0\n" + two},
			want: []winService{
				{Name: "Spooler", DisplayName: "Print Spooler", State: "Running", StartMode: "Auto", Delayed: true, PID: 1234, Account: "LocalSystem", Found: true},
				{Name: "W32Time", DisplayName: "Windows Time", State: "Stopped", StartMode: "Manual", Found: true},
			},
		},
		{
			name: "carriage returns around the marker line are tolerated",
			rr:   sshx.RunResult{Stdout: "#komando:json=[{\"name\":\"a\",\"found\":true}]\r\n"},
			want: []winService{{Name: "a", Found: true}},
		},
		{
			name:     "a missing service",
			rr:       sshx.RunResult{Stdout: `#komando:json=[{"name":"Spooler","found":true},{"name":"Nope","found":false},{"name":"Nada","found":false}]` + "\n"},
			want:     []winService{{Name: "Spooler", Found: true}, {Name: "Nope"}, {Name: "Nada"}},
			wantCode: "UNIT_NOT_FOUND",
			wantMsg:  "service not found: Nope, Nada",
		},
		{
			name:     "no json marker",
			rr:       sshx.RunResult{ExitCode: 1, Stdout: "#komando:rc=1\n"},
			wantCode: "COMMAND_FAILED",
			wantMsg:  "PowerShell gave no service list (exit code 1)",
		},
		{
			name:     "json that does not parse",
			rr:       sshx.RunResult{ExitCode: 0, Stdout: "#komando:json={not json\n"},
			wantCode: "COMMAND_FAILED",
			wantMsg:  "PowerShell gave no service list (exit code 0)",
		},
		{
			name:     "an empty json marker",
			rr:       sshx.RunResult{Stdout: "#komando:json=\n"},
			wantCode: "COMMAND_FAILED",
			wantMsg:  "PowerShell gave no service list (exit code 0)",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := winServices(&tt.rr)
			if tt.wantCode == "" {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
			} else if err == nil || err.Code != tt.wantCode || err.Message != tt.wantMsg {
				t.Fatalf("error = %+v, want %s %q", err, tt.wantCode, tt.wantMsg)
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("winServices\n got  %#v\n want %#v", got, tt.want)
			}
		})
	}
}
