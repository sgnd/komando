package cli

import (
	"reflect"
	"testing"

	"github.com/sgnd/komando/internal/sshx"
)

// pkgSimulateResult is the dry run of `pkg upgrade`: what would be
// upgraded, read out of the package manager's simulation.
func TestPkgSimulateResult(t *testing.T) {
	tests := []struct {
		name     string
		rr       sshx.RunResult
		want     pkgWouldUpgrade
		wantCode string
	}{
		{
			name: "apt simulation",
			rr: sshx.RunResult{
				Stderr: "# package-manager: apt\n",
				Stdout: "Inst openssl [3.0.2-0ubuntu1.10] (3.0.2-0ubuntu1.12 Ubuntu:22.04/jammy-updates [amd64])\n" +
					"Inst curl [7.81.0-1ubuntu1.14] (7.81.0-1ubuntu1.15 Ubuntu:22.04/jammy-updates [amd64])\n" +
					"Conf openssl (3.0.2-0ubuntu1.12 Ubuntu:22.04/jammy-updates [amd64])\n",
			},
			want: pkgWouldUpgrade{WouldUpgrade: []pkgUpgrade{
				{Name: "openssl", From: "3.0.2-0ubuntu1.10", Version: "3.0.2-0ubuntu1.12"},
				{Name: "curl", From: "7.81.0-1ubuntu1.14", Version: "7.81.0-1ubuntu1.15"},
			}, Count: 2},
		},
		{
			name: "apk simulation",
			rr: sshx.RunResult{
				Stderr: "# package-manager: apk\n",
				Stdout: "(1/2) Upgrading musl (1.2.4-r1 -> 1.2.4-r2)\n(2/2) Upgrading busybox (1.36.1-r5 -> 1.36.1-r6)\n",
			},
			want: pkgWouldUpgrade{WouldUpgrade: []pkgUpgrade{
				{Name: "musl", From: "1.2.4-r1", Version: "1.2.4-r2"},
				{Name: "busybox", From: "1.36.1-r5", Version: "1.36.1-r6"},
			}, Count: 2},
		},
		{
			name: "nothing to upgrade is an empty list, not null",
			rr:   sshx.RunResult{Stderr: "# package-manager: apt\n", Stdout: "0 upgraded, 0 newly installed\n"},
			want: pkgWouldUpgrade{WouldUpgrade: []pkgUpgrade{}, Count: 0},
		},
		{
			name: "an unknown package manager reads nothing",
			rr:   sshx.RunResult{Stderr: "# package-manager: unknown\n", Stdout: "Inst a [1] (2)\n"},
			want: pkgWouldUpgrade{WouldUpgrade: []pkgUpgrade{}, Count: 0},
		},
		{
			name:     "no package manager on the server",
			rr:       sshx.RunResult{ExitCode: 3, Stderr: "no supported package manager\n"},
			wantCode: "NO_PACKAGE_MANAGER",
		},
		{
			name:     "a failed run",
			rr:       sshx.RunResult{ExitCode: 100, Stderr: "E: Could not get lock\n"},
			wantCode: "PKG_FAILED",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := pkgSimulateResult(&tt.rr)
			if tt.wantCode != "" {
				if err == nil || err.Code != tt.wantCode {
					t.Fatalf("error = %v, want code %s", err, tt.wantCode)
				}
				if got != nil {
					t.Errorf("a failure returns no data, got %#v", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("pkgSimulateResult\n got  %#v\n want %#v", got, tt.want)
			}
		})
	}
}
