package cli

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/sgnd/komando/internal/cloud"
	"github.com/sgnd/komando/internal/out"
)

// AWS IAM Identity Center (SSO) logins that `komando login aws`, `aws sso
// login` or an SDK saved: komando status lists them, komando logout aws
// ends one.

// awsConfigProfiles are the profile names in ~/.aws/config (or
// AWS_CONFIG_FILE), in the file's order.
func awsConfigProfiles(cl *call) []string {
	path := cl.getenv("AWS_CONFIG_FILE")
	if path == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return nil
		}
		path = filepath.Join(home, ".aws", "config")
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var ps []string
	_, order := parseINI(string(b))
	for _, s := range order {
		switch {
		case s == "default":
			ps = append(ps, "default")
		case strings.HasPrefix(s, "profile "):
			ps = append(ps, strings.TrimSpace(strings.TrimPrefix(s, "profile ")))
		}
	}
	return ps
}

// awsLogins is every SSO login of the profiles in ~/.aws/config that still
// works; tests replace it.
var awsLogins = func(cl *call) []cloud.AWSLogin {
	return cloud.AWSSSOLogins(context.Background(), awsConfigProfiles(cl))
}

// awsLoginRow is the detail of a status row for l.
func awsLoginRow(l cloud.AWSLogin, now time.Time) string {
	end := "`komando logout aws --profile " + shellQuote(l.Profiles[0]) + "` ends it"
	switch left := l.ExpiresAt.Sub(now); {
	case left > 0 && l.Renews:
		return fmt.Sprintf("SSO login, token for %s more, then renewed while the AWS session lasts (%s)", humanAge(left), end)
	case left > 0:
		return fmt.Sprintf("SSO login, kept for %s more (%s)", humanAge(left), end)
	}
	return "SSO login, renewed at the next AWS command while the AWS session lasts (" + end + ")"
}

type awsLogoutData struct {
	LoggedOut   []awsLoggedOut `json:"logged_out"`
	NotLoggedIn []string       `json:"not_logged_in,omitempty"` // profiles without a login
}

type awsLoggedOut struct {
	cloud.AWSLogin
	// Revoked: IAM Identity Center ended the token too; false when it
	// could not be reached (the login on this computer is gone either way)
	Revoked bool `json:"revoked"`
}

func (d awsLogoutData) Text() string {
	var sb strings.Builder
	for _, l := range d.LoggedOut {
		fmt.Fprintf(&sb, "logged out of AWS %s (profiles: %s)", cleanText(l.StartURL), cleanText(strings.Join(l.Profiles, ", ")))
		if !l.Revoked {
			sb.WriteString("; AWS could not be reached to end the token there, it runs out by itself")
		}
		sb.WriteString("\n")
	}
	for _, p := range d.NotLoggedIn {
		fmt.Fprintf(&sb, "profile %s: no AWS SSO login on this computer\n", cleanText(p))
	}
	return sb.String()
}

func logoutAWSCmd(cl *call) *cobra.Command {
	var profile string
	var all bool
	c := &cobra.Command{
		Use:   "aws",
		Short: "End an AWS IAM Identity Center (SSO) login",
		Long: `Ends the SSO login a profile uses, as ` + "`aws sso logout`" + ` does: AWS is told to
end the token, and the login saved in ~/.aws/sso/cache is deleted, so
komando, the AWS SDKs and the aws CLI all need ` + "`komando login aws`" + ` again.
Profiles that share the login (one sso-session) are logged out together.
--all ends every SSO login of the profiles in ~/.aws/config.`,
		Example: `  komando logout aws --profile prod
  komando logout aws --all`,
		Args: cobra.NoArgs,
		RunE: inCall(func(cl *call, cmd *cobra.Command, _ []string) error {
			profiles := []string{profile}
			switch {
			case all && cmd.Flags().Changed("profile"):
				return out.Usage("give --profile or --all, not both")
			case all:
				profiles = nil
				for _, l := range awsLogins(cl) {
					profiles = append(profiles, l.Profiles[0])
				}
			case profile == "":
				profiles = []string{"default"}
			}
			if cl.flags.dryRun {
				cl.out.Print("logout.aws", map[string]any{"would_log_out": profiles}, nil)
				return nil
			}
			d := awsLogoutData{LoggedOut: []awsLoggedOut{}}
			for _, p := range profiles {
				l, revoked, ok, err := cloud.AWSSSOLogout(cmd.Context(), p)
				switch {
				case err != nil:
					return awsErr(p, err)
				case !ok:
					d.NotLoggedIn = append(d.NotLoggedIn, p)
				default:
					d.LoggedOut = append(d.LoggedOut, awsLoggedOut{AWSLogin: l, Revoked: revoked})
				}
			}
			if len(d.LoggedOut) > 0 {
				audit(cl, nil, "logout.aws", nil, "", true, map[string]any{"profiles": profiles})
			}
			cl.out.Print("logout.aws", d, nil)
			return nil
		}),
	}
	c.Flags().StringVar(&profile, "profile", cl.getenv("AWS_PROFILE"), "profile in ~/.aws/config (default: AWS_PROFILE, else default)")
	c.Flags().BoolVar(&all, "all", false, "end every AWS SSO login")
	return c
}
