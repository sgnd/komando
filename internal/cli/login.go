package cli

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"runtime"

	"github.com/spf13/cobra"

	"github.com/sgnd/komando/internal/cloud"
	"github.com/sgnd/komando/internal/out"
)

// komando login renews a person's cloud login without the vendor's CLI.
// It is for a person: they confirm the login in their browser.

func loginCmd() *cobra.Command {
	c := &cobra.Command{
		Use:   "login",
		Short: "Log in to a cloud account (for people): AWS IAM Identity Center (SSO)",
	}
	c.AddCommand(loginAWSCmd())
	return c
}

func loginAWSCmd() *cobra.Command {
	var profile string
	c := &cobra.Command{
		Use:   "aws",
		Short: "Log in to AWS IAM Identity Center (SSO) for a profile, like `aws sso login`",
		Long: `Opens the AWS sign-in page in your browser and waits until you confirm the
code shown here. The login is saved where the aws CLI keeps it
(~/.aws/sso/cache), so komando, the AWS SDKs and the aws CLI all use it. The
profile is the one in ~/.aws/config with sso_start_url or sso_session.`,
		Example: `  komando login aws --profile prod`,
		Args:    cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if !interactive() {
				return out.Errf(out.ExitUsage, "NEEDS_TERMINAL", "ask a person to run `komando login aws --profile "+firstNonEmpty(profile, "default")+"`",
					"logging in needs a person at a terminal and a browser")
			}
			if g.dryRun {
				out.P.Print("login.aws", map[string]any{"profile": firstNonEmpty(profile, "default"), "dry_run": true}, nil)
				return nil
			}
			path, err := cloud.AWSSSOLogin(cmd.Context(), profile, func(url, code string) {
				fmt.Fprintf(os.Stderr, "komando: confirm the code %s at %s\n", cleanText(code), cleanText(url))
				openBrowser(cmd.Context(), url)
			})
			if err != nil {
				return awsErr(profile, err)
			}
			audit(nil, "login.aws", nil, "", true, map[string]any{"profile": firstNonEmpty(profile, "default")})
			out.P.Print("login.aws", map[string]any{"profile": firstNonEmpty(profile, "default"), "saved": path}, nil)
			return nil
		},
	}
	c.Flags().StringVar(&profile, "profile", os.Getenv("AWS_PROFILE"), "profile in ~/.aws/config (default: AWS_PROFILE, else default)")
	return c
}

// openBrowser opens url with the operating system's own opener. When there
// is none (a server), the person opens the printed address themselves.
func openBrowser(ctx context.Context, url string) {
	name := "xdg-open"
	if runtime.GOOS == "darwin" {
		name = "open"
	}
	if _, err := exec.LookPath(name); err == nil {
		_ = exec.CommandContext(ctx, name, url).Start()
	}
}
