package cli

import (
	"cmp"
	"context"
	"fmt"
	"os"
	"os/exec"
	"runtime"

	"github.com/spf13/cobra"

	"github.com/sgnd/komando/internal/cloud"
	"github.com/sgnd/komando/internal/out"
)

// komando login HOST keeps a person's server login (login_ssh.go);
// komando login aws renews a person's cloud login without the vendor's
// CLI. Both are for a person: they answer the login at the terminal or in
// their browser.

func loginCmd() *cobra.Command {
	c := &cobra.Command{
		Use:   "login [HOST]",
		Short: "Log in to a server once and keep it, or to a cloud account",
		Long: `Type the password and code once; for 8 hours your commands and your AI
agent reuse that login. The safety rules, approvals and history of each
command stay the same.

` + "`komando logout HOST`" + ` ends it sooner, and ` + "`komando status`" + ` lists the kept logins.
A login to a jump host covers every server behind it. The 8 hours come from
the login_for setting.

komando login aws logs in to AWS IAM Identity Center (SSO).`,
		Example: `  komando login web1      # answer the code once; AI agents can then use web1
  komando logout web1
  komando login aws --profile prod`,
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) == 0 {
				if out.P.Format == "json" {
					// piped: one JSON envelope, never help text (ux.md, section 4)
					return out.Usage("komando login needs a server or a cloud account").WithHint("komando login HOST, or komando login aws")
				}
				return cmd.Help()
			}
			return loginHost(cmd.Context(), args[0])
		},
	}
	c.AddCommand(loginAWSCmd(), loginNotBuiltCmd("gcp", "Google Cloud"), loginNotBuiltCmd("azure", "Azure"))
	return c
}

// loginNotBuiltCmd answers `komando login gcp|azure` with what to do today
// instead of "no server named gcp".
func loginNotBuiltCmd(name, cloud string) *cobra.Command {
	return &cobra.Command{
		Use:    name,
		Short:  cloud + " login is not built yet",
		Hidden: true,
		Args:   cobra.NoArgs,
		RunE: func(*cobra.Command, []string) error {
			return out.Errf(out.ExitUsage, "USAGE", "for now, save a service account key: komando secret set "+name+"-key",
				"%s login is not built yet", cloud)
		},
	}
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
				return out.Errf(out.ExitUsage, "NEEDS_TERMINAL", "ask a person to run `komando login aws --profile "+cmp.Or(profile, "default")+"`",
					"logging in needs a person at a terminal and a browser")
			}
			if g.dryRun {
				out.P.Print("login.aws", map[string]any{"profile": cmp.Or(profile, "default"), "dry_run": true}, nil)
				return nil
			}
			path, err := cloud.AWSSSOLogin(cmd.Context(), profile, func(url, code string) {
				fmt.Fprintf(os.Stderr, "komando: confirm the code %s at %s\n", cleanText(code), cleanText(url))
				openBrowser(cmd.Context(), url)
			})
			if err != nil {
				return awsErr(profile, err)
			}
			audit(nil, "login.aws", nil, "", true, map[string]any{"profile": cmp.Or(profile, "default")})
			out.P.Print("login.aws", map[string]any{"profile": cmp.Or(profile, "default"), "saved": path}, nil)
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
