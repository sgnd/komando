package cli

import (
	"cmp"
	"context"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"slices"
	"strings"

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
			if i := slices.IndexFunc(loginClouds, func(c string) bool { return strings.EqualFold(c, args[0]) }); i >= 0 {
				// no server can have that name (checkHostName): it is the cloud login
				return out.Usage("cloud logins are lower case: komando login %s", loginClouds[i]).WithHint("komando login " + loginClouds[i])
			}
			err := loginHost(cmd.Context(), args[0])
			if e := toErr(err); e != nil && e.Code == "HOST_NOT_FOUND" {
				if c := closest(args[0], loginClouds[:1]); c != "" { // only aws is built
					e.Hint += " For the AWS login: komando login " + c
				}
				return e
			}
			return err
		},
	}
	// a new subcommand goes into loginClouds too, so no server takes its name
	c.AddCommand(loginAWSCmd(),
		loginNotBuiltCmd("gcp", "Google Cloud", "for now komando uses your Google application default credentials (GOOGLE_APPLICATION_CREDENTIALS, or the file gcloud saved), "+
			"or a service account key: `komando secret set gcs-key`, then `komando conn add NAME gs://BUCKET --password-ref secret:gcs-key`"),
		loginNotBuiltCmd("azure", "Azure", "for now komando uses a service principal (AZURE_TENANT_ID, AZURE_CLIENT_ID, AZURE_CLIENT_SECRET), a token the Azure CLI saved, "+
			"or a storage account key: `komando secret set blob-key`, then `komando conn add NAME azblob://ACCOUNT@CONTAINER --password-ref secret:blob-key`"))
	return c
}

// loginNotBuiltCmd answers `komando login gcp|azure` with what to do today
// instead of "no server named gcp". The browser login comes once komando
// has its own sign-in app with Google and Microsoft: it never borrows the
// gcloud or az one (docs/features/cloud.md).
func loginNotBuiltCmd(name, cloud, today string) *cobra.Command {
	return &cobra.Command{
		Use:    name,
		Short:  cloud + " login is coming in a later release",
		Hidden: true,
		Args:   cobra.ArbitraryArgs,
		RunE: func(*cobra.Command, []string) error {
			return out.Errf(out.ExitUsage, "USAGE", today, "komando login %s is not built yet: the %s browser login comes in a later release", name, cloud)
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
profile is the one in ~/.aws/config with sso_start_url or sso_session, or a
profile that assumes a role from one (source_profile).

Conns that name the profile (--option aws_profile=NAME) use the login until
it runs out; then their commands stop with AWS_LOGIN_REQUIRED and the same
command renews it. Logging in is for a person: an AI agent gets
NEEDS_PERSON and asks you to run it. A profile with keys in
~/.aws/credentials needs no login.`,
		Example: `  komando login aws --profile prod       # opens the browser; confirm the code shown
  komando login aws                      # the profile in AWS_PROFILE, else default
  komando login aws --profile prod --dry-run   # which sign-in page, without logging in`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			profile := cmp.Or(profile, "default")
			again := "komando login aws --profile " + shellQuote(profile)
			// the sign-in is in the person's browser, never the agent's
			var stop *out.Error
			switch {
			case interactive():
			case isAgent():
				stop = out.Errf(out.ExitPolicy, "NEEDS_PERSON",
					"ask the user to run `"+again+"` in their own terminal; their browser opens for the AWS sign-in, then your commands use the login",
					"logging in to AWS needs a person at a terminal and a browser")
			default:
				stop = out.Errf(out.ExitUsage, "NEEDS_TERMINAL", "a person runs `"+again+"` in a terminal",
					"logging in to AWS needs a person at a terminal and a browser")
			}
			if stop != nil && !g.dryRun {
				return stop
			}
			sso, err := cloud.AWSProfileSSO(cmd.Context(), profile)
			if err != nil {
				return awsErr(profile, err)
			}
			if g.dryRun { // a dry run is never blocked; it says what the real run needs
				if stop != nil {
					out.P.WouldBlock(stop)
				}
				out.P.Print("login.aws", map[string]any{"profile": profile, "sso_start_url": sso.StartURL, "sso_region": sso.Region, "dry_run": true}, nil)
				return nil
			}
			path, err := cloud.AWSSSOLogin(cmd.Context(), profile, func(url, code string) {
				fmt.Fprintf(os.Stderr, "komando: confirm the code %s at %s\n", cleanText(code), cleanText(url))
				openBrowser(cmd.Context(), url)
			})
			if err != nil {
				return awsErr(profile, err)
			}
			audit(nil, "login.aws", nil, "", true, map[string]any{"profile": profile})
			out.P.Print("login.aws", map[string]any{"profile": profile, "sso_start_url": sso.StartURL, "saved": path}, nil)
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
	if !strings.HasPrefix(url, "https://") { // only a web page, never a file or an app
		return
	}
	if _, err := exec.LookPath(name); err == nil {
		_ = exec.CommandContext(ctx, name, url).Start()
	}
}
