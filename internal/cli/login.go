package cli

import (
	"cmp"
	"context"
	"fmt"
	"os/exec"
	"runtime"
	"strings"

	"github.com/spf13/cobra"

	"github.com/sgnd/komando/internal/cli/kit/term"
	"github.com/sgnd/komando/internal/cloud"
	"github.com/sgnd/komando/internal/out"
	"github.com/sgnd/komando/internal/store"
)

// komando login aws renews a person's cloud login without the vendor's
// CLI. It is for a person: they answer the login in their browser. A
// person's server login is `komando test TARGET` (test_wait.go).

func loginCmd(cl *call) *cobra.Command {
	c := &cobra.Command{
		Use:   "login",
		Short: "Log in to a cloud account",
		Long: `komando login aws logs in to AWS IAM Identity Center (SSO).

A server's login is kept by ` + "`komando test TARGET`" + `, and ` + "`komando test --end`" + ` ends it.`,
		Example: `  komando login aws --profile prod       # opens the browser; confirm the code shown
  komando login aws                      # the profile in AWS_PROFILE, else default
  komando login aws --profile prod --dry-run   # which sign-in page, without logging in`,
	}
	// a new subcommand goes into loginClouds too, so no server takes its name
	c.AddCommand(loginAWSCmd(cl),
		loginNotBuiltCmd("gcp", "Google Cloud", "for now komando uses your Google application default credentials (GOOGLE_APPLICATION_CREDENTIALS, or the file gcloud saved), "+
			"or a service account key: `komando credential password add gcs-key`, then `komando conn add NAME gs://BUCKET --password-ref credential:gcs-key`"),
		loginNotBuiltCmd("azure", "Azure", "for now an Azure blob conn takes the storage account key or a SAS token: `komando credential token add blob-key`, then "+
			"`komando conn add NAME azblob://ACCOUNT@CONTAINER --password-ref credential:blob-key`; Key Vault secrets use AZURE_TENANT_ID, AZURE_CLIENT_ID and AZURE_CLIENT_SECRET, a token the Azure CLI saved, or the machine's managed identity"))
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
		RunE: inCall(func(cl *call, cmd *cobra.Command, _ []string) error {
			noteCloudNamed(cl, name)
			return out.Errf(out.ExitUsage, "USAGE", today, "komando login %s is not built yet: the %s browser login comes in a later release", name, cloud)
		}),
	}
}

func loginAWSCmd(cl *call) *cobra.Command {
	var profile string
	c := &cobra.Command{
		Use:   "aws",
		Short: "Log in to AWS IAM Identity Center for a profile",
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
		RunE: inCall(func(cl *call, cmd *cobra.Command, _ []string) error {
			profile := cmp.Or(profile, "default")
			noteCloudNamed(cl, "aws")
			again := "komando login aws --profile " + shellQuote(profile)
			// the sign-in is in the person's browser, never the agent's
			var stop *out.Error
			switch {
			case cl.interactive():
			case cl.isAgent():
				stop = out.Errf(out.ExitPolicy, "NEEDS_PERSON",
					"ask the user to run `"+again+"` in their own terminal; their browser opens for the AWS sign-in, then your commands use the login",
					"logging in to AWS needs a person at a terminal and a browser")
			default:
				stop = out.Errf(out.ExitPolicy, "NEEDS_PERSON", "a person runs `"+again+"` in a terminal",
					"logging in to AWS needs a person at a terminal and a browser")
			}
			if stop != nil && !cl.dryRun() {
				return stop
			}
			sso, err := cloud.AWSProfileSSO(cmd.Context(), profile)
			if err != nil {
				return awsErr(profile, err)
			}
			if cl.dryRun() { // a dry run is never blocked; it says what the real run needs
				if stop != nil {
					cl.out.WouldBlock(stop)
				}
				cl.out.Print("login.aws", map[string]any{"profile": profile, "sso_start_url": sso.StartURL, "sso_region": sso.Region, "dry_run": true}, nil)
				return nil
			}
			path, err := cloud.AWSSSOLogin(cmd.Context(), profile, func(url, code string) {
				fmt.Fprintf(cl.out.Err, "komando: confirm the code %s at %s\n", term.CleanText(code), term.CleanText(url))
				openBrowser(cmd.Context(), url)
			})
			if err != nil {
				return awsErr(profile, err)
			}
			audit(cl, nil, "login.aws", nil, "", true, map[string]any{"profile": profile})
			cl.out.Print("login.aws", map[string]any{"profile": profile, "sso_start_url": sso.StartURL, "saved": path}, nil)
			return nil
		}),
	}
	c.Flags().StringVar(&profile, "profile", cl.getenv("AWS_PROFILE"), "profile in ~/.aws/config (default: AWS_PROFILE, else default)")
	return c
}

// openBrowser opens url with the operating system's own opener. When there
// is none (a server), the person opens the printed address themselves.
func openBrowser(ctx context.Context, url string) {
	if !strings.HasPrefix(url, "https://") { // only a web page, never a file or an app
		return
	}
	argv := browserOpener(runtime.GOOS, url)
	if _, err := exec.LookPath(argv[0]); err == nil {
		_ = exec.CommandContext(ctx, argv[0], argv[1:]...).Start()
	}
}

// browserOpener is the command that opens url in the person's own browser
// on the system goos: open on macOS, the shell's URL handler on Windows
// (Go passes the address as one quoted word, so no cmd.exe reads it), and
// xdg-open elsewhere.
func browserOpener(goos, url string) []string {
	switch goos {
	case "darwin":
		return []string{"open", url}
	case "windows":
		return []string{"rundll32", "url.dll,FileProtocolHandler", url}
	}
	return []string{"xdg-open", url}
}

// cloudEntry is a server, conn or VPN with a cloud's name, from before the
// names were reserved (S-1.5).
type cloudEntry struct{ kind, name, cloud string }

// cloudNamed are the entries named like a cloud login, in a stable order.
func cloudNamed(st *store.State) []cloudEntry {
	var es []cloudEntry
	for _, h := range st.SortedHosts() {
		if c := reservedCloud(h.Name); c != "" {
			es = append(es, cloudEntry{"host", h.Name, c})
		}
	}
	for _, cn := range st.SortedConns() {
		if c := reservedCloud(cn.Name); c != "" {
			es = append(es, cloudEntry{"conn", cn.Name, c})
		}
	}
	for _, v := range st.SortedVpns() {
		if c := reservedCloud(v.Name); c != "" {
			es = append(es, cloudEntry{"vpn", v.Name, c})
		}
	}
	return es
}

// cloudNameText says that an entry's name is a cloud login's and how to
// rename it.
func cloudNameText(e cloudEntry) string {
	word := map[string]string{"host": "server", "conn": "conn", "vpn": "VPN"}[e.kind]
	return fmt.Sprintf("the %s %s has the name of a cloud login: `komando login %s` is the %s login, never this %s. Give it another name: `komando %s rename %s NEW`",
		word, e.name, e.cloud, map[string]string{"aws": "AWS", "gcp": "Google Cloud", "azure": "Azure"}[e.cloud], word, e.kind, e.name)
}

// noteCloudNamed: `login CLOUD` is always the cloud login; an older entry
// with that name gets a note on stderr (and in meta.warnings) that says so.
func noteCloudNamed(cl *call, cloud string) {
	st, err := loadState()
	if err != nil {
		return
	}
	for _, e := range cloudNamed(st) {
		if e.cloud == cloud {
			cl.out.Warn(cloudNameText(e))
		}
	}
}
