package cli

// Today's exceptions to the command standard (standard_test.go). Each list
// may only shrink: fixing one fails the test until its entry is dropped.

var (
	// S-3.1: verbs neither table names yet
	allowVerbs = []string{
		"db schema",
		"docker stats",
		"login aws",
		"logout aws", // login aws's other half: aws names the cloud, not a verb
		"policy deny",
		"storage cat",
		"storage link",
	}
	// S-3.2: key revoke pairs with key deploy, pkg rm with pkg install
	allowPairs = []string{
		"key grant/revoke",
		"pkg install/uninstall",
	}
	// S-5.1 exceptions: --wait is a bool on cluster commands; --config a file on vpn add, KEY=VALUE on queue create
	allowFlagTypes = []string{
		"--config",
		"--wait",
	}
	// S-5.11: flags whose usage text still differs per command
	allowSharedUsage = []string{
		"--no-sudo",
		"--protected",
		"--since",
		"--sudo",
		"--until",
	}
	// S-5.5
	allowNegatives = []string{}
	// S-6.1..S-6.4
	allowShort = []string{}
	// S-6.5: Longs with indented lines (examples, tables) wider than 76 columns
	allowLong = []string{
		"config set",
		"cp",
		"import",
		"secret",
		"tunnel",
		"vpn",
	}
	// S-6.6, S-6.7: commands with fewer examples than S-6.6 asks (a second one is still to write)
	allowExamples = []string{
		"audit",
		"audit verify",
		"cluster helm history",
		"cluster helm status",
		"cluster history",
		"config show",
		"conn kinds",
		"conn show",
		"cron list",
		"db info",
		"db locks",
		"db sizes",
		"db user list",
		"db user show",
		"docker compose",
		"docker images",
		"docker inspect",
		"docker raw",
		"docker stats",
		"doctor",
		"fs replace dry-run",
		"fs stat",
		"host show",
		"job status",
		"key list",
		"key show",
		"net check",
		"net http",
		"net ports",
		"pkg installed",
		"policy list",
		"queue describe",
		"queue groups",
		"queue info",
		"secret list",
		"shell",
		"ssh-gate",
		"storage download",
		"svc logs",
		"svc status",
		"tunnel list",
		"user list",
		"version",
		"vpn list",
		"vpn show",
		"vpn status",
		"vpn test",
	}
	// S-6.8: names outside the sample table where an example needs its own (a second VPN, a cloud queue)
	allowSampleNames = []string{
		"app1",
		"aws",
		"bastion",
		"bq",
		"client-x",
		"config",
		"dockerhub",
		"gcp",
		"jobs",
		"lab",
		"local",
		"mongo-db",
		"old-office",
		"shop-2",
		"stream",
		"vps1",
		"web3",
	}
	// S-6.10: group rename's Long shows a merge with the old and the new name
	allowReferences = []string{
		"group rename: komando group add NEW @OLD",
		"group rename: komando group rm OLD",
	}
	// S-5.9: depends commands without --write or --read-only (they decide by their arguments)
	allowDependsSwitch = []string{
		"cp",
		"pkg security",
		"pkg upgradable",
		"recipe run",
		"shell",
	}
)
