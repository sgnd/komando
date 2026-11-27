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
	}
	// S-3.2: key revoke pairs with key deploy, pkg rm with pkg install;
	// host ca revoke is known_hosts' @revoked, which pairs with host ca add
	allowPairs = []string{
		"host ca grant/revoke",
		"cluster kubernetes tunnel start/stop", // tunnel list and stop are new code (State New): not mounted yet
		"pkg install/uninstall",
	}
	// S-5.1 exceptions: --wait is a bool on cluster commands; --config a file on vpn add, KEY=VALUE on queue create;
	// --new a bool on secret set (create only), the replacement text on fs replace
	allowFlagTypes = []string{
		"--attach", // host ssh shell (a tmux session) and host ssh exec (session IDs): the v0.18.0 flag review gives them one word each
		"--config",
		"--new",
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
		"import",
		"secret",
		"vpn",
	}
	// S-6.6, S-6.7: commands with fewer examples than S-6.6 asks (a second one is still to write)
	allowExamples = []string{
		"cluster helm history",
		"cluster helm status",
		"cluster history",
		"conn kinds",
		"conn show",
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
		"pkg installed",
		"ssh-gate",
		"version",
	}
	// S-6.8: names outside the sample table where an example needs its own
	allowSampleNames = []string{
		"app1",
		"bastion",
		"shop-2",
		"web3",
	}
	// S-6.10: group rename's Long shows a merge with the old and the new name;
	// the vpn help writes KIND for the kind a VPN was saved with
	allowReferences = []string{
		"group rename: komando group create NEW @OLD",
		"group rename: komando group remove OLD",
		"vpn: komando vpn KIND start NAME",
	}
	// S-5.9: depends commands without --write or --read-only (they decide by their arguments)
	allowDependsSwitch = []string{
		"copy",
		"host ssh shell",
		"host winrm shell",
		"pkg security",
		"pkg upgradable",
		"snippet exec",
		"credential run",
	}
)
