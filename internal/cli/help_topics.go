package cli

import "github.com/spf13/cobra"

// Help topics: `komando help safety` (environment, exit-codes, output)
// explains one thing that holds for every command. They are not commands;
// cobra lists them under Additional help topics.

var helpTopics = []struct{ name, short, long string }{
	{"safety", "How komando keeps a change from going wrong", `How komando keeps a change from going wrong.

  --dry-run           every change can show what it would do first
  protected targets   a change asks [y/N] at your terminal; scripts and agents need --yes
  dangerous commands  rm -rf /, DROP DATABASE ...: you type the name; scripts need --allow-dangerous
  read only           db query, cache run and cluster run only read unless you add --write
  audit               komando audit shows every change and who asked for it

An AI agent is never asked: it gets exit 6 and a person allows the flag in a
window on the screen. See docs/features/safety.md.`},
	{"environment", "The environment variables komando reads", `The environment variables komando reads.

  KOMANDO_HOME        where komando keeps its data (default ~/.komando)
  KOMANDO_OUTPUT      json or text when -o is not given
  KOMANDO_ACTOR       the name the audit log gives you
  KOMANDO_AGENT=1     an AI agent komando does not know by itself
  KOMANDO_VAULT_PASS  the vault passphrase, when the vault has one
  CI                  a CI job: komando never asks anything
  NO_COLOR            no colors`},
	{"exit-codes", "What komando's exit codes mean", `What komando's exit codes mean.

  0 ok          1 error           2 usage           3 not found
  4 connect     5 failed on the server              6 blocked for safety
  7 timeout     8 precondition or conflict

-o json shows the error code (USAGE, PROTECTED_HOST ...) and a hint.`},
	{"output", "Text for people, JSON for programs", `Text for people, JSON for programs.

In a terminal komando prints text; piped, one JSON envelope on stdout:
  {"ok":true,"command":"exec","data":{...},"meta":{...}}
  {"ok":false,"command":"exec","error":{"code":"AUTH_FAILED",...}}
Force one with -o json or -o text (db query also takes csv and tsv).
Questions, the line komando runs ($ komando ...) and Next: go to stderr,
and only at a person's terminal.`},
}

func addHelpTopics(root *cobra.Command) {
	for _, t := range helpTopics {
		root.AddCommand(&cobra.Command{Use: t.name, Short: t.short, Long: t.long, GroupID: "meta"})
	}
	root.InitDefaultHelpCmd()
}
