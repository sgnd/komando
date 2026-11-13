# The komando message style

The words of every line komando writes for a person: questions and
confirms, the approval window, warnings and notes, dry-run and `Next:`
lines, success and empty lines, errors and hints, progress and Ctrl-C
lines, `doctor` and the guide. Help text follows the
[command standard](command-standard.md) (S-6); only its words follow this
page. This page adds to the command standard and does not repeat it: S-7
(confirms), S-8 (errors and hints) and S-9 (output) still hold. The
strings that still break a rule are the allow-lists in
`internal/cli/message_style_test.go`.

Tags: **[test]** a Go test can enforce it (the test it needs is under
"Tests"); **[review]** a person checks it.

The contract does not move: error codes, exit codes and JSON field names
stay. Only the human text changes. `error.message` and `error.hint` are free
text, but agents read them, so a change to them is listed in the release
note and TestAgentGolden is regenerated only for the intended rows.

## Voice

**M-1 Calm and plain, never blame.** Say what is true about the input or
the world, not about the person. [test]

| Never | Write |
|---|---|
| invalid X %q | %q is not a X / komando cannot read X %q |
| bad X, malformed X | X does not match / komando cannot read X |
| X must be Y | X takes Y / X is Y / X has to be Y |
| you must Y | Y first / komando needs Y |
| failed to X, unable to X | could not X |
| illegal, forbidden, please, simply, sorry, oops, a closing "!" | (leave out) |

"wrong" stays for a value that did not match a stored one ("wrong user name
or password"). "not allowed" stays when the line says why. "you" is the
person, only in questions, help under a question and Say text, never as the
subject of a mistake ("you gave", "you forgot").

**M-2 Shape of an error.** `error.message`: what happened and the state
now, after a colon the why (S-8.4). `error.hint`: only the next step, with
the exact command in backticks (S-8.5). A state ("nothing was changed")
goes in the message, never in the hint. A name the person typed is in
double quotes (`%q`); a command is in backticks. [test: S-8.4/S-8.5 tests
plus "a hint never starts with `nothing was`"]

## Case and punctuation

**M-3 Fragments and sentences.** One rule, decided by what the text is:

- A *fragment* starts lower-case and has no full stop: `error.message`,
  `error.hint`, warning text, `meta.*` notes, result headlines on stdout
  (`added web2`, `` no SSH keys yet: `komando key gen NAME` ``), table cells,
  the text after a label. Clauses join with `:` or `;`. A proper name,
  code or flag keeps its own case (`Swarm keeps …`, `KOMANDO_OUTPUT=…`).
- A *sentence* starts with a capital and ends with `.`, or `?` for a
  question: questions, the help shown under a question, Long help, Say text,
  confirm lines, notes of two or more sentences.

So a one-line error has **no trailing period**. The printer adds nothing:
`Stopped: <msg>; nothing was changed`. [test: catalog, Errf/Usage and Warn
literals start lower-case (allow-list of proper names) and do not end in
`.`; prompt `ask` ends in `?`, prompt `help` ends in `.`]

**M-4 Labels on stderr.** A line komando writes for itself starts with a
capital: a label from this closed set, then a fragment, or a sentence.

| Label | For |
|---|---|
| `Error:` / `Stopped:` | the end of a failed or stopped command (printer) |
| `Hint:` | the next step (printer) |
| `Warning:` | something went wrong beside the result |
| `Note:` | a fact the person should know: output cut, unknown agent |
| `Dry run:` | the dry-run line |
| `Skipped` | a target left out |
| `Next:` / `Next time:` | S-9.3 |
| `Using` | the one item komando picked for a missing argument |

`komando:` starts a line only where a server's output shares the screen:
status lines of shell, logs -f, cluster exec/forward, vpn up and sign-in,
tunnels. Lines under a question are indented: `  ! problem`, `  komando …`.
[test: every literal written to os.Stderr or promptW starts with a label,
a capital, `komando:`, two spaces, `$ komando` or a newline]

## Words

**M-5 One term for one thing,** the same word as the command noun.
[test: word list over catalog, Errf/Usage, Warn, prompt ask/help]

| Thing | Word | Not |
|---|---|---|
| a `host` entry | server (`host` only as the command) | host, machine, node |
| a non-SSH target | conn; the family word when known (database, cache …) | service, resource, connection |
| komando's list of servers, conns and VPNs | your list | inventory (help group title only, S-6.11) |
| a vault value | secret (a login password stays "password") | credential, saved password |
| an SSH key komando knows | key / SSH key | keypair, identity |
| `@name` | group | set, collection |
| `job start` work | job | task, background command |
| a deny rule a person added | your deny rule | custom deny pattern |
| a folder | folder | directory |

"host" stays for a URL's host part, "host key", "host name" and Kubernetes
or Swarm words; "service" for a systemd/Windows service, a Kubernetes or
Swarm Service and a cloud "service account"; "connection" for a network
connection.

**M-6 No Latin abbreviations.** "for example" in messages and hints, "like"
in questions and flag usage; never e.g., i.e., etc. [test]

**M-7 Jargon gets plain words first.** stdin, stdout, stderr, TTY,
interactive, selector and JSON paths are shown in parentheses after the
plain words: "the error output (stderr)", "pipe it in (stdin)", "each
server's result (data.results in -o json)". A doctor check shows a label,
not its JSON name. [test: a hint that names `data.`, `meta.` or `error.`
has it inside parentheses with "-o json"]

**M-8 "unknown" names the way out.** `unknown X %q` only when the same line
or its hint lists the known values or names the command that lists them.
Otherwise: `komando has no X named %q` (S-8.4) or `komando does not know
the X %q`. A value only a bug can reach says `(a bug: report it)`. [test]

## Layout

**M-9 80 columns.** A line komando lays out itself (question, note, status
line, table header, doctor line) fits in 80 columns. Error, hint, warning
and doctor details are wrapped by the printer at min(terminal width, 80)
with a two-space hanging indent, never inside backticks or a URL. Data
(file content, rows, server output) is never wrapped. [test: literal
stderr lines ≤ 80; the printer wraps a 200-character hint into lines ≤ 80
with every backticked command whole]

**M-10 Marks have one meaning each.** [test: out.Marks map; no other
non-ASCII mark in literals]

| Mark | Means | ASCII |
|---|---|---|
| ✓ | a check passed (doctor, test lists) | + |
| ✗ | a check failed, needs fixing | x |
| ! | worth a look; a problem under a question | ! |
| ● | starts one target's block in multi-target text | * |
| → | from → to: a path (`via vpn office → bastion`), a value or version change | -> |
| · | between items on one line (`Next: a · b`) | - |
| … | text cut; "and N more" when a count is known | ... |

Status words are lower-case: `ok`, `failed: <why>`; `exit N`, never
`exit=N`. No all-caps words in komando's own text except codes,
placeholders (TARGET), environment variables and the red `PROTECTED` tag.
Log lines of background programs (`TIME ERROR …`) are exempt.

## Fixed lines

**M-11 Confirms use the three S-7.2 templates.** The reason inside them is a
verb phrase without a subject, so it reads after "This": `deletes the
files`, `stops every copy of deploy/api`. Policy and classifier reasons
follow the same shape (they are also `policy list` text). [test: PTY test
per tier; risk rows and rule reasons start with a verb in -s]

- T2: `web1 (protected): this command changes it. Continue? [y/N]`
- T3: `This <reason>. Type <answer> to continue:`
- T3s: `This turns off a komando safety check: <what>. Continue? [y/N]`
- policy hit at a terminal: `Blocked by policy: <rule>.` (S-7.9)

**M-12 Stop lines.** [test]

| When | Line |
|---|---|
| a person answers no | `Cancelled. Nothing was changed.` (S-8.9) |
| Ctrl-C at a question, before anything ran | `Stopped. Nothing was run.` |
| Ctrl-C while it runs | `Stopped (Ctrl-C) before the end; what already ran stays as it is` + `Hint: check what it left, then run it again` |
| a safety stop | `Stopped: <msg>; nothing was changed` (printer) |

**M-13 Empty and cut.** Empty result: `` no <things> yet: `komando … add` ``,
or `no <things> match <filter>` (S-9.5). A cut list or output says, on
stderr: `Note: showing the first N; <how to see all>`. One phrase for rows,
bytes and output. [test]

## Audience

**M-14 One text for agents and people, Say for people only.** JSON message
and hint are read by agents and by people (`-o text`), so their words work
for both. Words only a person needs (run it in a terminal, type the name)
go through `Say`, as sentences (M-3). An agent's hint says "ask the user",
never "you". [review]

**M-15 Other programs' words are data.** kubectl's text in kctl, db shell's
psql-style lines, cache run replies, server output and strings matched
against other programs' errors keep their own words. [review]

## Tests

One file, `internal/cli/message_style_test.go`, reads the error catalog and
walks the non-test Go files with go/ast, as TestStandardReferences does:

| Test | Rules | Checks |
|---|---|---|
| TestMessageWords | M-1, M-6 | banned words and e.g./i.e./etc. in catalog text, Errf/Usage format strings, Warn, prompt ask/help; allow-list file:line that may only shrink |
| TestMessageCase | M-3 | fragment literals start lower-case (proper-name list) and end without `.`; questions end in `?` |
| TestStderrLabels | M-4 | first word of every literal written to os.Stderr / promptW |
| TestMessageTerms | M-5 | "host"/"service"/"inventory"/"directory" outside the allowed phrases |
| TestHintJargon | M-7 | JSON paths and stdin/stderr in hints only inside parentheses |
| TestUnknownNamesWayOut | M-8 | "unknown" lines have a list, "use", or a backticked command in message or hint |
| TestTextWidth | M-9 | stderr literals ≤ 80 columns; printer wraps and keeps backticks whole |
| TestMarks | M-10 | marks only from the table; no FAILED/ERROR/BROKEN/exit= in cli literals |
| TestRiskReasons | M-11 | riskRows `what`/`typed`, confirmDangerous reasons and policy rule reasons start with a verb ending in -s |
| TestStopLines | M-12, M-13 | the fixed lines; one cut-note helper |

Each test has an allow-list of the strings that still break its rule (or
that a rule does not fit, such as another program's words); an entry that
matches nothing any more fails the test, so the lists only shrink.
`KOMANDO_STYLE_LIST=1` prints the entries a test would need.
