package policy

import (
	"regexp"
	"strings"
)

// decode-run: a script or command that decodes hidden text and runs it.
// Matched as text only: a path built from variables still slips past, and
// the encoded-data risk line (ScanEncoded) shows the blob then.

// decoder is a command that turns hidden text back into code.
const decoder = `(\bbase(64|32)\s+(-\S+\s+)*(-d|--decode|-D)\b` +
	`|\bxxd\s+(-\S+\s+)*-r` +
	`|\bopenssl\s+(enc|base64)\b[^|;&]*\s-d\b` +
	`|\buudecode\b|\brev\b` +
	`|\btr\s+['"]?[a-zA-Z-]+['"]?\s+['"]?[n-zN-Z]-` + // rot13
	`|\bprintf\s+['"]?(\\x[0-9a-fA-F]{2}){16})`

// runner is a shell or interpreter that runs what it reads.
const runner = `(sudo\s+(-\S+\s+)*)?(env\s+)?(/usr)?(/bin/)?((ba|z|da|k|fi)?sh|python[0-9.]*|perl|node|ruby|php)\b`

// decodeRun is the pipe, substitution and one-liner forms.
const decodeRun = decoder + `[^;&\n]*\|\s*` + runner +
	`|\b(eval|exec|source|(ba|z)?sh|python[0-9.]*|perl|node)\s+(-\S+\s+)*("?\$\(|<\(|` + "`" + `)[^;\n]*?` + decoder +
	`|\b(python[0-9.]*|perl|ruby|node)\s+(-\S+\s+)*-[ceE]\s+.*\b(exec|eval|system|Function)\b.*(b64decode|a85decode|fromhex|unhexlify|decode_base64|Buffer\.from|atob)` +
	`|\b(python[0-9.]*|perl|ruby|node)\s+(-\S+\s+)*-[ceE]\s+.*(b64decode|a85decode|fromhex|unhexlify|decode_base64|Buffer\.from|atob).*\b(exec|eval|system|Function)\b`

const decodeRunReason = "decodes hidden data and runs it (it cannot be reviewed)"

// decodedTo finds a decoder that writes to a file: > PATH, -o PATH,
// -out PATH, --output PATH or of=PATH.
var decodedTo = regexp.MustCompile(decoder + `[^;&|\n]*?(>{1,2}\s*|\s-out\s+|\s-o\s*|--output[= ]|\bof=)([^\s;&|<>'"]+)`)

// decodeToFileRuns: a decoded file that a later step runs, by its path
// as written (sh PATH, ./PATH, PATH after chmod +x).
func decodeToFileRuns(cmd string) bool {
	for _, m := range decodedTo.FindAllStringSubmatchIndex(cmd, -1) {
		path := strings.TrimPrefix(cmd[m[len(m)-2]:m[len(m)-1]], "./")
		run := regexp.MustCompile(`(^|[;&|(]\s*|\b(sh|bash|zsh|dash|ksh|python[0-9.]*|perl|node|ruby|source|exec|nohup|sudo|env)\s+(-\S+\s+)*)(\./)?` +
			regexp.QuoteMeta(path) + `(\s|$|;|&|\||\))`)
		if run.MatchString(cmd[m[1]:]) {
			return true
		}
	}
	return false
}

func init() {
	compiled = append(compiled, Rule{ID: "decode-run", Reason: decodeRunReason, re: regexp.MustCompile(decodeRun), fn: decodeToFileRuns})
}
