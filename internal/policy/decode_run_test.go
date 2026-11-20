package policy

import (
	"strings"
	"testing"
)

const blob = "ZWNobyBoaQ=="

// decode-run: every form of decoding hidden text and running it.
func TestDecodeRun(t *testing.T) {
	blocked := map[string]string{
		"base64 | sh":          "echo " + blob + " | base64 -d | sh",
		"base64 | bash":        "echo " + blob + " | base64 --decode | sudo bash",
		"base64 | zsh":         "base64 -D <<< " + blob + " | zsh",
		"base64 | python":      "echo " + blob + " | base64 -d | python3",
		"base64 | perl":        "echo " + blob + " | base64 -d | perl",
		"base64 | node":        "echo " + blob + " | base64 -d | node",
		"base64 | gunzip | sh": "echo " + blob + " | base64 -d | gunzip | sh",
		"eval $(base64)":       `eval "$(echo ` + blob + ` | base64 -d)"`,
		"source <(base64)":     `source <(echo ` + blob + ` | base64 -d)`,
		"xxd | sh":             "echo 6563686f | xxd -r -p | sh",
		"openssl | sh":         "openssl enc -d -base64 -in p.b64 | sh",
		"python exec":          `python3 -c 'exec(__import__("base64").b64decode("` + blob + `"))'`,
		"perl eval":            `perl -MMIME::Base64 -e 'eval(decode_base64("` + blob + `"))'`,
		"rev | sh":             "echo 'ih ohce' | rev | sh",
		"rot13 | bash":         "echo 'rpub uv' | tr 'A-Za-z' 'N-ZA-Mn-za-m' | bash",
		"file then sh":         "base64 -d > /tmp/x <<EOF\n" + blob + "\nEOF\nsh /tmp/x",
		"file chmod run":       "xxd -r -p blob > a; chmod +x a; ./a",
		"openssl -out run":     "openssl base64 -d -in p -out /tmp/r; chmod +x /tmp/r; /tmp/r",
		"ps scriptblock":       `[scriptblock]::Create([Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('` + blob + `'))).Invoke()`,
		"base64 -di | sh":      "echo " + blob + " | base64 -di | sh",
		"base64 -id | sh":      "echo " + blob + " | base64 -id | sh",
		"base64 -dw0 | sh":     "echo " + blob + " | base64 -dw0 | sh",
		"python -m base64":     "echo " + blob + " | python3 -m base64 -d | sh",
		"basenc --base64 -d":   "echo " + blob + " | basenc --base64 -d | bash",
		"basenc -d":            "basenc -d --base32 < p | sh",
		"printf octal":         `printf '` + strings.Repeat(`\145`, 16) + `' | sh`,
		"printf %b":            `printf '%b' "$P" | sh`,
		"ps iex":               `iex ([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('` + blob + `')))`,
	}
	for name, cmd := range blocked {
		if !hasRule(Check(cmd, nil), "decode-run") && !hasRule(Check(cmd, nil), "win-decode-run") {
			t.Errorf("%s: %q not refused as decode-run, got %v", name, cmd, Check(cmd, nil))
		}
	}
	allowed := map[string]string{
		"decode to a file only": "echo " + blob + " | base64 -d > /etc/ssl/ca.der",
		"decode, run another":   "base64 -d > /tmp/x <<EOF\n" + blob + "\nEOF\nsh /tmp/other",
		"encode and send":       "tar cz . | base64 | ssh x 'cat > a'",
		"rev a list":            "ls | rev | sort",
		"ps decode to file":     `[IO.File]::WriteAllBytes('a.bin', [Convert]::FromBase64String('` + blob + `'))`,
	}
	for name, cmd := range allowed {
		if hasRule(Check(cmd, nil), "decode-run") || hasRule(Check(cmd, nil), "win-decode-run") {
			t.Errorf("%s: %q refused", name, cmd)
		}
	}
}

// base64-pipe-sh sees a decode flag inside a cluster too (-di, -id, -dw0).
func TestBase64PipeShFlagClusters(t *testing.T) {
	for _, f := range []string{"-di", "-id", "-dw0"} {
		cmd := "echo " + blob + " | base64 " + f + " | sh"
		if !hasRule(Check(cmd, nil), "base64-pipe-sh") {
			t.Errorf("%q: not base64-pipe-sh, got %v", cmd, Check(cmd, nil))
		}
	}
	if hasRule(Check("echo x | base64 -w0 | sh", nil), "base64-pipe-sh") {
		t.Error("an encode (-w0) counted as a decode")
	}
}
