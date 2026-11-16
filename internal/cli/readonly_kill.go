package cli

import "strings"

// Read tools whose one flag or form writes a file or kills (the allowlist
// otherwise lets them through --read-only).
// optionWrite finds a writing or killing option in args: a short option
// whose letter is in letters, alone or in a cluster (-tK), or a long one in
// longs, alone or with =VALUE. valued are short options whose value is the
// next word (or the rest of the cluster), so it is not read as options.
func optionWrite(cmd string, args []string, letters, valued string, longs ...string) string {
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "--":
			return ""
		case strings.HasPrefix(a, "--"):
			// getopt_long and argparse take any unique start of a long
			// option (--kil for --kill): a start of a writing one counts
			name, _, _ := strings.Cut(a, "=")
			for _, l := range longs {
				if len(name) > 2 && strings.HasPrefix(l, name) {
					return cmd + " " + l
				}
			}
		case len(a) > 1 && a[0] == '-':
			for _, f := range a[1:] {
				if strings.ContainsRune(letters, f) {
					return cmd + " -" + string(f)
				}
				if strings.ContainsRune(valued, f) {
					break // the rest of the word is its value
				}
			}
			if strings.ContainsRune(valued, rune(a[len(a)-1])) {
				i++
			}
		}
	}
	return ""
}

// xxdWrite: xxd [options] [IN [OUT]] writes OUT, whatever it looks like
// (-name too, once IN is given); OUT "-" prints. Its options are words
// with one dash, read by their first letter (-c, -cols, -c8); -c, -g, -l,
// -o, -s and -n take a value, in the same word or the next.
func xxdWrite(cmd string, args []string, _ bool) string {
	var files []string
	opts := true
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case opts && a == "--":
			opts = false
		case opts && len(a) > 1 && a[0] == '-':
			if strings.ContainsRune("cglosn", rune(a[1])) && strings.Trim(a[2:], "abcdefghijklmnopqrstuvwxyz") == "" {
				i++ // its value is the next word
			}
		default:
			opts = false
			files = append(files, a)
		}
	}
	if len(files) >= 2 && files[1] != "-" {
		return cmd + " writing " + files[1]
	}
	return ""
}

// yqWrite: -i/--inplace (--in-place in the Python yq) rewrites the file,
// -s/--split-exp writes a file per document.
func yqWrite(cmd string, args []string, _ bool) string {
	return optionWrite(cmd, args, "is", "o", "--inplace", "--in-place", "--split-exp")
}

// xmllintWrite: --output/-o FILE writes FILE; --shell runs commands
// (save, write) read from its input.
func xmllintWrite(cmd string, args []string, _ bool) string {
	for _, a := range args {
		// xmllint takes its long options with one dash or two
		name, _, _ := strings.Cut(strings.TrimLeft(a, "-"), "=")
		if strings.HasPrefix(a, "-") && (name == "output" || name == "o" || name == "shell") {
			return cmd + " " + a
		}
	}
	return ""
}

// fuserWrite: -k/--kill kills the processes it finds.
func fuserWrite(cmd string, args []string, _ bool) string {
	return optionWrite(cmd, args, "k", "n", "--kill")
}

// ssWrite: -K/--kill closes sockets, -D/--diag FILE writes FILE.
func ssWrite(cmd string, args []string, _ bool) string {
	return optionWrite(cmd, args, "KD", "fAF", "--kill", "--diag")
}

// arpWrite: -d deletes, -s sets and -f FILE loads entries.
func arpWrite(cmd string, args []string, _ bool) string {
	return optionWrite(cmd, args, "dsf", "Hi", "--delete", "--set", "--file")
}

// sarWrite: -o [FILE] saves the readings to a file.
func sarWrite(cmd string, args []string, _ bool) string {
	return optionWrite(cmd, args, "o", "fiesIPnm")
}

// rgWrite: --pre and --hostname-bin run a program.
func rgWrite(cmd string, args []string, _ bool) string {
	for _, a := range args {
		if a == "--" {
			break
		}
		if strings.HasPrefix(a, "--pre") || strings.HasPrefix(a, "--hostname-bin") {
			return cmd + " " + a
		}
	}
	return ""
}

// fileWrite: -C compiles a magic file, which writes NAME.mgc.
func fileWrite(cmd string, args []string, _ bool) string {
	return optionWrite(cmd, args, "C", "mFePf", "--compile")
}

// lsofWrite: -D builds or updates the device cache file.
func lsofWrite(cmd string, args []string, _ bool) string {
	return optionWrite(cmd, args, "D", "acdFgikopsSTuZ")
}

// pidstatWrite: -e PROGRAM runs a program to watch it.
func pidstatWrite(cmd string, args []string, _ bool) string {
	return optionWrite(cmd, args, "e", "CGpT")
}

// blkidWrite: -g and -c FILE change the cache file.
func blkidWrite(cmd string, args []string, _ bool) string {
	if w := optionWrite(cmd, args, "gc", "LUostOuSkn", "--garbage-collect", "--cache-file"); w != "" {
		return w
	}
	for _, a := range args {
		if strings.HasPrefix(a, "--") {
			return cmd + " " + a + " (komando does not know this option only reads)"
		}
	}
	return ""
}

// catOnly: zcat and its like print files; an option may name an output
// file (zstdcat -o), so they take none.
func catOnly(cmd string, args []string, _ bool) string {
	for _, a := range args {
		if len(a) > 1 && a[0] == '-' {
			return cmd + " " + a + " (komando does not know this option only reads)"
		}
	}
	return ""
}

// noWrite: every short option of the command reads; its long ones are
// held to readLongs.
func noWrite(string, []string, bool) string { return "" }

// The shell built-ins below read, but bash evaluates some of their
// arguments: a name with a subscript (a[$(cmd)]) runs the command in it.

// printfWrite: printf -v NAME sets a variable, and evaluates NAME.
func printfWrite(cmd string, args []string, _ bool) string {
	if len(args) > 0 && strings.HasPrefix(args[0], "-") && args[0] != "--" {
		return cmd + " " + args[0]
	}
	return ""
}

// testWrite: -v NAME and -R NAME evaluate NAME, and [[ ]] does arithmetic
// on both sides of -eq and its like.
func testWrite(cmd string, args []string, _ bool) string {
	for _, a := range args {
		switch a {
		case "-v", "-R":
			return cmd + " " + a
		case "-eq", "-ne", "-lt", "-le", "-gt", "-ge":
			if cmd == "[[" {
				return "[[ " + a
			}
		}
	}
	return ""
}

// readWrite: read NAME evaluates a subscript in NAME; only plain names
// and -r pass.
func readWrite(cmd string, args []string, _ bool) string {
	for _, a := range args {
		if a != "-r" && !validShellName(a) {
			return cmd + " " + a
		}
	}
	return ""
}

// configTest: a server program passes only when asked to check or print
// its configuration, or its version: nginx -t, nginx -T, sshd -T,
// apachectl configtest, apachectl -S.
func configTest(cmd string, args []string, _ bool) string {
	ok := map[string]string{"nginx": "tTvVq", "sshd": "tTV", "apachectl": "tSMvVl", "apache2ctl": "tSMvVl", "httpd": "tSMvVl"}[cmd]
	if len(args) == 0 {
		return cmd + " (starting the server)"
	}
	for _, a := range args {
		switch {
		case a == "configtest" && cmd != "nginx" && cmd != "sshd":
		case len(a) > 1 && a[0] == '-' && strings.Trim(a[1:], ok) == "":
		default:
			return notReadForm(cmd, args)
		}
	}
	return ""
}

// firewallCmdWrite: firewall-cmd reads with --state and its --list-,
// --get-, --query- and --info- options; --zone and --permanent say where.
func firewallCmdWrite(cmd string, args []string, _ bool) string {
	for _, a := range args {
		name, _, _ := strings.Cut(a, "=")
		read := name == "--state" || name == "--zone" || name == "--permanent" || name == "--version"
		for _, p := range []string{"--list-", "--get-", "--query-", "--info-"} {
			read = read || strings.HasPrefix(name, p)
		}
		if !read {
			return notReadForm(cmd, args)
		}
	}
	return ""
}
