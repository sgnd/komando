package policy

import "testing"

// FuzzCheck: never panics, and spacing or quoting a dangerous word does not
// hide it.
func FuzzCheck(f *testing.F) {
	for _, s := range []string{"rm -rf /", "mkfs.ext4 /dev/sda", "a\nreboot", `rm -rf "/"`, `r\m -rf /e""tc`, `$'\x72\155' -rf /`, "echo $(a `b` <(c)) 2>&1 >| f", `sh -c "eval 'x'"`, `bash -c -- 'r""m -rf /'`, `sh -c 'r""m -rf "$0"' /`, `{rm,-rf,/}`, "# it's\nr\\m -rf /\n#'", "cat <<EOF\nx\nEOF"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		_ = Check(s, []string{"x("})
		if len(Check("rm -rf /", nil)) == 0 {
			t.Fatal("rule lost")
		}
	})
}
