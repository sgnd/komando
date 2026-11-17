package policy

import "testing"

// Brace and Code mark the words bash changes or evaluates before the
// command runs, and only those: quoted text is data.
func TestTokenBraceAndCode(t *testing.T) {
	flag := func(s string) (brace, code bool) {
		for _, line := range Tokens(s) {
			for _, tok := range line {
				brace = brace || tok.Brace
				code = code || tok.Code
			}
		}
		return
	}
	for s, want := range map[string][2]bool{
		`systemctl {restart,status} x`: {true, false},
		`echo {1..3}`:                  {true, false},
		`sort {-o,}'/etc/x'`:           {true, false},
		`cat a{'b',c}`:                 {true, false},
		`awk '{print $1,$2}' f`:        {false, false},
		`echo "{a,b}"`:                 {false, false},
		`echo {a}`:                     {false, false},
		`echo ${x},b}`:                 {false, false},
		`echo \{a,b}`:                  {false, false},
		`echo ${x} $x ${1} $@ ${#}`:    {false, false},
		`echo ${x@P}`:                  {false, true},
		`echo "${x@P}"`:                {false, true},
		`echo ${x:=v}`:                 {false, true},
		`echo ${a[i]}`:                 {false, true},
		`echo ${x:n}`:                  {false, true},
		`echo $[x]`:                    {false, true},
		`echo "a $[x]"`:                {false, true},
		`echo '${x@P}' "\${x@P}"`:      {false, false},
		`echo $HOME; awk '${x@P}'`:     {false, false},
	} {
		if b, c := flag(s); b != want[0] || c != want[1] {
			t.Errorf("%q: brace %v code %v, want %v", s, b, c, want)
		}
	}
}
