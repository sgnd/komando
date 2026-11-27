package execsession

import (
	"context"
	"encoding/base64"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestReadScriptPSChecksItsArgs(t *testing.T) {
	if _, err := ReadScriptPS("../x", 0); err == nil {
		t.Error("a bad ID made a script")
	}
	if _, err := ReadScriptPS(testID, -1); err == nil {
		t.Error("a negative offset made a script")
	}
}

// The read script parses as Windows PowerShell 5.1, uses no .NET beyond
// the allowed calls, holds only the checked ID and the offset, and
// deletes nothing (a read never deletes, A-C324-10).
func TestReadScriptPSText(t *testing.T) {
	for _, from := range []int64{0, 70000} {
		s, err := ReadScriptPS(testID, from)
		if err != nil {
			t.Fatal(err)
		}
		psOnlyAllowed(t, s)
		for _, want := range []string{
			"$ks_id = '" + testID + "'", "$ks_from = " + strconv.FormatInt(from, 10),
			"-Encoding Byte -ReadCount 65536", "Select-Object -Skip $ks_k -First 2",
			"'ReparsePoint'", "(ks_owner (Get-Acl -LiteralPath $p).Sddl) -ne $ks_sid",
			"Write-Output ('data ' + [Convert]::ToBase64String([byte[]]$ks_part))",
		} {
			if !strings.Contains(s, want) {
				t.Errorf("the read script has no %q", want)
			}
		}
		for _, banned := range []string{"Remove-Item", "Set-Content", "New-Item", "Move-Item"} {
			if strings.Contains(s, banned) {
				t.Errorf("the read script holds %s: a read never changes the folder", banned)
			}
		}
		psParse(t, s) // last: it skips the test where there is no PowerShell
	}
}

// ParseReadPS reads the status between the markers and the base64 data
// line after them, CRLF or LF.
func TestParseReadPS(t *testing.T) {
	data := []byte("é\x00line\n")
	s := "noise\r\nread-begin " + testID + "\r\nexit 3\r\ntruncated 9\r\nsize 120\r\nread-end " + testID + "\r\ndata " + base64.StdEncoding.EncodeToString(data) + "\r\n"
	st, got, err := ParseReadPS(s, testID)
	if err != nil || !st.Ended() || st.Exit != 3 || st.Truncated != 9 || st.Size != 120 || string(got) != string(data) {
		t.Fatalf("%+v %q %v", st, got, err)
	}
	// no data line: nothing new
	if _, got, err := ParseReadPS("read-begin "+testID+"\nsize 0\nread-end "+testID+"\n", testID); err != nil || len(got) != 0 {
		t.Errorf("no data: %q, %v", got, err)
	}
	for name, bad := range map[string]string{
		"bad base64":  "read-begin " + testID + "\nsize 3\nread-end " + testID + "\ndata !!!\n",
		"two data":    "read-begin " + testID + "\nsize 3\nread-end " + testID + "\ndata YQ==\ndata YQ==\n",
		"other line":  "read-begin " + testID + "\nsize 3\nread-end " + testID + "\nexit 0\n",
		"no markers":  "size 3\ndata YQ==\n",
		"other ID":    "read-begin x\nsize 3\nread-end x\n",
		"over a read": "read-begin " + testID + "\nsize 99999\nread-end " + testID + "\ndata " + base64.StdEncoding.EncodeToString(make([]byte, ReadMaxPS+1)) + "\n",
	} {
		t.Run(name, func(t *testing.T) {
			if st, d, err := ParseReadPS(bad, testID); err == nil {
				t.Errorf("accepted %+v %q", st, d)
			}
		})
	}
}

// fakeLogPS serves ReadScriptPS calls from a log that grows by one piece
// per read, at most ReadMaxPS bytes at a time.
type fakeLogPS struct {
	pieces []string
	log    string
	ended  bool
	froms  []int64
}

var psFrom = regexp.MustCompile(`\$ks_from = ([0-9]+)`)

func (f *fakeLogPS) read(_ context.Context, script string) (string, int, error) {
	from, _ := strconv.ParseInt(psFrom.FindStringSubmatch(script)[1], 10, 64)
	f.froms = append(f.froms, from)
	if len(f.pieces) > 0 {
		f.log += f.pieces[0]
		f.pieces = f.pieces[1:]
	}
	head := "read-begin " + testID + "\r\n"
	if f.ended && len(f.pieces) == 0 {
		head += "exit 0\r\n"
	}
	head += "size " + strconv.Itoa(len(f.log)) + "\r\nread-end " + testID + "\r\n"
	data := f.log[min(int(from), len(f.log)):]
	if len(data) > ReadMaxPS {
		data = data[:ReadMaxPS]
	}
	if data != "" {
		head += "data " + base64.StdEncoding.EncodeToString([]byte(data)) + "\r\n"
	}
	return head, 0, nil
}

func followPS(from int64, shown *strings.Builder) Follow {
	f := follow(from, time.Second, true, shown)
	f.Windows = true
	return f
}

// The byte order mark Windows PowerShell 5.1 writes at the start of
// out.log is not shown, and next_from counts from the file's real offset
// (A-C324-11).
func TestFollowPSSkipsTheBOM(t *testing.T) {
	f := &fakeLogPS{pieces: []string{bom + "é 日本\n"}, ended: true}
	var shown strings.Builder
	res, err := followPS(0, &shown).Run(context.Background(), f.read)
	if err != nil || shown.String() != "é 日本\n" || res.NextFrom != int64(len(f.log)) {
		t.Fatalf("shown %q, next_from %d of %d, %v", shown.String(), res.NextFrom, len(f.log), err)
	}
	// from a later offset, the same bytes are text, not a mark to skip
	f = &fakeLogPS{pieces: []string{"ab\n" + bom + "c\n"}, ended: true}
	shown.Reset()
	if _, err := followPS(3, &shown).Run(context.Background(), f.read); err != nil || shown.String() != bom+"c\n" {
		t.Fatalf("shown %q, %v", shown.String(), err)
	}
}

// A token split across two 64 KiB polls comes out masked, and every read
// after the first starts at a line start (W12 without the lab).
func TestFollowPSMasksAcrossPolls(t *testing.T) {
	head := bom + strings.Repeat("x", ReadMaxPS-10) + "\n"
	f := &fakeLogPS{pieces: []string{head + "two tok", "123\nlast\n"}, ended: true}
	var shown strings.Builder
	res, err := followPS(0, &shown).Run(context.Background(), f.read)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasSuffix(shown.String(), "two [hidden]\nlast\n") || strings.Contains(shown.String(), "tok123") {
		t.Errorf("shown ends %q", shown.String()[max(0, shown.Len()-40):])
	}
	if res.NextFrom != int64(len(f.log)) {
		t.Errorf("next_from %d of %d", res.NextFrom, len(f.log))
	}
	for _, from := range f.froms {
		if from > 3 && f.log[from-1] != '\n' {
			t.Errorf("a read started inside a line at %d (%v)", from, f.froms)
		}
	}
}

// A Windows read that finds the folder unsafe says so in Windows terms.
func TestFollowPSRefusals(t *testing.T) {
	var shown strings.Builder
	f := followPS(0, &shown)
	_, err := f.Run(context.Background(), func(context.Context, string) (string, int, error) { return "", ExitUnsafe, nil })
	if err == nil || !strings.Contains(err.Error(), "LOCALAPPDATA") {
		t.Errorf("got %v", err)
	}
}

// A full 64 KiB read is followed by the next one at once: the pause is
// only for a read that found less than a full piece.
func TestFollowPSReadsOnWithoutPause(t *testing.T) {
	f := &fakeLogPS{pieces: []string{strings.Repeat("x\n", ReadMaxPS)}, ended: true}
	var shown strings.Builder
	fl := followPS(0, &shown)
	fl.Every, fl.Wait = time.Hour, time.Hour
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	res, err := fl.Run(ctx, f.read)
	if err != nil || res.NextFrom != int64(len(f.log)) {
		t.Fatalf("next_from %d of %d, %v", res.NextFrom, len(f.log), err)
	}
}
