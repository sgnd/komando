package cli

import (
	"strings"
	"testing"
)

const mxtSessions = "[Bookmarks]\r\nSubRep=\r\nImgNum=42\r\nweb1=#109#0%web.example%22%deploy%%-1%-1%%%%%0%0%0%%%-1%0%0%0%%1080%%0%0%1#MobaFont%10%0%0%-1%15%236,236,236%30,30,30%180,180,192%0%-1%0%%xterm%-1%-1%_Std_Colors_0_%80%24%0%1%-1%<none>%%0%0%-1#0# #-1\r\nrouter=#98#1%192.168.1.1%23%%%2%%%%%0%0%%1080%#MobaFont#0# #-1\r\n\r\n[Bookmarks_1]\r\nSubRep=Prod\\DB\r\nImgNum=41\r\ndb1=#109#0%10.0.0.9%2222%ops%%-1%-1%%%%%0%0%0%%%-1%0%0%0%%1080%%0%0%1#MobaFont#0# #-1\r\n"

// MobaXterm's exported sessions: SSH ones (type 109) become servers, with
// their folder as a group; a telnet session is listed.
func TestImportMobaXterm(t *testing.T) {
	p, err := importMobaXterm(writeTemp(t, "sessions.mxtsessions", mxtSessions))
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Hosts) != 2 {
		t.Fatalf("hosts %+v notes %v", p.Hosts, p.Notes)
	}
	var web, db = p.Hosts[0], p.Hosts[1]
	if web.Address == "10.0.0.9" {
		web, db = db, web
	}
	if web.Address != "web.example" || web.User != "deploy" || web.Port != 0 || len(web.Groups) != 0 {
		t.Errorf("web %+v", web)
	}
	if db.Address != "10.0.0.9" || db.User != "ops" || db.Port != 2222 || len(db.Groups) != 1 || db.Groups[0] != "prod-db" {
		t.Errorf("db %+v", db)
	}
	if !strings.Contains(strings.Join(p.Notes, "\n"), "router: not an SSH session") {
		t.Errorf("notes %v", p.Notes)
	}
}
