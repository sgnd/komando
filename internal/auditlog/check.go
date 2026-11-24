package auditlog

import "strconv"

type Check struct {
	OK          bool   `json:"ok"`
	Entries     int    `json:"entries"`
	Chained     int    `json:"chained"`                // records with a prev hash
	FirstBroken int    `json:"first_broken,omitempty"` // line number
	Note        string `json:"note"`
}

func (a Check) Text() string {
	if a.OK {
		return "audit log intact: " + strconv.Itoa(a.Entries) + " entries\n" + a.Note
	}
	return "audit log broken at line " + strconv.Itoa(a.FirstBroken) + "\n" + a.Note
}
