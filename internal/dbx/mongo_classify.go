package dbx

import (
	"strings"

	"go.mongodb.org/mongo-driver/v2/bson"

	"github.com/sgnd/komando/internal/driver"
)

// A MongoDB command is a document whose first key names it:
// {"find": "users", "filter": {...}}. komando rates it before sending it,
// as it does SQL: a command it does not know as a read needs --write.
// MongoDB has no read-only transaction, so this rating is what keeps a
// read a read (a read-only user enforces it on the server too).

// mongoRules are the rules ClassifyMongo reports, for `komando policy`.
var mongoRules = []driver.Rule{
	{ID: "mongo-drop", Reason: "drops a database, collection, index or user"},
	{ID: "mongo-delete-all", Reason: "removes every document (a delete with an empty filter)"},
	{ID: "mongo-update-all", Reason: "changes every document (an update of many documents with an empty filter)"},
	{ID: "mongo-admin", Reason: "shuts down, reconfigures or locks the server, or kills operations"},
	{ID: "mongo-privileges", Reason: "changes users, roles or privileges"},
}

// MongoRules lists the rules ClassifyMongo can report.
func MongoRules() []driver.Rule { return append([]driver.Rule(nil), mongoRules...) }

var mongoReads = set(`find aggregate count distinct listCollections listIndexes listDatabases collStats dbStats
dataSize explain serverStatus buildInfo ping hello isMaster ismaster hostInfo connectionStatus getParameter
currentOp top validate getMore killCursors replSetGetStatus getCmdLineOpts usersInfo rolesInfo
getLog dbHash profile listSearchIndexes`)

var mongoWrites = set(`insert update delete findAndModify create createIndexes collMod bulkWrite
createView renameCollection compact reIndex cloneCollectionAsCapped convertToCapped`)

var mongoDrops = set(`drop dropDatabase dropIndexes deleteIndexes dropUser dropAllUsersFromDatabase dropRole
dropAllRolesFromDatabase dropSearchIndex`)

var mongoAdmin = set(`shutdown replSetReconfig replSetStepDown replSetFreeze fsync fsyncUnlock killOp
killSessions killAllSessions setFeatureCompatibilityVersion setParameter logRotate removeShard`)

var mongoPrivileges = set(`createUser updateUser grantRolesToUser revokeRolesFromUser createRole updateRole
grantPrivilegesToRole revokePrivilegesFromRole grantRolesToRole revokeRolesFromRole`)

func set(words string) map[string]bool {
	m := map[string]bool{}
	for _, w := range strings.Fields(words) {
		m[strings.ToLower(w)] = true
	}
	return m
}

// ClassifyMongo rates a command document.
func ClassifyMongo(cmd bson.D) driver.Verdict {
	if len(cmd) == 0 {
		return driver.Verdict{Risk: driver.RiskWrite, Reasons: []string{"an empty command"}}
	}
	name := strings.ToLower(cmd[0].Key)
	hit := func(id string) driver.Verdict {
		for _, r := range mongoRules {
			if r.ID == id {
				return driver.Verdict{Risk: driver.RiskDestructive, RuleIDs: []string{id}, Reasons: []string{r.Reason}}
			}
		}
		return driver.Verdict{Risk: driver.RiskDestructive}
	}
	switch {
	case mongoDrops[name]:
		return hit("mongo-drop")
	case mongoAdmin[name]:
		return hit("mongo-admin")
	case mongoPrivileges[name]:
		return hit("mongo-privileges")
	case name == "delete" && anyStatement(cmd, "deletes", func(s bson.D) bool { return emptyDoc(field(s, "q")) && limitAll(s) }):
		return hit("mongo-delete-all")
	case name == "update" && anyStatement(cmd, "updates", func(s bson.D) bool { return emptyDoc(field(s, "q")) && field(s, "multi") == true }):
		return hit("mongo-update-all")
	case name == "renamecollection" && field(cmd, "dropTarget") == true:
		return hit("mongo-drop")
	case name == "aggregate" && writesOut(cmd):
		return driver.Verdict{Risk: driver.RiskWrite, Reasons: []string{"$out or $merge writes the result to a collection"}}
	case name == "explain":
		return driver.Verdict{Risk: driver.RiskRead}
	case mongoReads[name]:
		return driver.Verdict{Risk: driver.RiskRead}
	case mongoWrites[name]:
		return driver.Verdict{Risk: driver.RiskWrite}
	}
	return driver.Verdict{Risk: driver.RiskWrite, Reasons: []string{cmd[0].Key + " is not known to be a read"}}
}

func field(d bson.D, key string) any {
	for _, e := range d {
		if e.Key == key {
			return e.Value
		}
	}
	return nil
}

func emptyDoc(v any) bool {
	switch d := v.(type) {
	case nil:
		return true
	case bson.D:
		return len(d) == 0
	}
	return false
}

// limitAll: a delete statement with limit 0 removes every match.
func limitAll(s bson.D) bool {
	switch n := field(s, "limit").(type) {
	case int32:
		return n == 0
	case int64:
		return n == 0
	case float64:
		return n == 0
	}
	return true
}

func anyStatement(cmd bson.D, key string, f func(bson.D) bool) bool {
	arr, _ := field(cmd, key).(bson.A)
	for _, s := range arr {
		if d, ok := s.(bson.D); ok && f(d) {
			return true
		}
	}
	return false
}

func writesOut(cmd bson.D) bool {
	pipe, _ := field(cmd, "pipeline").(bson.A)
	for _, st := range pipe {
		if d, ok := st.(bson.D); ok && len(d) > 0 && (d[0].Key == "$out" || d[0].Key == "$merge") {
			return true
		}
	}
	return false
}
