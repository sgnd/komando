package cli

import (
	"fmt"
	"os"
	"strings"
	"testing"
)

// TestMongoLive runs komando's db commands against a real MongoDB:
//
//	docker run -d -p 127.0.0.1:27018:27017 -e MONGO_INITDB_ROOT_USERNAME=root -e MONGO_INITDB_ROOT_PASSWORD=rootpw mongo:8.0
//	KOMANDO_TEST_MONGO=127.0.0.1:27018 go test ./internal/cli -run MongoLive
func TestMongoLive(t *testing.T) {
	addr := os.Getenv("KOMANDO_TEST_MONGO")
	if addr == "" {
		t.Skip("KOMANDO_TEST_MONGO is not set")
	}
	invHome(t)
	withStdin(t, "rootpw\n", func() { mustRun(t, "secret", "set", "mongo-pass") })
	mustRun(t, "conn", "add", "shop", "mongodb://root@"+addr+"/shop_e2e?authSource=admin", "--password-ref", "secret:mongo-pass")
	mustRun(t, "db", "query", "shop", "--write", "--allow-dangerous", `{"dropDatabase": 1}`)

	r := mustRun(t, "conn", "test", "shop")["results"].([]any)[0].(map[string]any)
	if det, _ := r["detail"].(map[string]any); r["ok"] != true || det["check"] != "login" || !strings.HasPrefix(fmt.Sprint(det["version"]), "8.") {
		t.Errorf("conn test logs in and reads the version: %v", r)
	}
	ins := mustRun(t, "db", "query", "shop", "--write", `{"insert": "users", "documents": [{"name": "Ada", "plan": "pro"}, {"name": "Bob", "plan": "free", "address": {"city": "Oslo"}}]}`)
	if ins["reply"].(map[string]any)["n"].(float64) != 2 || ins["risk"] != "write" {
		t.Errorf("insert: %v", ins)
	}
	d := mustRun(t, "db", "query", "shop", `{"find": "users", "filter": {"plan": "pro"}, "projection": {"_id": 0}}`)
	if docs := d["documents"].([]any); len(docs) != 1 || docs[0].(map[string]any)["name"] != "Ada" || d["risk"] != "read" {
		t.Errorf("find: %v", d)
	}
	agg := mustRun(t, "db", "query", "shop", `{"aggregate": "users", "pipeline": [{"$group": {"_id": "$plan", "n": {"$sum": 1}}}, {"$sort": {"_id": 1}}], "cursor": {}}`)
	if agg["count"].(float64) != 2 {
		t.Errorf("aggregate: %v", agg)
	}
	if d := mustRun(t, "db", "query", "shop", "-n", "1", `{"find": "users"}`); d["count"].(float64) != 1 || d["truncated"] != "documents" {
		t.Errorf("--limit: %v", d)
	}

	wantCode(t, "WRITE_REQUIRES_FLAG", "db", "query", "shop", `{"insert": "users", "documents": [{"name": "Eve"}]}`)
	wantCode(t, "WRITE_REQUIRES_FLAG", "db", "query", "shop", `{"aggregate": "users", "pipeline": [{"$out": "copy"}], "cursor": {}}`)
	wantCode(t, "POLICY_BLOCKED", "db", "query", "shop", "--write", `{"delete": "users", "deletes": [{"q": {}, "limit": 0}]}`)
	dry := mustRun(t, "db", "query", "shop", "--write", "--dry-run", `{"update": "users", "updates": [{"q": {"name": "Bob"}, "u": {"$set": {"plan": "pro"}}}]}`)
	if !strings.Contains(dry["note"].(string), "nothing was sent") {
		t.Errorf("dry run: %v", dry)
	}
	if d := mustRun(t, "db", "query", "shop", `{"count": "users", "query": {"plan": "pro"}}`); d["reply"].(map[string]any)["n"].(float64) != 1 {
		t.Errorf("the dry run sent nothing: %v", d)
	}
	wantCode(t, "USAGE", "db", "query", "shop", "select * from users")

	sch := mustRun(t, "db", "schema", "shop")["collections"].([]any)
	if len(sch) != 1 || sch[0].(map[string]any)["name"] != "users" || sch[0].(map[string]any)["documents"].(float64) != 2 {
		t.Errorf("schema: %v", sch)
	}
	fields := mustRun(t, "db", "schema", "shop", "users")["collections"].([]any)[0].(map[string]any)["fields"].([]any)
	var paths []string
	for _, f := range fields {
		paths = append(paths, f.(map[string]any)["path"].(string))
	}
	if strings.Join(paths, ",") != "_id,address,address.city,name,plan" {
		t.Errorf("fields from a sample: %v", paths)
	}
	wantCode(t, "TABLE_NOT_FOUND", "db", "schema", "shop", "nope")
	if info := mustRun(t, "db", "info", "shop"); info["role"] != "standalone" || info["database"] != "shop_e2e" || info["collections"] == nil {
		t.Errorf("info: %v", info)
	}
	for _, args := range [][]string{{"db", "sizes", "shop"}, {"db", "activity", "shop"}, {"db", "explain", "shop", `{"find": "users"}`}} {
		wantCode(t, "NOT_SUPPORTED", args...)
	}
	mustRun(t, "db", "query", "shop", "--write", "--allow-dangerous", `{"dropDatabase": 1}`)
	mustRun(t, "conn", "edit", "shop", "--protected")
	wantCode(t, "PROTECTED_TARGET", "db", "query", "shop", "--write", `{"insert": "users", "documents": [{"name": "Eve"}]}`)
	mustRun(t, "db", "query", "shop", `{"find": "users"}`) // reading stays allowed
}
