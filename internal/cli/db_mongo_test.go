package cli

import (
	"context"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
)

// TestMongoLive runs komando's db commands against a real MongoDB:
//
//	docker run -d -p 127.0.0.1:27018:27017 -e MONGO_INITDB_ROOT_USERNAME=root -e MONGO_INITDB_ROOT_PASSWORD=rootpw mongo:7.0.45
//	KOMANDO_TEST_MONGO=127.0.0.1:27018 go test ./internal/cli -run MongoLive
func TestMongoLive(t *testing.T) {
	addr := os.Getenv("KOMANDO_TEST_MONGO")
	if addr == "" {
		t.Skip("KOMANDO_TEST_MONGO is not set")
	}
	invHome(t)
	withStdin(t, "rootpw\n", func() { mustRun(t, "credential", "password", "add", "mongo-pass") })
	mustRun(t, "conn", "add", "shop", "mongodb://root@"+addr+"/shop_e2e?authSource=admin", "--password-ref", "secret:mongo-pass")
	mustRun(t, "db", "query", "shop", "--write", "--allow-dangerous", `{"dropDatabase": 1}`)

	r := mustRun(t, "conn", "test", "shop")["results"].([]any)[0].(map[string]any)
	if det, _ := r["detail"].(map[string]any); r["ok"] != true || det["check"] != "login" || !strings.Contains(fmt.Sprint(det["version"]), ".") {
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
	wantCode(t, "NOT_SUPPORTED", "db", "sizes", "shop")
	if d := mustRun(t, "db", "explain", "shop", `{"find": "users", "filter": {"plan": "pro"}}`); d["plan"] == nil || d["command"] != "find" {
		t.Errorf("explain: %v", d)
	}
	wantCode(t, "USAGE", "db", "explain", "shop", `{"delete": "users", "deletes": [{"q": {}, "limit": 0}]}`)
	if d := mustRun(t, "db", "activity", "shop", "--all"); d["sessions"] == nil {
		t.Errorf("activity: %v", d)
	}
	users := mustRun(t, "db", "user", "list", "shop")["users"].([]any)
	if len(users) == 0 || !strings.Contains(fmt.Sprint(users), "root") || strings.Contains(fmt.Sprint(users), "SCRAM-SHA-256:") {
		t.Errorf("user list: %v", users)
	}
	g := mustRun(t, "db", "user", "show", "shop", "root")["grants"].([]any)
	if !strings.Contains(fmt.Sprint(g), "root") || !strings.Contains(fmt.Sprint(g), "on_type:role") {
		t.Errorf("user show: %v", g)
	}
	wantCode(t, "DB_USER_NOT_FOUND", "db", "user", "show", "shop", "nobody")
	wantCode(t, "SESSION_NOT_FOUND", "db", "kill", "shop", "999999999", "--dry-run")
	// a slow read, found with db activity and stopped with db kill
	cli, err := mongo.Connect(options.Client().ApplyURI("mongodb://root:rootpw@" + addr + "/?authSource=admin"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = cli.Disconnect(context.Background()) }()
	slow := make(chan error, 1)
	go func() {
		_, err := cli.Database("shop_e2e").Collection("users").Find(context.Background(), bson.D{{Key: "$where", Value: "sleep(30000) || true"}})
		slow <- err
	}()
	var opid string
	for i := 0; i < 50 && opid == ""; i++ {
		time.Sleep(100 * time.Millisecond)
		for _, x := range mustRun(t, "db", "activity", "shop")["sessions"].([]any) {
			if r := x.(map[string]any); strings.Contains(fmt.Sprint(r["query"]), "sleep(30000)") {
				opid = fmt.Sprint(r["pid"])
			}
		}
	}
	if opid == "" {
		t.Fatal("db activity does not show the slow read")
	}
	if d := mustRun(t, "db", "kill", "shop", opid, "--dry-run"); d["would"] != "cancel query" || d["dry_run"] != true {
		t.Errorf("kill --dry-run: %v", d)
	}
	if d := mustRun(t, "db", "kill", "shop", opid); d["done"] != "cancel query" {
		t.Errorf("kill: %v", d)
	}
	select {
	case err := <-slow:
		if err == nil || !strings.Contains(err.Error(), "interrupted") {
			t.Errorf("the read was not stopped: %v", err)
		}
	case <-time.After(15 * time.Second):
		t.Error("the read still runs after db kill")
	}
	mustRun(t, "db", "query", "shop", "--write", "--allow-dangerous", `{"dropDatabase": 1}`)
	mustRun(t, "conn", "edit", "shop", "--protected")
	wantCode(t, "PROTECTED_TARGET", "db", "query", "shop", "--write", `{"insert": "users", "documents": [{"name": "Eve"}]}`)
	mustRun(t, "db", "query", "shop", `{"find": "users"}`) // reading stays allowed
}

// TestMongoRefusals: what komando does not do for MongoDB says so before
// connecting (the address answers nothing).
func TestMongoRefusals(t *testing.T) {
	invHome(t)
	mustRun(t, "conn", "add", "m", "mongodb://app@127.0.0.1:1/shop")
	wantCode(t, "NOT_SUPPORTED", "db", "kill", "m", "42", "--session")
	wantCode(t, "USAGE", "db", "kill", "m", "shard01:42")
	for _, args := range [][]string{
		{"db", "user", "add", "m", "app", "--no-login"},
		{"db", "user", "rm", "m", "app", "--dry-run"},
		{"db", "user", "passwd", "m", "app", "--password-ref", "secret:x"},
		{"db", "grant", "m", "app", "--role", "read"},
		{"db", "revoke", "m", "app", "--role", "read"},
	} {
		if e := wantCode(t, "NOT_SUPPORTED", args...); e == nil || !strings.Contains(e.Hint, "db query") {
			t.Errorf("%v: the hint names db query: %v", args, e)
		}
	}
}
