package dbx

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"sort"
	"strings"
	"time"

	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
	"go.mongodb.org/mongo-driver/v2/mongo/readpref"

	"github.com/sgnd/komando/internal/driver"
	"github.com/sgnd/komando/internal/out"
)

// Mongo is an open MongoDB conn and the database its commands use.
type Mongo struct {
	C  *mongo.Client
	DB string
}

// Close disconnects.
func (m *Mongo) Close() { m.C.Disconnect(context.Background()) }

type dialerFunc DialFunc

func (d dialerFunc) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	return d(ctx, network, addr)
}

// OpenMongo connects to a MongoDB conn: the URL as the driver reads it
// (hosts, replicaSet, authSource, tls), the password from the vault, every
// member through dial when there is one, and ?ca= for its certificate.
func OpenMongo(ctx context.Context, rawURL string, t driver.Target, password string, dial DialFunc, appName string, timeout time.Duration) (*Mongo, error) {
	o := options.Client().ApplyURI(driver.WithoutCA(rawURL))
	if err := o.Validate(); err != nil {
		return nil, out.Usage("invalid mongodb URL: %v", err)
	}
	if o.Auth != nil {
		o.Auth.Password, o.Auth.PasswordSet = password, password != ""
	}
	pool, err := t.RootCAs()
	if err != nil {
		return nil, err
	}
	if pool != nil {
		if o.TLSConfig == nil {
			o.TLSConfig = &tls.Config{MinVersion: tls.VersionTLS12}
		}
		o.TLSConfig.RootCAs, o.TLSConfig.InsecureSkipVerify = pool, false
	}
	if dial != nil {
		o.SetDialer(dialerFunc(dial))
	}
	o.SetAppName(appName).SetServerSelectionTimeout(timeout).SetConnectTimeout(timeout).SetTimeout(timeout)
	c, err := mongo.Connect(o)
	if err != nil {
		return nil, mongoErr(err)
	}
	if err := c.Ping(ctx, readpref.PrimaryPreferred()); err != nil {
		c.Disconnect(context.Background())
		return nil, mongoConnectErr(t, err)
	}
	db := t.Database
	if db == "" {
		db = "admin"
	}
	return &Mongo{C: c, DB: db}, nil
}

func mongoConnectErr(t driver.Target, err error) error {
	msg := err.Error()
	switch {
	case strings.Contains(msg, "auth") || strings.Contains(msg, "Authentication failed"):
		return out.Errf(out.ExitConnect, "DB_AUTH", "check the user in the URL, its authSource, and the --password-ref secret", "%s: %v", t.Where(), err)
	case strings.Contains(msg, "x509") || strings.Contains(msg, "certificate"):
		return out.Errf(out.ExitConnect, "DB_CONNECT", "the server's certificate could not be checked: give the CA that signed it with ?ca=secret:NAME", "cannot connect to %s: %v", t.Where(), err)
	}
	return out.Errf(out.ExitConnect, "DB_CONNECT", "run `komando conn test NAME`; through a bastion, add --via HOST", "cannot connect to %s: %v", t.Where(), err)
}

func mongoErr(err error) error {
	var ce mongo.CommandError
	switch {
	case err == nil:
		return nil
	case errors.As(err, &ce) && (ce.Code == 13 || ce.Code == 18):
		return out.Errf(out.ExitConnect, "DB_PRIVILEGE", "the conn's user lacks the role for this command", "%v", err)
	case errors.As(err, &ce):
		return out.Errf(out.ExitRemote, "DB_ERROR", "check the command: its first key names it, e.g. {\"find\": \"users\", \"filter\": {}}", "%v", err)
	case errors.Is(err, context.DeadlineExceeded):
		return out.Errf(out.ExitTimeout, "TIMEOUT", "raise --timeout", "MongoDB did not answer in time")
	}
	return out.Errf(out.ExitRemote, "DB_ERROR", "run `komando conn test NAME`", "%v", err)
}

// ParseMongoCommand reads a command document written as JSON (MongoDB
// Extended JSON: {"$oid": ...}, {"$date": ...} work). A "$db" key names
// the database for this command and is taken out.
func ParseMongoCommand(text string) (bson.D, string, error) {
	var cmd bson.D
	if err := bson.UnmarshalExtJSON([]byte(strings.TrimSpace(text)), false, &cmd); err != nil {
		return nil, "", out.Errf(out.ExitUsage, "USAGE",
			`write the command as JSON, its first key naming it: '{"find": "users", "filter": {"plan": "pro"}, "limit": 10}'`,
			"not a MongoDB command document: %v", err)
	}
	db := ""
	keep := cmd[:0]
	for _, e := range cmd {
		if e.Key == "$db" {
			db, _ = e.Value.(string)
			continue
		}
		keep = append(keep, e)
	}
	if len(keep) == 0 {
		return nil, "", out.Usage("an empty command: its first key names it, e.g. {\"find\": \"users\"}")
	}
	return keep, db, nil
}

// MongoResult is what one command gave: documents for the commands that
// return a cursor (find, aggregate, listCollections, ...), else the reply.
type MongoResult struct {
	Documents []any  `json:"documents,omitempty"`
	Count     int    `json:"count"`
	Truncated string `json:"truncated,omitempty"` // "documents" (--limit) or "bytes" (--max-output)
	Reply     any    `json:"reply,omitempty"`
}

var cursorCmds = set("find aggregate listCollections listIndexes")

// RunMongo sends cmd to database db and reads at most limit documents
// (0: no limit) and maxBytes of them.
func RunMongo(ctx context.Context, m *Mongo, db string, cmd bson.D, limit, maxBytes int) (*MongoResult, error) {
	d := m.C.Database(firstOf(db, m.DB))
	res := &MongoResult{}
	if !cursorCmds[strings.ToLower(cmd[0].Key)] {
		raw, err := d.RunCommand(ctx, cmd).Raw()
		if err != nil {
			return nil, mongoErr(err)
		}
		res.Reply, res.Count = extJSON(raw), 1
		return res, nil
	}
	cur, err := d.RunCommandCursor(ctx, cmd)
	if err != nil {
		return nil, mongoErr(err)
	}
	defer cur.Close(ctx)
	size := 0
	res.Documents = []any{}
	for cur.Next(ctx) {
		if limit > 0 && len(res.Documents) >= limit {
			res.Truncated = "documents"
			break
		}
		if size += len(cur.Current); maxBytes > 0 && size > maxBytes {
			res.Truncated = "bytes"
			break
		}
		res.Documents = append(res.Documents, extJSON(cur.Current))
	}
	res.Count = len(res.Documents)
	return res, mongoErr(cur.Err())
}

// extJSON is a BSON document as relaxed Extended JSON values: numbers and
// strings plain, ObjectIds and dates as {"$oid"}, {"$date"}.
func extJSON(raw bson.Raw) any {
	b, err := bson.MarshalExtJSON(raw, false, false)
	if err != nil {
		return map[string]any{"$unreadable": err.Error()}
	}
	var v any
	dec := json.NewDecoder(strings.NewReader(string(b)))
	dec.UseNumber()
	if dec.Decode(&v) != nil {
		return string(b)
	}
	return v
}

func firstOf(s ...string) string {
	for _, x := range s {
		if x != "" {
			return x
		}
	}
	return ""
}

// MongoCollection is one collection in `db schema`: its size and indexes,
// and with a name given, the fields of a sample of its documents.
type MongoCollection struct {
	Name      string       `json:"name"`
	Type      string       `json:"type,omitempty"` // view, timeseries
	Documents int64        `json:"documents"`      // an estimate, from the collection's metadata
	Indexes   []string     `json:"indexes,omitempty"`
	Fields    []MongoField `json:"fields,omitempty"`
	Sampled   int          `json:"sampled,omitempty"`
}

// MongoField is a field path seen in sampled documents, with its types and
// how many of them had it.
type MongoField struct {
	Path  string   `json:"path"`
	Types []string `json:"types"`
	Seen  int      `json:"seen"`
}

// MongoSchema lists the collections, or describes the named ones from a
// sample of up to 100 documents each.
func MongoSchema(ctx context.Context, m *Mongo, names []string) ([]MongoCollection, error) {
	d := m.C.Database(m.DB)
	specs, err := d.ListCollectionSpecifications(ctx, bson.D{})
	if err != nil {
		return nil, mongoErr(err)
	}
	want := map[string]bool{}
	for _, n := range names {
		want[n] = true
	}
	res := []MongoCollection{}
	for _, s := range specs {
		if len(names) > 0 && !want[s.Name] {
			continue
		}
		delete(want, s.Name)
		col := MongoCollection{Name: s.Name}
		if s.Type != "collection" {
			col.Type = s.Type
		}
		coll := d.Collection(s.Name)
		col.Documents, _ = coll.EstimatedDocumentCount(ctx)
		if specs, err := coll.Indexes().ListSpecifications(ctx); err == nil {
			for _, ix := range specs {
				col.Indexes = append(col.Indexes, ix.Name)
			}
		}
		if len(names) > 0 {
			if col.Fields, col.Sampled, err = sampleFields(ctx, coll); err != nil {
				return nil, err
			}
		}
		res = append(res, col)
	}
	for n := range want {
		return nil, out.Errf(out.ExitNotFound, "TABLE_NOT_FOUND", "list collections with `komando db schema CONN`", "no collection %q in database %q", n, m.DB)
	}
	sort.Slice(res, func(i, j int) bool { return res[i].Name < res[j].Name })
	return res, nil
}

func sampleFields(ctx context.Context, coll *mongo.Collection) ([]MongoField, int, error) {
	cur, err := coll.Aggregate(ctx, bson.A{bson.D{{Key: "$sample", Value: bson.D{{Key: "size", Value: 100}}}}})
	if err != nil {
		return nil, 0, mongoErr(err)
	}
	defer cur.Close(ctx)
	seen := map[string]map[string]bool{}
	count := map[string]int{}
	n := 0
	for cur.Next(ctx) {
		n++
		walkFields("", cur.Current, seen, count)
	}
	fields := make([]MongoField, 0, len(seen))
	for p, ts := range seen {
		var types []string
		for t := range ts {
			types = append(types, t)
		}
		sort.Strings(types)
		fields = append(fields, MongoField{Path: p, Types: types, Seen: count[p]})
	}
	sort.Slice(fields, func(i, j int) bool { return fields[i].Path < fields[j].Path })
	return fields, n, mongoErr(cur.Err())
}

func walkFields(prefix string, doc bson.Raw, seen map[string]map[string]bool, count map[string]int) {
	elems, err := doc.Elements()
	if err != nil {
		return
	}
	for _, e := range elems {
		p := prefix + e.Key()
		v := e.Value()
		if seen[p] == nil {
			seen[p] = map[string]bool{}
		}
		seen[p][strings.ToLower(v.Type.String())] = true
		count[p]++
		if sub, ok := v.DocumentOK(); ok && len(prefix) < 200 {
			walkFields(p+".", sub, seen, count)
		}
	}
}

// MongoInfo is `db info`: version, role in a replica set, and sizes.
func MongoInfo(ctx context.Context, m *Mongo) (map[string]any, error) {
	admin := m.C.Database("admin")
	var build, hello, stats bson.M
	if err := admin.RunCommand(ctx, bson.D{{Key: "buildInfo", Value: 1}}).Decode(&build); err != nil {
		return nil, mongoErr(err)
	}
	_ = admin.RunCommand(ctx, bson.D{{Key: "hello", Value: 1}}).Decode(&hello)
	_ = m.C.Database(m.DB).RunCommand(ctx, bson.D{{Key: "dbStats", Value: 1}}).Decode(&stats)
	role := "standalone"
	switch {
	case hello["msg"] == "isdbgrid":
		role = "mongos"
	case hello["setName"] != nil && hello["isWritablePrimary"] == true:
		role = "primary"
	case hello["setName"] != nil:
		role = "secondary"
	}
	res := map[string]any{"version": build["version"], "role": role, "database": m.DB}
	if s, ok := hello["setName"].(string); ok {
		res["replica_set"] = s
	}
	for k, v := range map[string]string{"collections": "collections", "objects": "documents", "dataSize": "data_bytes", "storageSize": "storage_bytes", "indexSize": "index_bytes"} {
		if x, ok := stats[k]; ok {
			res[v] = x
		}
	}
	return res, nil
}

// MongoVersion is the server version, for `conn test`.
func MongoVersion(ctx context.Context, m *Mongo) string {
	var build bson.M
	if m.C.Database("admin").RunCommand(ctx, bson.D{{Key: "buildInfo", Value: 1}}).Decode(&build) != nil {
		return ""
	}
	return fmt.Sprint(build["version"])
}
