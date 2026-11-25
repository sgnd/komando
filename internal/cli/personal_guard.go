package cli

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"net"
	"regexp"
	"slices"
	"strings"

	"go.mongodb.org/mongo-driver/v2/bson"

	"github.com/sgnd/komando/internal/dbx"
	"github.com/sgnd/komando/internal/driver"
	"github.com/sgnd/komando/internal/inventory"
	"github.com/sgnd/komando/internal/out"
	"github.com/sgnd/komando/internal/queuex"
	"github.com/sgnd/komando/internal/store"
)

// The ways around hiding personal data from an AI agent that are not a
// matter of output text: a query that renames a hidden column, a dump or
// a link that hands over the raw data, an edit that takes the hiding away.

// maskedColumns are the names in a conn's mask_columns, lower case. They
// are split by spaces (--option takes a comma as the next option).
func maskedColumns(c *store.Conn) []string {
	var names []string
	for _, n := range strings.FieldsFunc(c.Options["mask_columns"], func(r rune) bool { return r == ' ' || r == ',' || r == ';' }) {
		names = append(names, strings.ToLower(n))
	}
	return names
}

// hiddenColumnUse refuses, for an AI agent, a query (SQL, or a MongoDB
// command) that names a column of the conn's mask_columns. The column is
// hidden by its name in the result; a query that names it can rename it
// (name AS customer), compute from it (upper(name)) or ask about it
// (WHERE name LIKE 'A%'), and komando cannot tell which results, or which
// row counts, come from it. The whole text is searched, strings included:
// a query inside a string is a query too. SELECT * names no column, and
// shows this one as [hidden: column].
//
// This stops the ordinary ways and the obvious ones. It is no wall against
// a database that can build the name at run time: for that, give the
// conn's database user no right to read the column.
func hiddenColumnUse(cl *call, c *store.Conn, text string) error {
	if !cl.out.Mask || !cl.out.Personal {
		return nil
	}
	names := maskedColumnsFor(cl, c)
	if len(names) == 0 {
		return nil
	}
	stop := func(what string) error {
		return out.Errf(out.ExitPolicy, "REVEAL_NEEDS_PERSON",
			revealHint(cl, "leave the hidden columns out of the query: `SELECT *` shows them as [hidden: column] beside the other columns; if the user wants you to see them, run it again with --reveal"),
			"the query %s, and conn %s hides columns from AI agents (mask_columns); komando cannot tell which results come from them", what, c.Name)
	}
	if strings.HasPrefix(strings.ToLower(c.URL), "mongodb") {
		decoded, ok := mongoWords(text)
		if !ok {
			return stop("is not plain JSON komando can read")
		}
		if op := mongoWholeDoc.FindString(decoded); op != "" {
			return stop("uses " + op + ", which reads every field of a document")
		}
		text = decoded
	} else if sqlEscapedName.MatchString(text) {
		return stop("names a column in an escaped form (U&\"...\")")
	}
	for _, n := range names {
		word := regexp.MustCompile(`(?i)(^|[^\pL\pN_])` + regexp.QuoteMeta(n) + `($|[^\pL\pN_])`)
		if word.MatchString(text) {
			return stop("names " + n)
		}
	}
	return nil
}

// sqlEscapedName is a PostgreSQL identifier with Unicode escapes, which
// can spell a hidden column with no letter of its name.
var sqlEscapedName = regexp.MustCompile(`(?i)\bU&["']`)

// mongoWholeDoc are MongoDB operators that read every field of a
// document, or run code, whatever the field names.
var mongoWholeDoc = regexp.MustCompile(`\$\$ROOT|\$\$CURRENT|\$objectToArray|\$function|\$where|\$accumulator|\bmapReduce\b|\$getField|\$replaceRoot|\$replaceWith`)

// mongoWords is a MongoDB command as the server reads it: every key and
// string of the document komando sends (an escape in the text,
// "$\u006eame", is the same field; a key given twice is there twice), one
// per line. ok is false when komando cannot read it.
func mongoWords(text string) (string, bool) {
	cmd, _, err := dbx.ParseMongoCommand(text)
	if err != nil {
		return "", false
	}
	var b strings.Builder
	var walk func(any)
	walk = func(v any) {
		switch x := v.(type) {
		case bson.D:
			for _, e := range x {
				b.WriteString(e.Key + "\n")
				walk(e.Value)
			}
		case bson.M:
			for k, e := range x {
				b.WriteString(k + "\n")
				walk(e)
			}
		case bson.A:
			for _, e := range x {
				walk(e)
			}
		case string:
			b.WriteString(x + "\n")
		}
	}
	walk(cmd)
	return b.String(), true
}

// personalTarget reports whether personal data is hidden from AI agents
// on these targets: a conn that asks for it, a server such a conn reaches
// its data through or points at, or what the mask_personal setting covers.
func personalTarget(st *store.State, hosts []*store.Host, conns []*store.Conn) bool {
	for _, c := range conns {
		if maskedConn(c) || maskedTwin(st, c) != nil {
			return true
		}
	}
	for _, h := range hosts {
		if maskingConnOn(st, h) {
			return true
		}
	}
	switch st.Settings.MaskPersonal {
	case "off":
		return false
	case "all":
		return len(hosts)+len(conns) > 0
	}
	for _, h := range hosts {
		if protectedHost(st, h) {
			return true
		}
	}
	for _, c := range conns {
		if protectedConn(st, c) {
			return true
		}
	}
	return false
}

// maskingConnOn reports whether a conn that hides personal data (itself
// or through a twin) has h on its --via path or names h's address or name
// as its own: what an AI agent reads on h (a command's output, a file
// copied from it) can hold that data.
func maskingConnOn(st *store.State, h *store.Host) bool {
	for _, c := range st.Conns {
		if !maskedConn(c) && maskedTwin(st, c) == nil {
			continue
		}
		if slices.ContainsFunc(inventory.ViaChain(c.Via), func(s string) bool { return strings.EqualFold(s, h.Name) }) {
			return true
		}
		if serverNamed(h, connServer(c)) {
			return true
		}
	}
	return false
}

// connServer is the server a conn's URL names (its host, without the
// port), or "" when it names none.
func connServer(c *store.Conn) string {
	t, err := driver.Parse(c.URL)
	if err != nil || t.Address == "" {
		return ""
	}
	if a, _, err := net.SplitHostPort(t.Address); err == nil {
		return a
	}
	return t.Address
}

// serverNamed says whether addr names h, by its address or its name.
func serverNamed(h *store.Host, addr string) bool {
	return addr != "" && (strings.EqualFold(addr, h.Address) || strings.EqualFold(addr, h.Name))
}

// maskingConnsUnmatched are the conns that hide personal data but reach
// no server komando knows: no --via, and a URL whose server matches no
// inventory server by address or name. maskingConnOn cannot follow them
// to a server (doctor lists them). A database file, a bucket, and a
// server on this computer have no server to add.
func maskingConnsUnmatched(st *store.State) map[string]string {
	res := map[string]string{}
	for _, c := range st.SortedConns() {
		if c.Via != "" || !maskedConn(c) && maskedTwin(st, c) == nil {
			continue
		}
		t, err := driver.Parse(c.URL)
		addr := connServer(c)
		if err != nil || t.Kind.File || t.Bucket != "" || addr == "" || addr == "localhost" {
			continue
		}
		if ip := net.ParseIP(addr); ip != nil && ip.IsLoopback() {
			continue
		}
		if !slices.ContainsFunc(st.SortedHosts(), func(h *store.Host) bool { return serverNamed(h, addr) }) {
			res[c.Name] = addr
		}
	}
	return res
}

// guardRawCopy stops an AI agent from taking a copy that cannot be masked
// (a database dump) of a target whose personal data is hidden from it.
// --reveal, which a person allows on the screen, lets it through. Under
// --dry-run the stop is only reported.
func guardRawCopy(cl *call, st *store.State, c *store.Conn, what string) error {
	if !cl.out.Mask || !personalTarget(st, nil, []*store.Conn{c}) || cl.revealOK() {
		return nil
	}
	return cl.policyStop(out.Errf(out.ExitPolicy, "SENSITIVE_FILE",
		revealHint(cl, "read what you need with `komando db query` (personal data shows as [hidden: KIND]); if the user wants the whole copy on this computer, run it again with --reveal"),
		"%s holds every row of %s as it is, and %s hides personal data from AI agents; komando does not write it to this computer for an AI agent", what, c.Name, c.Name))
}

// guardLink: a download link is the raw object for whoever holds it, past
// the masking and the secret-file stop of download and cat. An AI agent
// gets one only with a person's yes (--reveal), and none for an object
// that is a secret by its name.
func guardLink(cl *call, key string) error {
	if !cl.isAgent() {
		return nil
	}
	if err := guardSensitiveCopy(cl, key); err != nil {
		return err
	}
	if cl.revealOK() {
		return nil
	}
	return cl.policyStop(out.Errf(out.ExitPolicy, "SENSITIVE_FILE",
		revealHint(cl, "read it with `komando storage cat` (secrets show as [hidden]); if the user wants a link to hand out, run it again with --reveal"),
		"a link gives %s as it is to whoever holds the link; komando does not make one for an AI agent", key))
}

// lostMasking says what a change of a conn (an edit, a replacement; now
// is nil when it is removed) takes away from the hiding of personal data,
// or "".
func lostMasking(old, now *store.Conn) string {
	if old == nil {
		return ""
	}
	if now == nil {
		now = &store.Conn{Name: old.Name}
	}
	var lost []string
	if strings.EqualFold(old.Options["mask_personal"], "on") && !strings.EqualFold(now.Options["mask_personal"], "on") {
		lost = append(lost, "mask_personal no longer on")
	}
	kept := map[string]bool{}
	for _, n := range maskedColumns(now) {
		kept[n] = true
	}
	var gone []string
	for _, n := range maskedColumns(old) {
		if !kept[n] {
			gone = append(gone, n)
		}
	}
	if len(gone) > 0 {
		lost = append(lost, "the hidden columns "+strings.Join(gone, ", ")+" no longer in mask_columns")
	}
	if len(lost) == 0 {
		return ""
	}
	return "showing AI agents personal data of conn " + now.Name + " (" + strings.Join(lost, "; ") + ")"
}

// guardLostMasking: what a person chose to hide from AI agents stays
// hidden until a person says otherwise, as for the mask_personal setting.
// It covers conn edit, conn add (--overwrite) and conn rm (now nil), and
// checks how the new settings write the options (checkMaskOptions).
func guardLostMasking(cl *call, old, now *store.Conn) error {
	if now != nil {
		if err := checkMaskOptions(now); err != nil {
			return err
		}
	}
	if lost := lostMasking(old, now); lost != "" && cl.isAgent() {
		return guardSafety(cl, lost)
	}
	return nil
}

// maskedConn reports whether a conn asks for personal data hiding itself.
func maskedConn(c *store.Conn) bool {
	return strings.EqualFold(c.Options["mask_personal"], "on") || c.Options["mask_columns"] != ""
}

// maskedTwin is another conn to the same resource (database, bucket,
// file) that asks for personal data hiding, or nil: the hiding follows the
// resource, so a second name for it hides as much.
func maskedTwin(st *store.State, c *store.Conn) *store.Conn {
	k := maskKey(c)
	if k == "" {
		return nil
	}
	for _, o := range st.SortedConns() {
		if o.Name != c.Name && maskedConn(o) && maskKey(o) == k {
			return o
		}
	}
	return nil
}

// maskKey is the resource a conn reaches for masking: the server
// (connAddrKey) and, for PostgreSQL only, the database on it. A
// PostgreSQL conn reads only its own database; MySQL, SQL Server,
// ClickHouse, MongoDB and the others read every database of the server
// from any conn to it (select name from shop.users), so there the hiding
// covers the whole server.
func maskKey(c *store.Conn) string {
	k := connAddrKey(c)
	if k == "" {
		return ""
	}
	if t, err := driver.Parse(c.URL); err == nil && t.Kind.Name == "postgres" && t.Database != "" {
		k += " db " + strings.ToLower(t.Database)
	}
	return k
}

// noteTwinMask records, for each conn of the command, the mask_columns of
// the other conns to the same resource.
func noteTwinMask(cl *call, st *store.State, conns []*store.Conn) {
	for _, c := range conns {
		k := maskKey(c)
		if k == "" {
			continue
		}
		for _, o := range st.SortedConns() {
			if o.Name != c.Name && maskKey(o) == k {
				if cl.twinMask == nil {
					cl.twinMask = map[string][]string{}
				}
				cl.twinMask[c.Name] = append(cl.twinMask[c.Name], maskedColumns(o)...)
			}
		}
	}
}

// maskedColumnsFor are the columns hidden on c in this command: its own
// mask_columns and those of the other conns to the same resource.
func maskedColumnsFor(cl *call, c *store.Conn) []string {
	return append(maskedColumns(c), cl.twinMask[c.Name]...)
}

// maskCell hides, in one query cell, a binary value that holds something
// the output hides, and the fields named in names inside a cell that
// holds JSON.
func maskCell(cl *call, v any, names map[string]bool, label string) any {
	switch x := v.(type) {
	case map[string]string:
		if b64, ok := x["base64"]; ok && len(x) == 1 {
			if raw, err := base64.StdEncoding.DecodeString(b64); err == nil && cl.out.BinaryHidden(raw) {
				return out.Hidden
			}
			return v
		}
	case string:
		t := strings.TrimSpace(x)
		if len(names) == 0 || t == "" || (t[0] != '{' && t[0] != '[') || !json.Valid([]byte(t)) {
			return v
		}
		return string(out.MaskJSONFields([]byte(t), names, label))
	}
	if len(names) == 0 {
		return v
	}
	switch v.(type) {
	case map[string]any, []any, map[string]string:
		b, err := json.Marshal(v)
		if err != nil {
			return out.Hidden
		}
		dec := json.NewDecoder(bytes.NewReader(out.MaskJSONFields(b, names, label)))
		dec.UseNumber() // numbers stay exact
		var back any
		if dec.Decode(&back) != nil {
			return out.Hidden
		}
		return back
	}
	return v
}

// agentStdout is what an AI agent is shown of an object it reads on
// stdout: text with its secrets hidden. Binary content cannot be shown
// that way, so it is checked for what the printer hides and refused, as
// a download to a file is.
func agentStdout(cl *call, key string, b []byte) (string, error) {
	if bytes.IndexByte(b, 0) < 0 {
		return cl.out.Redact(string(b)), nil
	}
	if cl.out.BinaryHidden(b) {
		return "", out.Errf(out.ExitPolicy, "SENSITIVE_FILE",
			revealHint(cl, "it is binary, so what it holds cannot be shown as [hidden]; if the user wants to see it, run it again with --reveal"),
			"%s holds a secret or personal data komando hides from AI agents, in binary form", key)
	}
	return string(b), nil
}

// maskMongo hides, in a MongoDB result for an AI agent, what the output
// hides (so -o text shows the same as JSON) and the fields named in the
// conn's mask_columns, at any depth.
func maskMongo(cl *call, c *store.Conn, res *dbx.MongoResult) {
	if !cl.out.Mask || res == nil {
		return
	}
	names := map[string]bool{}
	if cl.out.Personal {
		for _, n := range maskedColumnsFor(cl, c) {
			names[n] = true
		}
	}
	mask := func(v any) any {
		b, err := json.Marshal(v)
		if err != nil {
			return out.Hidden
		}
		b = cl.out.RedactJSON(b)
		if len(names) > 0 {
			b = out.MaskJSONFields(b, names, out.PersonalLabel(out.PersonalColumn))
		}
		return json.RawMessage(b)
	}
	for i, d := range res.Documents {
		res.Documents[i] = mask(d)
	}
	if res.Reply != nil {
		res.Reply = mask(res.Reply)
	}
}

// hideBinaryValue is v, or [hidden] when v is base64 (with or without
// SQS's "base64:" in front) of bytes that hold something the output hides.
func hideBinaryValue(cl *call, v string) string {
	b64 := strings.TrimPrefix(v, "base64:")
	if len(b64) < 4 || len(b64)%4 != 0 {
		return v
	}
	if raw, err := base64.StdEncoding.DecodeString(b64); err == nil && cl.out.BinaryHidden(raw) {
		return out.Hidden
	}
	return v
}

// hideBinaryMessages hides the value of each queue message that is shown
// as base64 and holds something the printer hides.
// Keys and headers that are not text are base64 too, without a mark.
func hideBinaryMessages(cl *call, msgs []queuex.Received) {
	for i := range msgs {
		m := &msgs[i]
		if m.Encoding == "base64" {
			if v := hideBinaryValue(cl, m.Value); v != m.Value {
				m.Value, m.Encoding = v, ""
			}
		}
		if m.KafkaRecord != nil && m.Key != nil {
			k := hideBinaryValue(cl, *m.Key)
			m.Key = &k
		}
		for h, v := range m.Headers {
			m.Headers[h] = hideBinaryValue(cl, v)
		}
	}
}

// checkMaskOptions: mask_columns takes plain column names, which hide the
// column whatever table it is in (a table in front, users.name, would
// match no result column and hide nothing), and the two options are
// written in lower case (Mask_Columns would be kept and do nothing).
func checkMaskOptions(c *store.Conn) error {
	for k := range c.Options {
		if l := strings.ToLower(k); (l == "mask_columns" || l == "mask_personal") && k != l {
			return out.Usage("write the option as %s, in lower case", l)
		}
	}
	for _, n := range maskedColumns(c) {
		if strings.Contains(n, ".") {
			return out.Usage("mask_columns takes column names without the table (%s, not %s): a name hides that column in every table of the conn", n[strings.LastIndexByte(n, '.')+1:], n)
		}
	}
	return nil
}

// personalBinary stops an AI agent's copy of a file komando cannot show
// with personal data hidden (binary, or larger than it reads whole: n
// bytes, b the start) from a target whose personal data is hidden from
// it, when the file may hold some: a binary file whose text holds personal
// data or a secret, or any file too large to check.
func personalBinary(cl *call, b []byte, n int64) error {
	if !cl.out.Mask || !cl.out.Personal || cl.revealOK() {
		return nil
	}
	if n <= hiddenScanMax && !cl.out.BinaryHidden(b) {
		return nil
	}
	return out.Errf(out.ExitPolicy, "SENSITIVE_FILE",
		revealHint(cl, "it is binary or larger than komando reads whole, so its personal data cannot be shown as [hidden]; if the user wants the real file on this computer, re-run with --reveal"),
		"the file may hold personal data, which this target hides from AI agents; komando does not copy it to this computer for an AI agent")
}
