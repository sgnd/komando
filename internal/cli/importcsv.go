package cli

import (
	"bytes"
	"encoding/csv"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"

	"github.com/sgnd/komando/internal/out"
	"github.com/sgnd/komando/internal/store"
)

// `komando import csv FILE` adds many servers from a spreadsheet. The first
// row names the columns; each later row is one server, like one `host add`.
// Every row is checked before anything is written: one bad row stops the
// whole import, so a half-imported fleet never happens.

// csvColumns maps the column names people write to komando's fields.
var csvColumns = map[string]string{
	"name": "name", "server": "name",
	"address": "address", "ip": "address", "host": "address", "hostname": "address",
	"user": "user", "username": "user", "login": "user",
	"port":     "port",
	"key":      "key",
	"identity": "identity", "identity-file": "identity",
	"password-ref": "password-ref",
	"sudo-ref":     "sudo-ref",
	"via":          "via", "jump": "via",
	"groups": "groups", "group": "groups", "role": "groups", "roles": "groups",
	"tags": "tags", "tag": "tags",
	"protected": "protected",
	"notes":     "notes", "note": "notes", "description": "notes",
}

const csvColumnList = "name, address (or ip), user, port, key, identity, password-ref, sudo-ref, via, groups (or role), tags, protected, notes"

// csvHeader turns a column title into its field: "Password Ref" and
// "password_ref" are password-ref.
func csvHeader(h string) string {
	h = strings.ToLower(strings.TrimSpace(h))
	h = strings.NewReplacer("_", "-", " ", "-").Replace(h)
	return csvColumns[h]
}

func importCSV(path string) (*importPlan, error) {
	b, err := readFileOrStdin(path)
	if err != nil {
		return nil, localFileErr("FILE_NOT_FOUND", err, "give the path of a CSV file after `csv`, or - for stdin")
	}
	hosts, err := parseHostsCSV(b)
	if err != nil {
		return nil, err
	}
	p := newPlan()
	p.Hosts, p.Strict, p.OwnRefs = hosts, true, true
	return p, nil
}

func csvErr(format string, a ...any) error {
	return out.Errf(out.ExitUsage, "USAGE", "the first row names the columns: "+csvColumnList+"; see `komando import --help`. Nothing was imported", format, a...)
}

// parseHostsCSV reads the servers in a CSV file and checks every row on
// its own (names, ports, users, references, groups and tags). It reports
// all bad rows at once.
func parseHostsCSV(b []byte) ([]*store.Host, error) {
	b = bytes.TrimPrefix(b, []byte("\xef\xbb\xbf")) // a BOM from Excel
	r := csv.NewReader(bytes.NewReader(b))
	r.Comment = '#'
	r.TrimLeadingSpace = true
	header, err := r.Read()
	if errors.Is(err, io.EOF) {
		return nil, csvErr("the file is empty")
	}
	if err != nil {
		return nil, csvErr("cannot read the CSV: %v", err)
	}
	cols := make([]string, len(header))
	seen := map[string]bool{}
	for i, h := range header {
		f := csvHeader(h)
		switch {
		case strings.EqualFold(strings.TrimSpace(h), "env"):
			return nil, out.Errf(out.ExitUsage, "USAGE", "for prod, staging and the like use a tags column; environment variables for commands are set with `komando host edit TARGET --env KEY=VALUE`",
				"unknown column %q", h)
		case f == "":
			return nil, csvErr("unknown column %q", strings.TrimSpace(h))
		case seen[f]:
			return nil, csvErr("column %q appears twice", f)
		}
		seen[f], cols[i] = true, f
	}
	if !seen["name"] || !seen["address"] {
		return nil, csvErr("the file needs a name and an address column")
	}
	var hosts []*store.Host
	var problems []string
	names := map[string]int{}
	for {
		rec, err := r.Read()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, csvErr("cannot read the CSV: %v", err)
		}
		line, _ := r.FieldPos(0)
		h, err := csvHost(cols, rec)
		label := fmt.Sprintf("line %d", line)
		if h != nil && h.Name != "" {
			label += " (" + h.Name + ")"
		}
		if err != nil {
			problems = append(problems, label+": "+toErr(err).Message)
			continue
		}
		key := strings.ToLower(h.Name)
		if first, dup := names[key]; dup {
			problems = append(problems, fmt.Sprintf("%s: the name is also on line %d", label, first))
			continue
		}
		names[key] = line
		hosts = append(hosts, h)
	}
	if len(problems) > 0 {
		return nil, csvErr("%s: %s", countOf(len(problems), "bad row"), strings.Join(problems, "; "))
	}
	if len(hosts) == 0 {
		return nil, csvErr("no servers in the file, only the header row")
	}
	return hosts, nil
}

// csvHost makes one server from a row and checks it as host add does
// (the inventory checks, like --via, come later in vetImportHosts).
func csvHost(cols, rec []string) (*store.Host, error) {
	h := &store.Host{}
	for i, v := range rec {
		v = strings.TrimSpace(v)
		switch cols[i] {
		case "name":
			h.Name = v
		case "address":
			h.Address = normAddr(v)
		case "user":
			h.User = v
		case "port":
			if v != "" {
				p, err := strconv.Atoi(v)
				if err != nil {
					return h, out.Usage("port %q is not a number", v)
				}
				h.Port = p
			}
		case "key":
			h.Key = v
		case "identity":
			h.Identity = v
		case "password-ref":
			h.PasswordRef = v
		case "sudo-ref":
			h.SudoRef = v
		case "via":
			h.Via = strings.Join(csvList(v), ",")
		case "groups":
			h.Groups = dedupe(csvList(v))
		case "tags":
			h.Tags = dedupe(csvList(v))
		case "protected":
			switch strings.ToLower(v) {
			case "", "no", "n", "false", "0":
			case "yes", "y", "true", "1":
				h.Protected = true
			default:
				return h, out.Usage("protected is yes or no, not %q", v)
			}
		case "notes":
			h.Notes = v
		}
	}
	if h.Name == "" {
		return h, out.Usage("no name")
	}
	if err := checkHostName(h.Name); err != nil {
		return h, err
	}
	if h.Address == "" {
		return h, out.Usage("no address")
	}
	if err := validPort(h.Port); err != nil {
		return h, err
	}
	if h.User != "" {
		if err := validUser(h.User); err != nil {
			return h, err
		}
	}
	if err := checkLabels(h.Groups, h.Tags, nil); err != nil {
		return h, err
	}
	return h, checkHostRefs(h)
}

// csvList splits a cell with several values: "web, prod" or "web;prod" or
// "web prod".
func csvList(v string) []string {
	return strings.FieldsFunc(v, func(r rune) bool { return r == ',' || r == ';' || r == ' ' || r == '\t' })
}
