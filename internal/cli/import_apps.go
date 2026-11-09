package cli

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/sgnd/komando/internal/cloud"
	"github.com/sgnd/komando/internal/driver"
	"github.com/sgnd/komando/internal/out"
	"github.com/sgnd/komando/internal/store"
	"github.com/sgnd/komando/internal/storex"
)

// importFileZilla reads FileZilla's sitemanager.xml. SFTP sites become
// servers (their password goes to the vault); FTP sites are reported until
// komando's storage speaks FTP.
func importFileZilla(path string) (*importPlan, error) {
	b, err := readSource(path)
	if err != nil {
		return nil, err
	}
	var doc struct {
		Servers []fzServer `xml:"Servers>Server"`
		Folders []struct {
			Servers []fzServer `xml:"Server"`
		} `xml:"Servers>Folder"`
	}
	if err := xml.Unmarshal(b, &doc); err != nil {
		return nil, out.Usage("%s: %v", path, err)
	}
	all := doc.Servers
	for _, f := range doc.Folders {
		all = append(all, f.Servers...)
	}
	p := newPlan()
	for _, s := range all {
		label := firstNonEmpty(s.Name, s.Host)
		if s.Protocol != 1 { // 0 FTP, 3/4 FTPS
			p.Notes = append(p.Notes, label+": FTP sites are not imported yet (only SFTP)")
			continue
		}
		name := p.name(label)
		h := &store.Host{Name: name, Address: s.Host, User: s.User}
		if s.Port != 0 && s.Port != 22 {
			h.Port = s.Port
		}
		if pw := s.password(); pw != "" {
			h.PasswordRef = "secret:" + name + "-pass"
			p.Secrets[name+"-pass"] = pw
		}
		if s.Keyfile != "" {
			h.Identity = s.Keyfile
		}
		p.Hosts = append(p.Hosts, h)
	}
	return p, nil
}

type fzServer struct {
	Host     string `xml:"Host"`
	Port     int    `xml:"Port"`
	Protocol int    `xml:"Protocol"`
	User     string `xml:"User"`
	Keyfile  string `xml:"Keyfile"`
	Name     string `xml:"Name"`
	Pass     struct {
		Value    string `xml:",chardata"`
		Encoding string `xml:"encoding,attr"`
	} `xml:"Pass"`
}

func (s fzServer) password() string {
	if s.Pass.Encoding == "base64" {
		b, err := base64.StdEncoding.DecodeString(strings.TrimSpace(s.Pass.Value))
		if err != nil {
			return ""
		}
		return string(b)
	}
	if s.Pass.Encoding == "crypt" {
		return "" // protected by FileZilla's master password
	}
	return s.Pass.Value
}

// importRclone reads rclone.conf. sftp remotes become servers; others are
// reported (rclone passwords are obscured, so a stored one is noted).
func importRclone(path string) (*importPlan, error) {
	b, err := readSource(path)
	if err != nil {
		return nil, err
	}
	p := newPlan()
	sections, order := parseINI(string(b))
	for _, name := range order {
		kv := sections[name]
		switch kv["type"] {
		case "sftp":
			n := p.name(name)
			h := &store.Host{Name: n, Address: kv["host"], User: kv["user"], Identity: expandHome(kv["key_file"])}
			if port, err := strconv.Atoi(kv["port"]); err == nil && port != 22 {
				h.Port = port
			}
			if kv["pass"] != "" {
				p.Notes = append(p.Notes, name+": rclone keeps the password obscured; set it with `komando secret set "+n+"-pass` and `--password-ref`")
			}
			p.Hosts = append(p.Hosts, h)
		case "":
		default:
			p.Notes = append(p.Notes, fmt.Sprintf("%s: rclone type %q is not imported (add it with `komando conn add`)", name, kv["type"]))
		}
	}
	return p, nil
}

// parseINI reads [section] key = value files; keys are lower case.
func parseINI(text string) (map[string]map[string]string, []string) {
	sections := map[string]map[string]string{}
	var order []string
	cur := ""
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		switch {
		case line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";"):
		case strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]"):
			cur = strings.TrimSpace(line[1 : len(line)-1])
			if sections[cur] == nil {
				sections[cur] = map[string]string{}
				order = append(order, cur)
			}
		case cur != "":
			k, v, _ := strings.Cut(line, "=")
			sections[cur][strings.ToLower(strings.TrimSpace(k))] = strings.TrimSpace(v)
		}
	}
	return sections, order
}

// importDBeaver reads DBeaver's data-sources.json. PostgreSQL, MySQL,
// MariaDB, SQL Server, Oracle and SQLite connections become conns (an
// Oracle one by SID gets ?sid=); DBeaver keeps passwords in a
// separate encrypted file, so they are set afterwards.
func importDBeaver(path string) (*importPlan, error) {
	b, err := readSource(path)
	if err != nil {
		return nil, err
	}
	var doc struct {
		Connections map[string]struct {
			Name          string `json:"name"`
			Provider      string `json:"provider"`
			Configuration struct {
				Host     string `json:"host"`
				Port     string `json:"port"`
				Database string `json:"database"`
				User     string `json:"user"`
				// Oracle: "@dbeaver-sid-service@" is SID when database is a SID
				Props map[string]string `json:"provider-properties"`
			} `json:"configuration"`
		} `json:"connections"`
	}
	if err := json.Unmarshal(b, &doc); err != nil {
		return nil, out.Usage("%s: %v", path, err)
	}
	ids := make([]string, 0, len(doc.Connections))
	for id := range doc.Connections {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	p := newPlan()
	for _, id := range ids {
		c := doc.Connections[id]
		cfg := c.Configuration
		scheme := map[string]string{"postgresql": "postgres", "mysql": "mysql", "mariadb": "mysql", "sqlite": "sqlite", "sqlserver": "sqlserver", "mssql": "sqlserver", "oracle": "oracle"}[c.Provider]
		if scheme == "" {
			p.Notes = append(p.Notes, fmt.Sprintf("%s: DBeaver provider %q is not a kind komando knows", c.Name, c.Provider))
			continue
		}
		name := p.name(firstNonEmpty(c.Name, cfg.Database, id))
		var u url.URL
		if scheme == "sqlite" {
			u = url.URL{Scheme: "sqlite", Path: cfg.Database}
		} else {
			host := cfg.Host
			if cfg.Port != "" {
				host += ":" + cfg.Port
			}
			u = url.URL{Scheme: scheme, User: url.User(cfg.User), Host: host, Path: "/" + cfg.Database}
			if scheme == "oracle" && strings.EqualFold(cfg.Props["@dbeaver-sid-service@"], "SID") {
				u.Path, u.RawQuery = "", url.Values{"sid": {cfg.Database}}.Encode()
			}
		}
		n := len(p.Conns)
		if p.addConn(name, u.String(), c.Name); len(p.Conns) > n && scheme != "sqlite" {
			p.NoPassword[p.Conns[n]] = true // the note comes once its name is final (applyImport)
		}
	}
	return p, nil
}

// importAWS reads the profiles in ~/.aws/config (and the credentials file
// next to it) and adds one storage conn per S3 bucket each profile can see.
// The conns use the profile (aws_profile), so no key is copied: komando
// reads the person's current login each time, SSO and roles included.
func importAWS(path string) (*importPlan, error) {
	b, err := readSource(path)
	if err != nil {
		return nil, err
	}
	credsFile := os.Getenv("AWS_SHARED_CREDENTIALS_FILE")
	if credsFile == "" {
		credsFile = filepath.Join(filepath.Dir(path), "credentials")
	}
	var profiles []string
	seen := map[string]bool{}
	add := func(name string) {
		if name != "" && !seen[name] {
			seen[name] = true
			profiles = append(profiles, name)
		}
	}
	_, order := parseINI(string(b))
	for _, s := range order {
		switch {
		case s == "default":
			add("default")
		case strings.HasPrefix(s, "profile "):
			add(strings.TrimSpace(strings.TrimPrefix(s, "profile ")))
		}
	}
	if cb, err := os.ReadFile(credsFile); err == nil { // profiles that only have keys
		_, corder := parseINI(string(cb))
		for _, s := range corder {
			add(s)
		}
	}
	p := newPlan()
	if len(profiles) == 0 {
		p.Notes = append(p.Notes, path+": no AWS profiles")
		return p, nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	for _, prof := range profiles {
		creds, region, endpoint, err := cloud.AWSProfileAccess(ctx, prof, path, credsFile)
		if err != nil {
			if errors.Is(err, cloud.ErrAWSLogin) {
				p.Notes = append(p.Notes, fmt.Sprintf("profile %s: the login has expired; run `komando login aws --profile %s`, then import again", prof, prof))
			} else {
				p.Notes = append(p.Notes, fmt.Sprintf("profile %s: %v", prof, err))
			}
			continue
		}
		buckets, err := storex.ListBuckets(ctx, endpoint, creds.AccessKeyID, creds.SecretAccessKey, creds.SessionToken, firstNonEmpty(region, "us-east-1"))
		if err != nil {
			p.Notes = append(p.Notes, fmt.Sprintf("profile %s: cannot list its buckets: %v", prof, err))
			continue
		}
		if len(buckets) == 0 {
			p.Notes = append(p.Notes, "profile "+prof+": no buckets")
		}
		for _, bk := range buckets {
			q := url.Values{}
			if bk.Region != "" {
				q.Set("region", bk.Region)
			}
			if endpoint != "" {
				q.Set("endpoint", endpoint)
			}
			u := url.URL{Scheme: "s3", Host: bk.Name, RawQuery: q.Encode()}
			if _, err := driver.Parse(u.String()); err != nil {
				p.Notes = append(p.Notes, fmt.Sprintf("profile %s, bucket %s: %s", prof, bk.Name, toErr(err).Message))
				continue
			}
			n := p.name(bk.Name)
			if prof != "default" {
				n = p.name(prof, bk.Name)
			}
			p.Conns = append(p.Conns, &store.Conn{Name: n, URL: u.String(), Options: map[string]string{"aws_profile": prof}})
		}
	}
	return p, nil
}
