package cli

import (
	"encoding/json"
	"net"
	"net/netip"
	"net/url"
	"os"
	"regexp"
	"strings"

	"github.com/sgnd/komando/internal/store"
)

// File storage: buckets (S3 and the services that speak it, Google Cloud,
// Azure) and file servers (SFTP, FTP, WebDAV). Each form asks what the
// person sees in their console or hosting panel and builds the conn URL
// from it; a secret is never typed here: --ask-password makes the command
// ask for it hidden, and a Google key stays in its file (--password-ref).

func storageForms() []formKind {
	return []formKind{
		{"S3 bucket", "cloud bucket: Amazon S3, MinIO, Cloudflare R2, Wasabi, DigitalOcean Spaces, Backblaze B2", s3Form},
		{"Google Cloud Storage bucket", "cloud bucket: logs in like gcloud, or with a key file", gcsForm},
		{"Azure Blob Storage container", "cloud bucket: with the account key or a SAS token", azureForm},
		{"SFTP file server", "file server: files over SSH, common on web hosting", sftpForm},
		{"FTP or FTPS file server", "file server: classic FTP hosting", ftpForm},
		{"WebDAV folder", "file server: Nextcloud, ownCloud, a NAS", webdavForm},
		{"Windows share (SMB)", "file server: Windows, Samba, a NAS, Azure Files", smbForm},
	}
}

// What the forms share.

var (
	storeBucketRe    = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{1,221}[a-z0-9]$`)
	storeRegionRe    = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,40}$`)
	storeAccountRe   = regexp.MustCompile(`^[a-z0-9]{3,24}$`)
	storeContainerRe = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{1,61}[a-z0-9]$`)
	storeR2AccountRe = regexp.MustCompile(`^[0-9a-f]{32}$`)
)

// storeBucketQ asks a bucket's name, as the console shows it.
func storeBucketQ(where string) formQ {
	return formQ{key: "bucket", label: "Bucket", ask: "What is the bucket's name?", example: "my-backups",
		help:  "The name shown in " + where + ". Only the name, not a link.",
		check: func(_ *store.State, _ formAnswers, v string) string { return storeBucketProblem(v) }}
}

// storeBucketProblem checks a bucket name: lowercase, no scheme, no folder.
func storeBucketProblem(v string) string {
	switch {
	case strings.Contains(v, "://"):
		return "type only the name, like my-backups, without s3:// or gs://"
	case strings.ContainsAny(v, "/ \t@:"):
		return "type only the bucket's name, like my-backups; a folder inside it is asked under More options"
	case strings.ToLower(v) != v:
		return "bucket names are in small letters; type it as the console shows it"
	case !storeBucketRe.MatchString(v):
		return "a bucket name has 3 to 63 small letters, digits, dots and dashes"
	}
	return ""
}

// storeFolderQ asks the folder the conn starts in: everything komando
// does with it stays inside.
func storeFolderQ(inside string, advanced bool, help, example string) formQ {
	return formQ{key: "folder", label: "Folder", ask: "Start in a folder inside the " + inside + "?",
		optional: true, advanced: advanced, help: help, example: example,
		check: func(_ *store.State, _ formAnswers, v string) string {
			switch {
			case strings.Contains(v, "://"):
				return "type only the folder, like db/backups"
			case strings.Contains("/"+v+"/", "/../"):
				return "a folder cannot contain .."
			case strings.ContainsAny(v, "?#"):
				return "a folder name cannot contain ? or #"
			}
			return ""
		}}
}

// storeFolder is a folder answer as a URL path: "" or "/a/b".
func storeFolder(v string) string {
	if v = strings.Trim(v, "/"); v != "" {
		return "/" + v
	}
	return ""
}

// storeViaQ is "through which server", under More options, asked only
// while komando knows a server or VPN.
func storeViaQ(what string) formQ {
	q := formViaQ(what, true)
	q.when = formHasVia
	return q
}

// storeQuery writes URL options in this order, leaving : and / readable
// (they are allowed in a query) and the empty ones out.
func storeQuery(kv ...string) string {
	var parts []string
	for i := 0; i+1 < len(kv); i += 2 {
		if kv[i+1] == "" {
			continue
		}
		v := strings.NewReplacer("%3A", ":", "%2F", "/").Replace(url.QueryEscape(kv[i+1]))
		parts = append(parts, kv[i]+"="+v)
	}
	return strings.Join(parts, "&")
}

// storeEndpoint is an address as typed, with https:// added when it has
// no scheme.
func storeEndpoint(v string) string {
	if v != "" && !strings.Contains(v, "://") {
		return "https://" + v
	}
	return v
}

// storeEndpointProblem checks a service address. A path is refused unless
// allowed (an emulator's account path, a WebDAV folder).
func storeEndpointProblem(v string, path bool) string {
	u, err := url.Parse(storeEndpoint(v))
	switch {
	case err != nil || u.Hostname() == "" || strings.ContainsAny(v, " \t"):
		return "type the address, like https://files.example.com"
	case u.Scheme != "https" && u.Scheme != "http":
		return "the address starts with https:// (or http:// for a server without encryption)"
	case u.User != nil:
		return "type the address without a user name; the login is asked next"
	case u.RawQuery != "" || u.Fragment != "":
		return "type only the address, without ? or #"
	case !path && strings.Trim(u.Path, "/") != "":
		return "type only the address, without the bucket or a folder, like https://" + u.Host
	}
	if p := u.Port(); p != "" && formPortProblem(nil, nil, p) != "" {
		return "the port after : is a number from 1 to 65535"
	}
	return ""
}

// storeHostQ asks a file server's address, as the hosting panel shows it.
func storeHostQ(scheme, example string) formQ {
	return formQ{key: "host", label: "Address", ask: "What is the server's address?", addr: true, example: example,
		help: "The host name or IP address from your hosting panel, without " + scheme + "://.",
		check: func(_ *store.State, _ formAnswers, v string) string {
			switch {
			case strings.Contains(v, "://"):
				return "type it without " + scheme + "://, like " + example
			case strings.Contains(v, "@"):
				return "type only the address; the user name is the next question"
			case strings.Contains(v, ":") && net.ParseIP(v) == nil:
				return "type only the address; a port other than the usual one goes under More options"
			}
			return formAddressProblem(v)
		}}
}

// storeUserQ asks the login name on a file server.
func storeUserQ(help string) formQ {
	return formQ{key: "user", label: "User", ask: "What is your user name?", example: "deploy", help: help,
		check: storeUserProblem}
}

func storeUserProblem(_ *store.State, _ formAnswers, v string) string {
	if strings.ContainsAny(v, " \t:@/") {
		return "type only the user name, without spaces, : or @"
	}
	return ""
}

// storePortQ asks a file server's port under More options.
func storePortQ(usual, help string, check func(*store.State, formAnswers, string) string) formQ {
	return formQ{key: "port", label: "Port", ask: "Which port does it use?", advanced: true, help: help,
		def: func(*store.State, formAnswers) string { return usual }, check: check}
}

// storeSelfSignedQ asks whether to skip the certificate check.
func storeSelfSignedQ(show func(formAnswers) bool) formQ {
	return formWhen(formMore(formYesNoQ("selfsigned", "Self-signed", "Does the server use a certificate it made itself (self-signed)?",
		"Say yes only if you trust this server and komando test failed because of its certificate.", "no",
		"encrypted, but the certificate is not checked", "the certificate is checked (safer)")), show)
}

// S3.

// s3Providers are the services an S3 conn can point at; all but AWS and
// "another" have an address komando builds from a region or an ID.
func s3Providers(*store.State, formAnswers) []menuRow {
	return []menuRow{
		{label: "Amazon S3 (AWS)", detail: "no address needed", value: "aws"},
		{label: "Cloudflare R2", detail: "needs your Cloudflare account ID", value: "r2"},
		{label: "DigitalOcean Spaces", detail: "needs the region, like nyc3", value: "spaces"},
		{label: "Wasabi", detail: "needs the region, like us-east-1", value: "wasabi"},
		{label: "Backblaze B2", detail: "needs the region, like us-west-004", value: "b2"},
		{label: "MinIO or another S3 service", detail: "you type its address", value: "other"},
	}
}

func s3Form() formSpec {
	is := func(p string) func(formAnswers) bool { return func(a formAnswers) bool { return a["provider"] == p } }
	return formSpec{title: "Add an S3 bucket", qs: []formQ{
		formNameQ("conn", "bucket", "backups"),
		{key: "provider", label: "Service", ask: "Which service is the bucket on?", choices: s3Providers,
			help: "Any service that says it is S3 compatible works: pick the last one when yours is not listed.",
			def:  func(*store.State, formAnswers) string { return "aws" }},
		formWhen(formQ{key: "endpoint", label: "Address", ask: "What is the service's address?", example: "https://minio.example.com:9000",
			help:  "Its web address, from the service's settings or the person who runs it. Only the address: no bucket, no folder.",
			check: func(_ *store.State, _ formAnswers, v string) string { return storeEndpointProblem(v, false) }}, is("other")),
		formWhen(formQ{key: "r2account", label: "Account ID", ask: "What is your Cloudflare account ID?",
			example: "0123456789abcdef0123456789abcdef",
			help:    "In the Cloudflare dashboard: R2, then Account ID on the right. 32 letters and digits.",
			check:   s3R2AccountProblem}, is("r2")),
		s3RegionQ("region", "aws", true, "", "eu-west-1",
			"Shown next to the bucket in the AWS console. Empty lets komando find it."),
		s3RegionQ("spaces_region", "spaces", false, "", "nyc3",
			"The first part of the Space's address: nyc3 for nyc3.digitaloceanspaces.com."),
		s3RegionQ("wasabi_region", "wasabi", false, "us-east-1", "eu-central-1",
			"Shown next to the bucket in the Wasabi console."),
		s3RegionQ("b2_region", "b2", false, "", "us-west-004",
			"In the bucket's details, Endpoint s3.us-west-004.backblazeb2.com: the part between s3. and .backblazeb2.com."),
		s3RegionQ("other_region", "other", true, "", "us-east-1",
			"Empty works for most services. Type it when the service names one."),
		storeBucketQ("the service's console"),
		{key: "login", label: "Login", ask: "How does komando log in?", choices: s3Logins,
			help: "Most people use an access key. Safest is a key that can reach only this bucket.",
			def:  func(*store.State, formAnswers) string { return "key" }},
		formWhen(formQ{key: "keyid", label: "Access key ID", ask: "What is the access key ID?", example: "AKIAIOSFODNN7EXAMPLE",
			help:  "The public half of the key (Backblaze calls it keyID). When the command asks \"Password for\" with the name you gave, paste the secret half; it stays hidden.",
			check: s3KeyIDProblem}, func(a formAnswers) bool { return a["login"] == "key" }),
		formWhen(formQ{key: "profile", label: "AWS profile", ask: "Which AWS profile?", example: "default",
			help:  "A profile name from ~/.aws/config. default is the usual AWS login, SSO too.",
			def:   func(*store.State, formAnswers) string { return "default" },
			check: s3ProfileProblem}, func(a formAnswers) bool { return a["login"] == "profile" && a["provider"] == "aws" }),
		formProtectQ("bucket"),
		storeFolderQ("bucket", true, "Empty for the whole bucket. komando cannot reach files outside this folder.", "db/backups"),
		formWhen(formQ{key: "resolve", label: "Fixed IP", ask: "Connect to a fixed IP address instead of looking up the name?",
			advanced: true, optional: true, example: "203.0.113.10 or 203.0.113.10:9000",
			help:  "Only when the address has no DNS entry or a wrong one. The certificate is still checked against the name.",
			check: s3ResolveProblem}, func(a formAnswers) bool { return a["provider"] != "aws" }),
		storeViaQ("bucket"),
		formGroupQ(), formNotesQ(),
	}, build: s3Build}
}

// s3RegionQ is the region question for one service.
func s3RegionQ(key, provider string, optional bool, def, example, help string) formQ {
	q := formQ{key: key, label: "Region", ask: "Which region is the bucket in?", optional: optional,
		example: example, help: help,
		show: func(a formAnswers) bool { return a["provider"] == provider },
		check: func(_ *store.State, _ formAnswers, v string) string {
			if !storeRegionRe.MatchString(v) {
				return "a region is a short code in small letters, like " + example
			}
			return ""
		}}
	if def != "" {
		q.def = func(*store.State, formAnswers) string { return def }
	}
	return q
}

func s3Logins(_ *store.State, a formAnswers) []menuRow {
	rows := []menuRow{{label: "An access key", detail: "an ID and a secret from the console; the secret is asked hidden", value: "key"}}
	if a["provider"] == "aws" {
		rows = append(rows, menuRow{label: "My AWS login on this computer", detail: "a profile from ~/.aws/config, SSO too", value: "profile"})
	}
	return append(rows, menuRow{label: "No login", detail: "only for a public bucket anyone can read", value: "none"})
}

func s3R2AccountProblem(_ *store.State, _ formAnswers, v string) string {
	if strings.Contains(v, "r2.cloudflarestorage.com") {
		return "type only the ID: the part before .r2.cloudflarestorage.com"
	}
	if !storeR2AccountRe.MatchString(strings.ToLower(v)) {
		return "the account ID is 32 letters and digits, like 0123456789abcdef0123456789abcdef"
	}
	return ""
}

// s3KeyIDProblem catches the secret half typed in the wrong place: it
// would end up in the command line and the conn list.
func s3KeyIDProblem(_ *store.State, _ formAnswers, v string) string {
	switch {
	case strings.ContainsAny(v, "/+") || len(v) >= 40:
		return "this looks like the secret half; type the access key ID here, the secret is asked hidden when the command runs"
	case strings.ContainsAny(v, " \t:@"):
		return "type only the access key ID, without spaces, : or @"
	}
	return ""
}

func s3ProfileProblem(_ *store.State, _ formAnswers, v string) string {
	if strings.ContainsAny(v, " \t=[]") {
		return "type only the profile name, like default or work"
	}
	return ""
}

func s3ResolveProblem(_ *store.State, _ formAnswers, v string) string {
	host := v
	if h, p, err := net.SplitHostPort(v); err == nil {
		if formPortProblem(nil, nil, p) != "" {
			return "the port after : is a number from 1 to 65535"
		}
		host = h
	}
	if _, err := netip.ParseAddr(strings.Trim(host, "[]")); err != nil {
		return "type an IP address, like 203.0.113.10 or 203.0.113.10:9000"
	}
	return ""
}

// s3Where is the address and region the answers point at: no address for
// AWS (komando then uses s3.REGION.amazonaws.com).
func s3Where(a formAnswers) (endpoint, region string) {
	switch a["provider"] {
	case "r2":
		return "https://" + strings.ToLower(a["r2account"]) + ".r2.cloudflarestorage.com", "auto"
	case "spaces": // Spaces signs with us-east-1 whatever the region
		return "https://" + a["spaces_region"] + ".digitaloceanspaces.com", "us-east-1"
	case "wasabi":
		return "https://s3." + a["wasabi_region"] + ".wasabisys.com", a["wasabi_region"]
	case "b2":
		return "https://s3." + a["b2_region"] + ".backblazeb2.com", a["b2_region"]
	case "other":
		return storeEndpoint(a["endpoint"]), a["other_region"]
	}
	return "", a["region"]
}

func s3Build(_ *store.State, a formAnswers) [][]string {
	endpoint, region := s3Where(a)
	u := url.URL{Scheme: "s3", Host: a["bucket"], Path: storeFolder(a["folder"])}
	if a["login"] == "key" {
		u.User = url.User(a["keyid"])
	}
	resolve := ""
	if a["provider"] != "aws" {
		resolve = a["resolve"]
	}
	u.RawQuery = storeQuery("endpoint", endpoint, "region", region, "resolve", resolve)
	cmds := formConnBuild(a, u.String(), a["login"] == "key")
	if a["login"] == "profile" && a["provider"] == "aws" {
		cmds[0] = append(cmds[0], "--option", "aws_profile="+a["profile"])
	}
	return cmds
}

// Google Cloud Storage.

func gcsForm() formSpec {
	return formSpec{title: "Add a Google Cloud Storage bucket", qs: []formQ{
		formNameQ("conn", "bucket", "media"),
		storeBucketQ("the Cloud Storage page of the Google Cloud console"),
		{key: "login", label: "Login", ask: "How does komando log in?",
			help: "A service account is a login for programs; its key is a JSON file you download once.",
			def:  func(*store.State, formAnswers) string { return "gcloud" },
			choices: func(*store.State, formAnswers) []menuRow {
				return []menuRow{
					{label: "Like gcloud on this computer", detail: "after gcloud auth application-default login", value: "gcloud"},
					{label: "With a service account key file", detail: "the JSON file from the console; needed for share links", value: "keyfile"},
				}
			}},
		formWhen(formQ{key: "keyfile", label: "Key file", ask: "Where is the key file?", example: "~/keys/media-sa.json",
			help:  "The JSON file from IAM, Service accounts, Keys. komando reads it each time, so leave it where it is.",
			check: func(_ *store.State, _ formAnswers, v string) string { return gcsKeyProblem(v) }},
			func(a formAnswers) bool { return a["login"] == "keyfile" }),
		formProtectQ("bucket"),
		storeFolderQ("bucket", true, "Empty for the whole bucket. komando cannot reach files outside this folder.", "db/backups"),
		{key: "endpoint", label: "Address", ask: "Use an emulator or another address?", advanced: true, optional: true,
			example: "http://127.0.0.1:4443", help: "Only for a local emulator or testing. Empty uses Google Cloud.",
			check: func(_ *store.State, _ formAnswers, v string) string { return storeEndpointProblem(v, true) }},
		storeViaQ("bucket"),
		formGroupQ(), formNotesQ(),
	}, build: func(_ *store.State, a formAnswers) [][]string {
		u := url.URL{Scheme: "gs", Host: a["bucket"], Path: storeFolder(a["folder"]),
			RawQuery: storeQuery("endpoint", storeEndpoint(a["endpoint"]))}
		cmds := formConnBuild(a, u.String(), false)
		if a["login"] == "keyfile" {
			cmds[0] = append(cmds[0], "--password-ref", "file:"+formAbs(a["keyfile"]))
		}
		return cmds
	}}
}

// gcsKeyProblem checks that a file is a service account key, without
// showing anything from it.
func gcsKeyProblem(v string) string {
	if p := formFileProblem(v); p != "" {
		return p
	}
	if fi, err := os.Stat(expandHome(v)); err == nil && fi.Size() > 1<<20 {
		return "this file is too big for a key; give the .json key file"
	}
	b, err := os.ReadFile(expandHome(v))
	var key struct {
		Type string `json:"type"`
	}
	if err != nil || json.Unmarshal(b, &key) != nil {
		return "this is not a JSON key file; download one from IAM, Service accounts, Keys"
	}
	if key.Type != "service_account" {
		return "this JSON file is not a service account key; download one from IAM, Service accounts, Keys"
	}
	return ""
}

// Azure Blob Storage.

func azureForm() formSpec {
	return formSpec{title: "Add an Azure Blob Storage container", qs: []formQ{
		formNameQ("conn", "container", "files"),
		{key: "account", label: "Account", ask: "What is the storage account's name?", example: "mystorageacct",
			help:  "In the Azure portal, Storage accounts. It is the first part of mystorageacct.blob.core.windows.net.",
			check: azureAccountProblem},
		{key: "container", label: "Container", ask: "What is the container's name?", example: "uploads",
			help: "A container is a top-level folder in the account: Data storage, Containers.",
			check: func(_ *store.State, _ formAnswers, v string) string {
				if !storeContainerRe.MatchString(v) || strings.Contains(v, "--") {
					return "a container name has 3 to 63 small letters, digits and dashes"
				}
				return ""
			}},
		{key: "login", label: "Login", ask: "Which login do you have?",
			help: "Paste either one when the command asks \"Password for\" with the name you gave; it stays hidden. Paste only the key or the token, not a connection string.",
			def:  func(*store.State, formAnswers) string { return "key" },
			choices: func(*store.State, formAnswers) []menuRow {
				return []menuRow{
					{label: "Account key", detail: "key1 or key2 from Security, Access keys; can make share links", value: "key"},
					{label: "SAS token", detail: "from Shared access signature, starts with sv=; a read-only one keeps komando to reading", value: "sas"},
				}
			}},
		formProtectQ("container"),
		storeFolderQ("container", true, "Empty for the whole container. komando cannot reach files outside this folder.", "db/backups"),
		{key: "endpoint", label: "Address", ask: "Use an emulator or another address?", advanced: true, optional: true,
			example: "http://127.0.0.1:10000/devstoreaccount1",
			help:    "Only for Azurite or a government cloud. Empty uses https://ACCOUNT.blob.core.windows.net.",
			check:   func(_ *store.State, _ formAnswers, v string) string { return storeEndpointProblem(v, true) }},
		storeViaQ("container"),
		formGroupQ(), formNotesQ(),
	}, build: func(_ *store.State, a formAnswers) [][]string {
		u := url.URL{Scheme: "azblob", User: url.User(a["account"]), Host: a["container"],
			Path: storeFolder(a["folder"]), RawQuery: storeQuery("endpoint", storeEndpoint(a["endpoint"]))}
		return formConnBuild(a, u.String(), true)
	}}
}

func azureAccountProblem(_ *store.State, _ formAnswers, v string) string {
	switch {
	case strings.ContainsAny(v, "=;"):
		return "this looks like a connection string; type only the account's name"
	case strings.Contains(v, "."):
		return "type only the first part, like mystorageacct for mystorageacct.blob.core.windows.net"
	case !storeAccountRe.MatchString(v):
		return "an account name has 3 to 24 small letters and digits"
	}
	return ""
}

// SFTP.

func sftpForm() formSpec {
	return formSpec{title: "Add an SFTP file server", qs: []formQ{
		formNameQ("conn", "file server", "site"),
		storeHostQ("sftp", "files.example.com"),
		storeUserQ("The login name for this server, from your hosting panel."),
		{key: "login", label: "Login", ask: "How do you log in?",
			help: "Not sure? Pick password: your hosting panel shows it.",
			def: func(st *store.State, a formAnswers) string {
				if serverLoginDefault(st, a) == "usual" {
					return "key"
				}
				return "password"
			},
			choices: func(*store.State, formAnswers) []menuRow {
				return []menuRow{
					{label: "My SSH key", detail: "from ssh-agent or ~/.ssh/id_ed25519, id_ecdsa, id_rsa", value: "key"},
					{label: "A password", detail: "asked hidden when the command runs; saved as a saved password", value: "password"},
				}
			}},
		storeFolderQ("server", false,
			"The folder's full path, like /var/www/uploads. On many hosting accounts / is your home folder. Empty starts at /.",
			"/var/www/uploads"),
		formProtectQ("file server"),
		storePortQ("22", "Almost always 22. Change it only if your hosting gives another number.", formPortProblem),
		storeViaQ("file server"),
		formGroupQ(), formNotesQ(),
	}, build: func(_ *store.State, a formAnswers) [][]string {
		u := url.URL{Scheme: "sftp", User: url.User(a["user"]), Host: formHostPort(a["host"], a["port"], "22"),
			Path: storeFolder(a["folder"])}
		return formConnBuild(a, u.String(), a["login"] == "password")
	}}
}

// FTP and FTPS.

func ftpForm() formSpec {
	plain := func(a formAnswers) bool { return a["encryption"] == "ftp" && a["plain"] == "yes" }
	return formSpec{title: "Add an FTP file server", qs: []formQ{
		formNameQ("conn", "file server", "site"),
		storeHostQ("ftp", "ftp.example.com"),
		storeUserQ("The FTP user from your hosting panel; anonymous for a public server. The password is asked hidden when the command runs."),
		{key: "encryption", label: "Encryption", ask: "Does the server support encryption (FTPS)?",
			help: "Encryption keeps your password and files private on the way. If SFTP is offered too, prefer it.",
			def:  func(*store.State, formAnswers) string { return "ftps" },
			choices: func(*store.State, formAnswers) []menuRow {
				return []menuRow{
					{label: "Yes, or I am not sure", detail: "FTP with encryption (FTPS); try this first", value: "ftps"},
					{label: "No, plain FTP only", detail: "the password and files travel unencrypted", value: "ftp"},
				}
			}},
		formWhen(formQ{key: "plain", label: "Plain FTP", ask: "Send your password and files unencrypted?",
			help: "Anyone on the network between you and the server can read them. Use it only when the server offers nothing else.",
			def:  func(*store.State, formAnswers) string { return "no" },
			choices: func(*store.State, formAnswers) []menuRow {
				return []menuRow{
					{label: "No, use FTPS", detail: "encrypted; komando test shows whether the server supports it", value: "no"},
					{label: "Yes, unencrypted", detail: "plain FTP", value: "yes"},
				}
			}}, func(a formAnswers) bool { return a["encryption"] == "ftp" }),
		storeFolderQ("server", false, "Empty for the folder you land in after login.", "public_html"),
		formProtectQ("file server"),
		storeSelfSignedQ(func(a formAnswers) bool { return !plain(a) }),
		storePortQ("21", "Almost always 21. Port 990 (implicit FTPS) does not work with komando.",
			func(st *store.State, a formAnswers, v string) string {
				if v == "990" && !plain(a) {
					return "990 is implicit FTPS, which komando does not support; most servers offer FTPS on 21 too"
				}
				return formPortProblem(st, a, v)
			}),
		storeViaQ("file server"),
		formGroupQ(), formNotesQ(),
	}, build: func(_ *store.State, a formAnswers) [][]string {
		u := url.URL{Scheme: "ftps", User: url.User(a["user"]), Host: formHostPort(a["host"], a["port"], "21"),
			Path: storeFolder(a["folder"])}
		switch {
		case plain(a):
			u.Scheme, u.RawQuery = "ftp", "insecure=1"
		case a["selfsigned"] == "yes":
			u.RawQuery = "tls=skip-verify"
		}
		return formConnBuild(a, u.String(), true)
	}}
}

// WebDAV.

func webdavForm() formSpec {
	isHTTP := func(a formAnswers) bool { return strings.HasPrefix(strings.ToLower(a["address"]), "http://") }
	return formSpec{title: "Add a WebDAV folder", qs: []formQ{
		formNameQ("conn", "folder", "cloud"),
		{key: "address", label: "Address", ask: "What is the WebDAV address?", addr: true,
			example: "https://cloud.example.com/remote.php/dav/files/alice",
			help:    "The full web address. In Nextcloud: Files, then Files settings at the bottom left, WebDAV.",
			check:   webdavAddressProblem},
		{key: "user", label: "User", ask: "What is your user name?", optional: true, example: "alice",
			help:  "Empty when the server needs no login. The password is asked hidden when the command runs; with Nextcloud use an app password.",
			def:   webdavUserDefault,
			check: storeUserProblem},
		formWhen(formQ{key: "insecure", label: "No encryption", ask: "This address has no encryption (http://). Send the password unencrypted?",
			help: "Anyone on the network between you and the server can read it. Try https:// first.",
			def:  func(*store.State, formAnswers) string { return "no" },
			choices: func(*store.State, formAnswers) []menuRow {
				return []menuRow{
					{label: "No, use https://", detail: "encrypted; komando test shows whether the server supports it", value: "no"},
					{label: "Yes, unencrypted", detail: "plain http://", value: "yes"},
				}
			}}, isHTTP),
		formProtectQ("folder"),
		storeSelfSignedQ(func(a formAnswers) bool { return !isHTTP(a) || a["insecure"] != "yes" }),
		storeViaQ("server"),
		formGroupQ(), formNotesQ(),
	}, build: func(_ *store.State, a formAnswers) [][]string {
		u := url.URL{Scheme: "webdavs"}
		if w, err := url.Parse(storeEndpoint(a["address"])); err == nil {
			u.Host, u.Path = strings.ToLower(w.Host), w.Path
		}
		if a["user"] != "" {
			u.User = url.User(a["user"])
		}
		switch {
		case isHTTP(a) && a["insecure"] == "yes":
			u.Scheme, u.RawQuery = "webdav", "insecure=1"
		case a["selfsigned"] == "yes":
			u.RawQuery = "tls=skip-verify"
		}
		return formConnBuild(a, u.String(), a["user"] != "")
	}}
}

func webdavAddressProblem(_ *store.State, _ formAnswers, v string) string {
	if l := strings.ToLower(v); strings.HasPrefix(l, "webdav") || strings.HasPrefix(l, "dav") {
		return "type the web address, starting with https://"
	}
	return storeEndpointProblem(v, true)
}

// webdavUserDefault is the user in a pasted address, or the one in a
// Nextcloud path (/remote.php/dav/files/alice).
func webdavUserDefault(_ *store.State, a formAnswers) string {
	u, err := url.Parse(storeEndpoint(a["address"]))
	if err != nil {
		return ""
	}
	if n := u.User.Username(); n != "" {
		return n
	}
	if _, rest, ok := strings.Cut(u.Path, "/remote.php/dav/files/"); ok {
		n, _, _ := strings.Cut(rest, "/")
		if un, err := url.PathUnescape(n); err == nil {
			return un
		}
	}
	return ""
}

// SMB.

func smbForm() formSpec {
	return formSpec{title: "Add a Windows share (SMB)", qs: []formQ{
		formNameQ("conn", "share", "team"),
		storeHostQ("smb", "fileserver.corp.lan"),
		{key: "share", label: "Share", ask: "What is the share's name?", example: "team",
			help: `The part after the server in \\fileserver\team, as Explorer shows it. Azure Files: the file share's name.`,
			check: func(_ *store.State, _ formAnswers, v string) string {
				if strings.ContainsAny(v, "/\\ \t:@?#") {
					return "type only the share's name, like team, without \\ or /"
				}
				return ""
			}},
		storeFolderQ("share", false, "Empty for the whole share. komando cannot reach files outside this folder.", "reports/2026"),
		smbUserQ(),
		{key: "domain", label: "Domain", ask: "Which domain is the account in?", optional: true, example: "CORP",
			help: `The part before \ in CORP\alice. Empty for an account of the server itself, or Azure Files.`,
			check: func(_ *store.State, _ formAnswers, v string) string {
				if strings.ContainsAny(v, " \t/\\@:;?#&=") {
					return "type only the domain's name, like CORP"
				}
				return ""
			}},
		formProtectQ("share"),
		storePortQ("445", "Almost always 445. It is often blocked across the internet: then reach the server through a server in its network.", formPortProblem),
		storeViaQ("share"),
		formGroupQ(), formNotesQ(),
	}, build: func(_ *store.State, a formAnswers) [][]string {
		u := url.URL{Scheme: "smb", User: url.User(a["user"]), Host: formHostPort(a["host"], a["port"], "445"),
			Path: "/" + a["share"] + storeFolder(a["folder"]), RawQuery: storeQuery("domain", a["domain"])}
		return formConnBuild(a, u.String(), true)
	}}
}

// smbUserQ is storeUserQ with CORP\alice split: the domain is the next
// question.
func smbUserQ() formQ {
	q := storeUserQ("Your Windows user name, without the domain. Azure Files: the storage account's name. The password is asked hidden when the command runs.")
	q.check = func(st *store.State, a formAnswers, v string) string {
		if d, u, ok := strings.Cut(v, `\`); ok {
			return "type only " + u + " here; the domain " + d + " is the next question"
		}
		return storeUserProblem(st, a, v)
	}
	return q
}

// The storage commands: what a typed command asks for when it is missing.

func init() {
	conn := formArg{ask: "Which file storage?", pick: "storage", help: "A bucket or file server from your list (komando list kind:storage). Add one first with komando storage add."}
	key := func(ask, help, example string) formArg { return formArg{ask: ask, help: help, example: example} }
	addFormHints(map[string]formHint{
		"storage list": {args: []formArg{conn,
			key("Which folder inside it?", "Empty lists the top. A folder ends in /, like db/2026-11/.", "db/")},
			flags: []formFlag{{name: "recursive", ask: "List everything below it too, not only one level?"}}},
		"storage cat": {args: []formArg{conn,
			key("Which file?", "Its name inside the storage, as storage list shows it.", "logs/app.log")},
			flags: []formFlag{{name: "tail", ask: "Show only the last how many lines?", help: "Empty shows the whole file, up to 1 MiB.", example: "50"}}},
		"storage download": {args: []formArg{conn,
			key("Which file (or folder) to download?", "Its name inside the storage, as storage list shows it. A folder ends in /.", "reports/q3.pdf")},
			flags: []formFlag{
				{name: "to", ask: "Where to save it on this computer?", help: "A file or a folder. Empty saves it in the current folder with its own name.", example: "~/Downloads/"},
				{name: "recursive", ask: "Is it a folder? Download everything in it?"}}},
		"storage upload": {args: []formArg{conn,
			key("Which file on this computer?", "Its path; ~/ means your home folder.", "./report.pdf"),
			key("Where in the storage?", "Empty keeps its name, at the top. A folder ends in /, like reports/2026/.", "reports/2026/")}},
		"storage rm": {args: []formArg{conn,
			key("Which files to delete? (several: separate them with spaces)", "Exact names as storage list shows them. Empty to delete a whole folder with the next question. Deleted files cannot be brought back: try it first.", "tmp/old.sql.gz")},
			flags: []formFlag{
				{name: "prefix", ask: "Delete everything in a folder?", help: "Empty when you named the files above. A folder ends in /, like daily/.", example: "daily/"},
				{name: "older-than", ask: "Only files older than?", help: "With a folder: newer ones are kept. Like 30d (days) or 12h (hours).", example: "30d"}}},
		"storage link": {args: []formArg{conn,
			key("Which file to share?", "Its name inside the storage. Anyone with the link can download it until it ends.", "reports/q3.pdf")},
			flags: []formFlag{{name: "expires", ask: "How long should the link work?", help: "Like 30m or 24h; at most 168h (7 days).", def: "1h"}}},
	})
}

// Next: lines for the storage commands.
func init() {
	addFormHints(map[string]formHint{
		"storage list":     {next: []string{"storage cat {} KEY --tail 50", "download {} KEY", "storage list {} FOLDER/ --recursive"}},
		"storage cat":      {next: []string{"download {} KEY"}},
		"storage upload":   {next: []string{"storage list {} FOLDER/", "storage link {} KEY --expires 24h"}},
		"storage download": {next: []string{"storage list {}"}},
		"storage rm":       {next: []string{"storage list {} --recursive"}},
	})
}
