package cli

import (
	"cmp"
	"encoding/json"
	"net"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"github.com/sgnd/komando/internal/store"
)

// Container registries.

// registryKind is one registry product: its fixed address (or "" to ask
// it), the name it usually gets, and where its user and token are found.
type registryKind struct {
	id, title, host, name string
	userHelp, tokenHelp   string
}

const (
	regHub   = "dockerhub"
	regGHCR  = "ghcr"
	regLab   = "gitlab"
	regECR   = "ecr"
	regACR   = "acr"
	regGAR   = "gar"
	regOwn   = "own"
	regToken = "ask"
	regVault = "secret"
	regNone  = "none"
)

func registryKinds() []registryKind {
	return []registryKind{
		{id: regHub, title: "Docker Hub", host: "docker.io", name: "dockerhub",
			userHelp:  "Your Docker ID: the name you sign in to hub.docker.com with.",
			tokenHelp: "Make one on hub.docker.com: Account settings, Personal access tokens. Your account password works too, a token is safer."},
		{id: regGHCR, title: "GitHub", host: "ghcr.io", name: "ghcr",
			userHelp: "Your GitHub user name.",
			tokenHelp: "GitHub refuses your account password here. Make a token: Settings, Developer settings, Personal access tokens (classic), " +
				"with read:packages (add write:packages to copy images there, delete:packages to clean up)."},
		{id: regLab, title: "GitLab", name: "gitlab",
			userHelp: "Your GitLab user name, or the user name of a deploy token.",
			tokenHelp: "A personal access token (Preferences, Access tokens) with read_registry, add write_registry to change images; " +
				"or a deploy token from the project's Settings, Repository."},
		{id: regECR, title: "Amazon ECR", name: "ecr"},
		{id: regACR, title: "Azure Container Registry", name: "acr"},
		{id: regGAR, title: "Google Artifact Registry", name: "gar"},
		{id: regOwn, title: "your own registry",
			userHelp:  "The user name you log in to the registry with. Empty when its images are public.",
			tokenHelp: "The password or access token of that user (Harbor: a robot account's secret)."},
	}
}

// registryForms are the registries people use most, then any other one,
// then every login `docker login` saved on this computer at once.
func registryForms() []formKind {
	var kinds []formKind
	details := map[string]string{
		regHub:  "hub.docker.com, with your Docker ID",
		regGHCR: "ghcr.io, with your GitHub user name and a token",
		regLab:  "registry.gitlab.com or your company's GitLab",
		regECR:  "logs in with your AWS profile, no password to type",
		regACR:  "logs in with your Azure login, no password to type",
		regGAR:  "also Container Registry (gcr.io); logs in with your Google login",
		regOwn:  "Harbor, Nexus, a registry:2 container, any other",
	}
	for _, k := range registryKinds() {
		label := k.title
		if k.id == regOwn {
			label = "Your own registry"
		}
		kinds = append(kinds, formKind{label, details[k.id], func() formSpec { return registryForm(k) }})
	}
	return append(kinds, formKind{"From docker login", "every registry you logged in to with docker on this computer", dockerLoginForm})
}

// registryForm asks for one registry: where it is, who logs in, and how
// the token is given (never typed here: the command asks for it hidden).
func registryForm(k registryKind) formSpec {
	is := func(ids ...string) func(formAnswers) bool {
		return func(formAnswers) bool { return strings.Contains(" "+strings.Join(ids, " ")+" ", " "+k.id+" ") }
	}
	notCloud := func(formAnswers) bool { return !registryCloud(k.id) }
	qs := []formQ{
		formWhen(registryHostQ(k), func(formAnswers) bool { return k.host == "" }),
		formWhen(formMore(formQ{key: "port", label: "Port", ask: "Which port does the registry use?",
			help: "Almost always 443 (https). A registry:2 container often uses 5000.",
			def: func(_ *store.State, a formAnswers) string {
				return cmp.Or(registryPort(a["host"]), "443")
			}, check: formPortProblem}), is(regOwn)),
		registryNameQ(k),
		formWhen(formQ{key: "user", label: "User", ask: "What is your user name on this registry?", addr: true,
			help: k.userHelp, example: "octocat", optional: k.id == regOwn,
			check: func(_ *store.State, _ formAnswers, v string) string { return registryUserProblem(v) }}, notCloud),
		formWhen(registryLoginQ(k), notCloud),
		formWhen(registrySecretQ("secret", "Saved token", "Which saved password holds the token?",
			"One you saved with komando secret set. Kept somewhere else? Type where, like env:REGISTRY_TOKEN."),
			func(a formAnswers) bool { return !registryCloud(k.id) && a["login"] == regVault }),
		formWhen(registryProfileQ(), is(regECR)),
		formProtectQ("registry"),
		formWhen(formViaQ("registry", true), is(regOwn, regLab)),
	}
	qs[len(qs)-1].when = formHasVia
	qs = append(qs, registryTLSQs(is(regOwn))...)
	qs = append(qs, formGroupQ(), formNotesQ())
	return formSpec{title: "Add " + k.title, qs: qs, build: func(_ *store.State, a formAnswers) [][]string {
		return registryBuild(k, a)
	}}
}

// registryCloud: a registry komando logs in to with the cloud's own login
// (AWS, Azure, Google), so no user or token is asked.
func registryCloud(id string) bool { return id == regECR || id == regACR || id == regGAR }

func registryHostQ(k registryKind) formQ {
	q := formQ{key: "host", label: "Address", ask: "What is the registry's address?", addr: true,
		help:    "The part before the image name in docker pull, like harbor.example.com in harbor.example.com/shop/api:1.0.",
		example: "harbor.example.com or registry.example.com:5000",
		check:   func(_ *store.State, _ formAnswers, v string) string { return registryHostProblem(k, v) }}
	switch k.id {
	case regLab:
		q.help = "registry.gitlab.com on gitlab.com. A company GitLab shows it on a project's Deploy, Container registry page."
		q.def = func(*store.State, formAnswers) string { return "registry.gitlab.com" }
	case regECR:
		q.help = "In the AWS console: Elastic Container Registry, a repository's URI without the part after the /."
		q.example = "123456789012.dkr.ecr.eu-west-1.amazonaws.com"
	case regACR:
		q.help = "In the Azure portal: the registry's Overview, Login server. komando logs in like az acr login; the login needs the AcrPull role."
		q.example = "myregistry.azurecr.io"
	case regGAR:
		q.help = "The part before the project in an image name: europe-west1-docker.pkg.dev, or gcr.io. The login needs the Artifact Registry Reader role."
		q.example = "europe-west1-docker.pkg.dev"
	}
	return q
}

// registryHost is the address part of what people paste: https:// and an
// image path (ghcr.io/octocat/app) are left out.
func registryHost(v string) string {
	v = strings.TrimSpace(v)
	if i := strings.Index(v, "://"); i >= 0 {
		v = v[i+3:]
	}
	if i := strings.Index(v, "/"); i >= 0 {
		v = v[:i]
	}
	return strings.ToLower(v)
}

// registryPort is the port typed with the address (host:5000), or "".
func registryPort(v string) string {
	if _, p, err := net.SplitHostPort(registryHost(v)); err == nil {
		return p
	}
	return ""
}

// registryHostOnly is the address without its port.
func registryHostOnly(v string) string {
	h := registryHost(v)
	if host, _, err := net.SplitHostPort(h); err == nil {
		return host
	}
	return strings.Trim(h, "[]")
}

func registryHostProblem(k registryKind, v string) string {
	h := registryHostOnly(v)
	switch {
	case strings.Contains(v, "@"):
		return "type only the address; the user name is the next question"
	case h == "" || strings.ContainsAny(h, " \t") || strings.HasPrefix(h, "-"):
		return "type only the address, like harbor.example.com"
	case k.id == regECR && ecrRegion(h) == "":
		return "an Amazon ECR address looks like 123456789012.dkr.ecr.eu-west-1.amazonaws.com"
	case k.id != regECR && ecrRegion(h) != "":
		return "this is an Amazon ECR address: Esc back to the list and pick Amazon ECR, which logs in with your AWS profile"
	case k.id == regACR && acrResource(h) == "":
		return "an Azure Container Registry address looks like myregistry.azurecr.io"
	case k.id == regGAR && !isGoogleRegistry(h):
		return "a Google registry address looks like europe-west1-docker.pkg.dev or gcr.io"
	case registryPort(v) != "" && registryCloud(k.id):
		return "type the address without a port"
	}
	if p := registryPort(v); p != "" {
		return formPortProblem(nil, nil, p)
	}
	return ""
}

func registryNameQ(k registryKind) formQ {
	q := formNameQ("conn", "registry", cmp.Or(k.name, "harbor"))
	q.help = "A short name you type later, like komando registry ls " + cmp.Or(k.name, "harbor") +
		". Letters, digits, dot, dash, underscore."
	q.def = func(st *store.State, a formAnswers) string {
		base := k.name
		if base == "" { // the first part of the address, as import docker names it
			base = strings.Split(registryHostOnly(a["host"]), ".")[0]
		}
		if base == "" || formNameProblem(st, "conn", base) == "" {
			return base
		}
		if validName("conn", base) != nil {
			return ""
		}
		return formFreeName(st, base)
	}
	return q
}

func registryUserProblem(v string) string {
	switch {
	case strings.Contains(v, ":"):
		return "type only the user name; komando asks for the token after this, hidden"
	case strings.ContainsAny(v, " \t@/"):
		return "type only the user name, without spaces, @ or /"
	}
	return ""
}

func registryLoginQ(k registryKind) formQ {
	return formQ{key: "login", label: "Token", ask: "How do you give komando the token (or password)?", help: k.tokenHelp,
		def: func(_ *store.State, a formAnswers) string {
			if k.id == regOwn && a["user"] == "" {
				return regNone
			}
			return regToken
		},
		choices: func(_ *store.State, a formAnswers) []menuRow {
			rows := []menuRow{
				{label: "Type it when the command asks", detail: "hidden; komando keeps it as a saved password", value: regToken},
				{label: "It is saved in komando already", detail: "a secret from komando secret set", value: regVault},
			}
			if k.id == regOwn {
				rows = append(rows, menuRow{label: "No login", detail: "public images only", value: regNone})
			}
			return rows
		}}
}

// registrySecretQ picks a secret from komando's vault, or takes a typed
// reference (secret:NAME, env:VAR, op://...); a pasted token is refused.
func registrySecretQ(key, label, ask, help string) formQ {
	return formQ{key: key, label: label, ask: ask, help: help, free: true, check: cacheSecretProblem,
		choices: func(*store.State, formAnswers) []menuRow {
			var rows []menuRow
			for _, n := range secretNames() {
				rows = append(rows, menuRow{label: n, detail: "saved password", value: n})
			}
			return rows
		}}
}

func registryProfileQ() formQ {
	return formQ{key: "profile", label: "AWS profile", ask: "Which AWS profile should komando log in with?", free: true,
		help: "A profile from ~/.aws/config, the one the aws command uses. komando gets a fresh 12 hour login from it each time.",
		def:  func(*store.State, formAnswers) string { return "default" },
		choices: func(*store.State, formAnswers) []menuRow {
			var rows []menuRow
			for _, p := range registryAWSProfiles() {
				rows = append(rows, menuRow{label: p, value: p})
			}
			return rows
		}}
}

// registryAWSProfiles are the profile names in the AWS config file.
func registryAWSProfiles() []string {
	path := os.Getenv("AWS_CONFIG_FILE")
	if path == "" {
		home, _ := os.UserHomeDir()
		path = filepath.Join(home, ".aws", "config")
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	_, order := parseINI(string(b))
	var names []string
	for _, s := range order {
		if s == "default" {
			names = append(names, s)
		} else if n, ok := strings.CutPrefix(s, "profile "); ok && strings.TrimSpace(n) != "" {
			names = append(names, strings.TrimSpace(n))
		}
	}
	return names
}

// registryTLSQs are the More options of your own registry: how its
// certificate is checked, and an IP to use in place of DNS.
func registryTLSQs(own func(formAnswers) bool) []formQ {
	tls := formMore(formQ{key: "tls", label: "Certificate", ask: "How should komando check the registry's certificate?",
		help: "Leave it checked unless the registry uses a certificate it made itself.",
		def:  func(*store.State, formAnswers) string { return "" },
		choices: func(*store.State, formAnswers) []menuRow {
			return []menuRow{{label: "Check it", detail: "the normal, safe choice", value: ""},
				{label: "Check it with my own CA certificate", detail: "store it first: komando secret set NAME < ca.crt", value: "ca"},
				{label: "Do not check it", detail: "self-signed; anyone in between could read the token", value: "skip-verify"},
				{label: "No encryption (plain http)", detail: "only inside a network you trust", value: "false"}}
		}})
	ca := formMore(registrySecretQ("ca", "CA certificate", "Which saved secret holds the CA certificate?",
		"The CA certificate you stored with komando secret set NAME < ca.crt."))
	ca.check = cacheCAProblem
	resolve := formMore(formQ{key: "resolve", label: "Use IP", ask: "Connect to another IP than DNS gives? (leave empty to use DNS)", optional: true,
		help:    "Only for a registry whose name is not in DNS yet. The certificate is still checked against the name.",
		example: "203.0.113.10 or 203.0.113.10:8443",
		check:   func(_ *store.State, _ formAnswers, v string) string { return registryResolveProblem(v) }})
	return []formQ{formWhen(tls, own), formWhen(ca, func(a formAnswers) bool { return own(a) && a["tls"] == "ca" }), formWhen(resolve, own)}
}

func registryResolveProblem(v string) string {
	host := v
	if h, p, err := net.SplitHostPort(v); err == nil {
		if formPortProblem(nil, nil, p) != "" {
			return "the port after the IP is a number from 1 to 65535"
		}
		host = h
	}
	if _, err := netip.ParseAddr(strings.Trim(host, "[]")); err != nil {
		return "type an IP address, like 203.0.113.10 or 203.0.113.10:8443"
	}
	return ""
}

// registryBuild is conn add with a registry:// URL (no password in it,
// ever), then a test, which logs in to the registry.
func registryBuild(k registryKind, a formAnswers) [][]string {
	host, port := k.host, ""
	if host == "" {
		host, port = registryHostOnly(a["host"]), cmp.Or(a["port"], registryPort(a["host"]))
	}
	u := url.URL{Scheme: "registry", Host: formHostPort(host, port, "443")}
	if a["user"] != "" && !registryCloud(k.id) {
		u.User = url.User(a["user"])
	}
	q := url.Values{}
	if k.id == regOwn {
		switch {
		case a["tls"] == "ca" && a["ca"] != "":
			q.Set("ca", "secret:"+strings.TrimPrefix(a["ca"], "secret:"))
		case a["tls"] == "skip-verify" || a["tls"] == "false":
			q.Set("tls", a["tls"])
		}
		if a["resolve"] != "" {
			q.Set("resolve", a["resolve"])
		}
	}
	u.RawQuery = strings.ReplaceAll(q.Encode(), "%3A", ":") // ca=secret:NAME reads as typed
	args := []string{"conn", "add", a["name"], u.String()}
	switch {
	case registryCloud(k.id) && k.id != regECR: // no secret: the Azure or Google login each time
	case k.id == regECR: // no secret: komando logs in with the AWS profile each time
		if p := a["profile"]; p != "" && p != "default" {
			args = append(args, "--option", "aws_profile="+p)
		}
	case a["login"] == regVault && a["secret"] != "":
		args = append(args, "--password-ref", formSecretRef(a["secret"]))
	case a["login"] == regToken || (a["login"] == "" && a["user"] != ""):
		args = append(args, "--ask-password")
	}
	return [][]string{formFlags(args, a), {"test", a["name"]}}
}

// Every docker login at once.

const dockerConfigDefault = "~/.docker/config.json"

func dockerLoginForm() formSpec {
	return formSpec{title: "Add the registries you use with docker", qs: []formQ{
		{key: "file", label: "File", ask: "Where is docker's config file?",
			help: "docker login keeps your logins there. With Docker Desktop they are in its credential helper; komando asks it.",
			def:  func(*store.State, formAnswers) string { return dockerConfigDefault },
			check: func(_ *store.State, _ formAnswers, v string) string {
				return dockerConfigProblem(v)
			}},
		formGroupQ(),
		formMore(formYesNoQ("overwrite", "Replace", "Replace registries you added before under the same name?",
			"Without it, a name komando knows already is left as it is.", "no",
			"the login from docker replaces the old one", "keep the ones you have")),
	}, build: func(_ *store.State, a formAnswers) [][]string {
		file := cmp.Or(a["file"], dockerConfigDefault)
		args := []string{"import", "docker"}
		if file != dockerConfigDefault {
			args = append(args, formAbs(file))
		}
		target := "kind:registry"
		if a["group"] != "" {
			args = append(args, "-g", a["group"])
			target = "@" + a["group"]
		}
		if a["overwrite"] == "yes" {
			args = append(args, "--overwrite")
		}
		return [][]string{args, {"test", target}}
	}}
}

// dockerConfigProblem checks the file has at least one registry login.
func dockerConfigProblem(v string) string {
	if p := formFileProblem(v); p != "" {
		if v == dockerConfigDefault {
			return "there is no " + v + " here; run docker login first, or pick the registry from the list instead"
		}
		return p
	}
	b, err := os.ReadFile(expandHome(v))
	if err != nil {
		return "komando cannot read " + v
	}
	var cfg struct {
		Auths map[string]json.RawMessage `json:"auths"`
	}
	if json.Unmarshal(b, &cfg) != nil {
		return v + " is not docker's config file (it should be JSON, like ~/.docker/config.json)"
	}
	if len(cfg.Auths) == 0 {
		return "there is no docker login in " + v + "; run docker login first, or pick the registry from the list instead"
	}
	return ""
}

// The registry commands, asked from a menu task.

func init() {
	conn := formArg{ask: "Which registry?", pick: "registry",
		help: "A registry from your list. Add one first with Add, Images (registries)."}
	image := formArg{ask: "Which image?", example: "acme/api:1.4.3",
		help: "The repository and its tag, without the registry's address. komando registry ls shows them."}
	addFormHints(map[string]formHint{
		"registry ls": {args: []formArg{conn, {ask: "Which repository? (leave empty to list them all)", example: "acme/api",
			help: "Empty: every repository. A repository: its tags. Docker Hub cannot list every repository, give one."}}},
		"registry inspect": {args: []formArg{conn, image}},
		"registry rm": {args: []formArg{conn, {ask: "Which image to delete?", example: "acme/api:1.4.3",
			help: "Every tag that points at the same image goes too, and it cannot be undone. komando asks a person first."}}},
		"registry prune": {args: []formArg{conn, {ask: "In which repository?", example: "acme/api",
			help: "Old images of this repository are deleted for good; Try it first shows which. komando asks a person first."}},
			flags: []formFlag{{name: "keep", ask: "Keep how many of the newest images?", example: "10"},
				{name: "older-than", ask: "Or delete only images older than? (leave empty for any age)", example: "30d or 12h"}}},
		"registry copy": {args: []formArg{
			{ask: "Copy which image? Type its registry, a colon, then the image", label: "Copy from", example: "ghcr:acme/api:1.4.3",
				help: "Like ghcr:acme/api:1.4.3: ghcr is the registry's name in your list, acme/api:1.4.3 the image."},
			{ask: "Copy it where? Type the registry, a colon, then the new name", label: "Copy to", example: "harbor:shop/api:1.4.3",
				help: "Like harbor:shop/api:1.4.3. Type only harbor: to keep the same name."}}},
	})
}

// Next: lines for the registry commands.
func init() {
	addFormHints(map[string]formHint{
		"registry ls":      {next: []string{"registry ls {} REPO", "registry inspect {} REPO:TAG", "registry prune {} REPO --keep 10 --dry-run"}},
		"registry inspect": {next: []string{"registry copy {}:REPO:TAG OTHER:", "registry rm {} REPO:TAG --dry-run"}},
		"registry copy":    {next: []string{"registry inspect OTHER REPO:TAG"}},
	})
}
