package cli

import (
	"regexp"
	"strings"
)

// A command with subcommands (systemctl, docker, ip ...) passes --read-only
// only in a form komando knows reads. The lists say what reads, not what
// writes: a form that is not here is refused, so a subcommand komando has
// never heard of (systemctl soft-reboot, ip netns exec) cannot slip by.

// subRule is what one such command may be given.
type subRule struct {
	// options the command may get: "-n" is a flag, "-n=" takes a value
	// (attached, or the next word). A short flag also passes in a group
	// (-an). An option that is not here is refused.
	options string
	// words: options are whole words (ip -brief), never a group of letters
	words bool
	// free: once the form is complete the rest is not looked at (docker
	// and kubectl read each subcommand's own flags after it)
	free bool
	// first: the first word must match it, and is not checked further
	// (rpm -qa, pacman -Qi: the mode is a letter group of its own)
	first *regexp.Regexp
	// forms that read: the words that are not options, in order. "*" is
	// any one word; a last "*" is any words, or none. "" is the command
	// with no such word.
	forms []string
}

var readSubs = map[string]*subRule{
	"systemctl": {
		options: `--no-pager --user --system --all -a -l --full --failed --type= -t= --state= --property= -p= -P= --value
			-n= --lines= -o= --output= --plain --no-legend --quiet -q --recursive -r --reverse --after --before --version
			--with-dependencies --show-types`,
		forms: []string{"", "status *", "show *", "cat *", "list-units *", "list-unit-files *", "list-timers *",
			"list-sockets *", "list-dependencies *", "list-jobs *", "list-machines", "is-active *", "is-enabled *",
			"is-failed *", "is-system-running", "get-default", "show-environment"},
	},
	"service":     {options: `--status-all --version`, forms: []string{"", "* status"}},
	"hostnamectl": {options: `--static --transient --pretty --json= --no-pager --version`, forms: []string{"", "status"}},
	"timedatectl": {
		options: `--no-pager --all -a -p= --property= --value --version`,
		forms:   []string{"", "status", "show *", "list-timezones", "timesync-status", "show-timesync *"},
	},
	"ip": {
		words: true,
		options: `-4 -6 -o -s -d -j -p -br -c -h -r -V -oneline -stats -statistics -details -json -pretty -brief
			-color -human -resolve -family= -f=`,
		forms: []string{"", "addr", "addr show *", "addr list *", "address", "address show *", "address list *",
			"a", "a show *", "a list *", "link", "link show *", "link list *", "route", "route show *", "route list *",
			"route get *", "r", "neigh", "neigh show *", "neighbor", "neighbor show *", "neighbour", "neighbour show *",
			"rule", "rule show *", "rule list *", "netns", "netns list", "maddr", "maddr show *"},
	},
	"iptables":  {options: `-L -S -n -v -x -t= -w= --list --list-rules --numeric --verbose --exact --table= --line-numbers --wait= --version -V`, forms: []string{"*"}},
	"ip6tables": {options: `-L -S -n -v -x -t= -w= --list --list-rules --numeric --verbose --exact --table= --line-numbers --wait= --version -V`, forms: []string{"*"}},
	"ufw":       {options: `--version`, forms: []string{"", "status", "status verbose", "status numbered", "show *", "version", "app list", "app info *"}},
	"nft":       {options: `-a -n -s -j --handle --numeric --stateless --json --version -v`, forms: []string{"list ruleset", "list tables *", "list table *", "list chain *", "list sets *", "list set *"}},
	"sysctl":    {options: `-a -A -X -n -e -N -b -q --all --values --names --ignore --binary --quiet --version -V -r= --pattern=`, forms: []string{"*"}},

	"apt":        {options: `--upgradable --installed --all-versions -a -q -qq --names-only -n -v --version`, forms: []string{"", "list *", "show *", "search *", "policy *", "depends *", "rdepends *"}},
	"apt-get":    {options: `-v --version`, forms: []string{""}},
	"apt-cache":  {options: `-q -n --names-only --installed --no-all-versions -a --all-versions -i --important`, forms: []string{"policy *", "show *", "search *", "depends *", "rdepends *", "madison *", "pkgnames *", "showpkg *", "showsrc *", "stats"}},
	"dpkg":       {options: `-l -L -s -S -p -C -V --list --listfiles --status --search --print-avail --print-architecture --get-selections --audit --verify --version --compare-versions`, forms: []string{"*"}},
	"dpkg-query": {options: `-l -L -s -S -W -p -f= --list --listfiles --status --search --show --showformat= --print-avail --control-list --control-show --version --no-pager`, forms: []string{"*"}},
	"rpm": {
		first: regexp.MustCompile(`^(-q[ailcdfRpv]*|--query|-V[a-z]*|--verify|--version)$`),
		options: `-a -i -l -c -d -f -R -p -v --all --info --list --requires --provides --changelog --scripts --last
			--whatprovides --whatrequires --file --queryformat= --qf= --configfiles --docfiles`,
		forms: []string{"*"},
	},
	"pacman": {first: regexp.MustCompile(`^(-Q[a-z]*|-Ss|-Si|-Sl|-V|--version)$`), options: `-q --quiet`, forms: []string{"*"}},
	"dnf": {options: `-q --quiet -C --cacheonly --installed --available --upgrades --all --showduplicates -v --version`,
		forms: []string{"", "list *", "info *", "search *", "repolist *", "provides *", "repoquery *", "deplist *", "history", "history list *", "history info *"}},
	"yum": {options: `-q --quiet -C --cacheonly --installed --available --upgrades --all --showduplicates -v --version`,
		forms: []string{"", "list *", "info *", "search *", "repolist *", "provides *", "repoquery *", "deplist *", "history", "history list *", "history info *"}},
	"apk":    {options: `-v -q -a -e -L -d -s -r -R -I -u -W= --installed --upgradable --available --who-owns= --contents --rdepends --depends --no-network --version`, forms: []string{"", "info *", "list *", "search *", "version *", "policy *", "stats"}},
	"zypper": {options: `-n --non-interactive -q --quiet -i --installed-only -u -s --details -t= --type= --no-refresh -d --version -V`, forms: []string{"", "search *", "se *", "info *", "if *", "packages *", "pa *", "patches *", "lr *", "repos *"}},
	"pip":    {options: `-o --outdated --format= -v --user --local -l --not-required --disable-pip-version-check --no-color -V --version`, forms: []string{"", "list *", "show *", "freeze *", "check"}},
	"pip3":   {options: `-o --outdated --format= -v --user --local -l --not-required --disable-pip-version-check --no-color -V --version`, forms: []string{"", "list *", "show *", "freeze *", "check"}},
	"npm":    {options: `-g --global --depth= --json --long -l --all -a --parseable -p --omit= --no-color -v --version`, forms: []string{"", "ls *", "list *", "ll *", "root", "prefix", "version"}},

	"docker":  {free: true, options: `-v --version`, forms: dockerReads},
	"podman":  {free: true, options: `-v --version`, forms: dockerReads},
	"kubectl": {free: true, options: `-n= --namespace= --context= -A --all-namespaces --request-timeout=`, forms: []string{"get *", "describe *", "logs *", "top *", "explain *", "api-resources *", "api-versions", "version *", "events *", "config view *", "config get-contexts *", "config current-context", "auth can-i *", "auth whoami", "rollout status *", "rollout history *", "cluster-info"}},
}

var dockerReads = []string{"", "ps *", "logs *", "inspect *", "images *", "stats *", "top *", "port *", "diff *", "history *",
	"events *", "info", "version *", "system df *", "system info", "network ls *", "network inspect *", "volume ls *",
	"volume inspect *", "image ls *", "image inspect *", "image history *", "container ls *", "container inspect *",
	"container logs *", "container top *", "container port *", "container stats *", "container diff *",
	"compose ps *", "compose logs *", "compose ls *", "compose images *", "compose top *", "compose version",
	"node ls *", "node inspect *", "node ps *", "service ls *", "service ps *", "service logs *", "service inspect *",
	"stack ls *", "stack ps *", "stack services *", "context ls *", "context show", "config ls *", "secret ls *", "plugin ls *"}

// option reports whether a is an option the rule knows, and whether the
// next word is its value.
func (r *subRule) option(a string) (known, valueNext bool) {
	opts := strings.Fields(r.options)
	has := func(o string) bool {
		for _, x := range opts {
			if x == o {
				return true
			}
		}
		return false
	}
	name, _, attached := strings.Cut(a, "=")
	switch {
	case has(a) && !attached:
		return true, false
	case has(name + "="):
		return true, !attached
	case strings.HasPrefix(a, "--") || r.words:
		return false, false
	}
	for j := 1; j < len(a); j++ { // a group of letters: -an, -n5, -ptcp
		l := "-" + string(a[j])
		switch {
		case has(l):
		case has(l + "="):
			return true, j == len(a)-1
		default:
			return false, false
		}
	}
	return true, false
}

// formMatch says how pos (the words so far that are not options) fits the
// forms: done, when a form ending in "*" is complete; exact, when pos is a
// whole form.
func (r *subRule) formMatch(pos []string) (done, exact bool) {
	for _, f := range r.forms {
		words := strings.Fields(f)
		open := len(words) > 0 && words[len(words)-1] == "*"
		if open {
			words = words[:len(words)-1]
		}
		if len(words) != len(pos) {
			continue
		}
		same := true
		for i, w := range words {
			same = same && (w == "*" || w == pos[i])
		}
		if same && open {
			done = true
		}
		if same && !open {
			exact = true
		}
	}
	return done, exact
}

// subRead returns why `cmd args` is not a form komando knows reads, or "".
func subRead(cmd string, args []string, r *subRule) string {
	if r.first != nil {
		if len(args) == 0 || !r.first.MatchString(args[0]) {
			return notReadForm(cmd, args)
		}
		args = args[1:]
	}
	all := args
	var pos []string
	done, _ := r.formMatch(pos)
	if done && r.free {
		return ""
	}
	for i := 0; i < len(args); i++ {
		a := args[i]
		if len(a) > 1 && a[0] == '-' {
			known, valueNext := r.option(a)
			if !known || a == "--" {
				return notReadForm(cmd, all)
			}
			if valueNext {
				i++
			}
			continue
		}
		if done {
			continue // the words after a complete form: names, filters
		}
		pos = append(pos, a)
		if done, _ = r.formMatch(pos); done && r.free {
			return ""
		}
	}
	if _, exact := r.formMatch(pos); done || exact {
		return ""
	}
	return notReadForm(cmd, all)
}

// notReadForm is the refusal for a command line that is not a read form.
func notReadForm(cmd string, args []string) string {
	line := strings.TrimSpace(cmd + " " + strings.Join(args, " "))
	if len(line) > 60 {
		line = line[:60] + "..."
	}
	return line + " (not a form komando knows only reads)"
}

// readLongs are the long options (--name) of a command whose options
// decide whether it writes. Such a command passes only with the long
// options here, by their full name: getopt takes any unique start of a
// name (sed --in is --in-place, sort --o=F is --output=F), so a name
// komando does not know may be a start of one that writes.
var readLongs = map[string]map[string]bool{
	"sed":  set(`--quiet --silent --expression --regexp-extended --null-data --separate --unbuffered --line-length --posix --debug --sandbox --version --help`),
	"sort": set(`--reverse --numeric-sort --human-numeric-sort --general-numeric-sort --version-sort --month-sort --key --field-separator --unique --ignore-case --stable --check --ignore-leading-blanks --dictionary-order --zero-terminated --merge --version --help`),
	"uniq": set(`--count --repeated --unique --ignore-case --skip-fields --skip-chars --check-chars --all-repeated --group --zero-terminated --version --help`),
	"date": set(`--utc --universal --date --reference --file --iso-8601 --rfc-3339 --rfc-email --rfc-2822 --debug --version --help`),
	"journalctl": set(`--unit --user-unit --no-pager --since --until --lines --follow --reverse --boot --dmesg --priority --output --grep
		--case-sensitive --identifier --catalog --all --full --no-full --no-tail --quiet --utc --system --user --list-boots
		--disk-usage --fields --field --output-fields --no-hostname --pager-end --merge --facility --version --help`),
	"dmesg": set(`--ctime --level --facility --human --kernel --userspace --notime --time-format --nopager --decode --follow
		--follow-new --raw --reltime --show-delta --color --json --since --until --buffer-size --version --help`),
	"tar": set(`--list --create --diff --compare --file --gzip --gunzip --bzip2 --xz --zstd --lzma --verbose --directory --wildcards
		--no-wildcards --numeric-owner --utc --full-time --exclude --null --no-recursion --totals --anchored --ignore-case
		--strip-components --occurrence --files-from --exclude-from --absolute-names --dereference --force-local --version --help`),
	"gzip": compressLongs, "gunzip": compressLongs, "bzip2": compressLongs, "bunzip2": compressLongs, "xz": compressLongs,
	"unxz": compressLongs, "zstd": compressLongs, "unzstd": compressLongs, "lzma": compressLongs, "unlzma": compressLongs,
	"pigz":      compressLongs,
	"redis-cli": redisLongs, "valkey-cli": redisLongs, "keydb-cli": redisLongs,
	"yq":       set(`--raw-output --yaml-output --null-input --prettyPrint --no-colors --colors --output-format --input-format --indent --unwrapScalar --exit-status --no-doc --version --help`),
	"xmllint":  set(`--xpath --format --noout --html --recover --nonet --noblanks --nowarning --huge --schema --valid --version`),
	"fuser":    set(`--verbose --mount --user --ipv4 --ipv6 --version`),
	"ss":       set(`--numeric --listening --tcp --udp --processes --all --extended --memory --info --ipv4 --ipv6 --family --summary --no-header --oneline --resolve --options --unix --raw --packet --sctp --query --socket --kernel --version --help`),
	"arp":      set(`--numeric --verbose --all --device --hw-type --use-device --version --help`),
	"sar":      set(`--human --pretty --dev --iface --fs`),
	"hostname": set(`--fqdn --short --domain --ip-address --all-ip-addresses --all-fqdns --alias --long --nis --yp --version --help`),
	"file":     set(`--brief --mime --mime-type --mime-encoding --dereference --no-dereference --uncompress --special-files --keep-going --print0 --separator --version --help`),
	// these take no start of a name, or their own check reads every option
	"rg": nil, "firewall-cmd": nil,
}

var (
	compressLongs = set(`--stdout --to-stdout --list --test --decompress --uncompress --keep --verbose --quiet --fast --best --version --help`)
	redisLongs    = set(`--no-auth-warning --raw --no-raw --tls --insecure --user --pass --cacert --cacertdir --cert --key --sni --csv --json --resp2 --resp3 --scan --pattern --count --bigkeys --memkeys --hotkeys --cluster --version --help`)
)

// longOptionUnknown returns the first long option of args that is not in
// cmd's readLongs, or "". A command with no entry takes none.
func longOptionUnknown(cmd string, args []string) string {
	known, listed := readLongs[cmd]
	if listed && known == nil {
		return ""
	}
	for _, a := range args {
		if a == "--" {
			return ""
		}
		if !strings.HasPrefix(a, "--") {
			continue
		}
		if name, _, _ := strings.Cut(a, "="); !known[name] {
			return cmd + " " + name + " (komando does not know this option only reads)"
		}
	}
	return ""
}
