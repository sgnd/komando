package inventory

// Package inventory holds the rules for what goes into komando's inventory:
// names, login names, ports, labels, --via paths, conn families and the
// references to vault secrets. It imports nothing of internal/cli.

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/sgnd/komando/internal/out"
)

var NameRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,62}$`)

func ValidName(kind, n string) error {
	if !NameRe.MatchString(n) {
		return out.Usage("%q cannot be a %s name: use letters, digits and . _ - (at most 63)", n, kind)
	}
	if (kind == "host" || kind == "conn" || kind == "vpn") && strings.EqualFold(n, "all") {
		return out.Usage("%q cannot be a %s name: as a target it means everything", n, kind)
	}
	return nil
}

// UserRe is a login name: what useradd, Active Directory (user@domain) and
// cloud images use. No spaces, no shell or URL characters.
var UserRe = regexp.MustCompile(`^[A-Za-z0-9_.][A-Za-z0-9_.@$-]{0,63}$`)

func ValidUser(u string) error {
	if !UserRe.MatchString(u) {
		return out.Errf(out.ExitUsage, "USAGE", "a login name has letters, digits and . _ - @ $ (no spaces), for example --user deploy",
			"%q cannot be a login name", u)
	}
	return nil
}

func ValidPort(p int) error {
	if p < 0 || p > 65535 {
		return out.Errf(out.ExitUsage, "USAGE", "a port is a number from 1 to 65535; leave it out for 22",
			"%d is not a port number", p)
	}
	return nil
}

// ValidLabelName checks a group or tag name, or a label key: the same rule
// as host names, so every one of them can be written in a selector
// (@GROUP, tag:TAG, label:KEY=VALUE).
func ValidLabelName(kind, n string) error {
	if !NameRe.MatchString(n) {
		return out.Errf(out.ExitUsage, "USAGE", "use letters, digits and . _ - (max 63), for example web or prod-eu",
			"%q cannot be a %s name", n, kind)
	}
	return nil
}

// CheckLabels validates the groups, tags and labels of an inventory entry.
func CheckLabels(groups, tags []string, labels map[string]string) error {
	for _, gr := range groups {
		if err := ValidLabelName("group", gr); err != nil {
			return err
		}
	}
	for _, t := range tags {
		if err := ValidLabelName("tag", t); err != nil {
			return err
		}
	}
	for k, v := range labels {
		if err := ValidLabelName("label", k); err != nil {
			return err
		}
		if strings.ContainsAny(v, ",") || HasControl(v) {
			return out.Errf(out.ExitUsage, "USAGE", "a label value cannot hold commas or control characters (it would break label:KEY=VALUE selectors)",
				"the value of label %s holds a comma or a control character", k)
		}
	}
	return nil
}

func HasControl(s string) bool {
	return strings.IndexFunc(s, func(r rune) bool { return r < 0x20 || r == 0x7f }) >= 0
}

func NameTaken(kind, name string) error {
	return out.Errf(out.ExitConflict, "NAME_TAKEN", fmt.Sprintf("pick another name; servers, conns and VPNs share one name space (see `komando %s show %s`)", kind, name),
		"name %q is already used by a %s", name, out.KindWord(kind))
}
