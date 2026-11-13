package cli

import (
	"fmt"
	"maps"
	"slices"
	"strings"

	"github.com/sgnd/komando/internal/out"
	"github.com/sgnd/komando/internal/store"
	"github.com/sgnd/komando/internal/vault"
)

// vpnAddCheck is what `vpn add` checks before it writes anything, in a
// dry run too: the name is free (or --overwrite replaces the VPN of that
// name), and no vault secret the VPN keeps its keys in is taken.
func vpnAddCheck(s *store.State, name string, secrets map[string]string, overwrite bool) error {
	if err := checkNewName(s, "vpn", name, overwrite); err != nil {
		return err
	}
	return checkVpnSecrets(s, name, secrets, overwrite)
}

// checkVpnSecrets refuses a VPN whose keys would go into a vault secret
// that exists already (NAME-key and NAME-psk for WireGuard, NAME-config for
// OpenVPN). Storing them would replace that secret's value, and whatever
// uses it (a server's password, a {{secret:NAME}} in a file on a server)
// would get a value the caller chose, an AI agent too. The only secret
// that may be replaced is the VPN's own: --overwrite replaces a VPN that
// keeps the same key in it, and nothing else uses it.
func checkVpnSecrets(s *store.State, name string, secrets map[string]string, overwrite bool) error {
	if len(secrets) == 0 {
		return nil
	}
	list, err := vault.List()
	if err != nil {
		return err
	}
	have := map[string]bool{}
	for _, i := range list {
		have[i.Name] = true
	}
	for _, n := range slices.Sorted(maps.Keys(secrets)) {
		if !have[n] {
			continue
		}
		users := secretUsers(s, n)
		if overwrite && vpnOwnsSecret(s.Vpns[name], n) && slices.Equal(users, []string{"vpn " + name}) {
			continue
		}
		if len(users) == 0 {
			// left by a removed VPN of this name: adding the same file
			// again stores the value it has, which changes nothing
			if old, err := vault.Get(n); err == nil && old == secrets[n] {
				continue
			}
		}
		used := ""
		if len(users) > 0 {
			used = " (used by " + strings.Join(users, ", ") + ")"
		}
		return out.Errf(out.ExitConflict, "SECRET_EXISTS",
			fmt.Sprintf("nothing was saved; pick another VPN name, or move that secret away first: `komando secret rename %s NEW` (what uses it follows), or `komando secret rm %s` if an earlier VPN named %s left it", n, n, name),
			"vault secret %q already exists%s; VPN %s would store its %s there and replace it", n, used, name, vpnSecretWhat(n))
	}
	return nil
}

// vpnOwnsSecret: v, the VPN --overwrite replaces, keeps the same key in
// the vault secret n, as `vpn add` stored it.
func vpnOwnsSecret(v *store.Vpn, n string) bool {
	if v == nil {
		return false
	}
	ref := "secret:" + n
	switch strings.TrimPrefix(n, v.Name) {
	case "-key":
		return v.Kind == "wireguard" && v.KeyRef == ref
	case "-psk":
		return v.Kind == "wireguard" && v.PSKRef == ref
	case "-config":
		return v.Kind == "openvpn" && v.ConfigRef == ref
	}
	return false
}

// vpnSecretWhat names what `vpn add` keeps in the vault secret n.
func vpnSecretWhat(n string) string {
	switch {
	case strings.HasSuffix(n, "-key"):
		return "WireGuard private key"
	case strings.HasSuffix(n, "-psk"):
		return "WireGuard preshared key"
	}
	return "OpenVPN profile"
}
