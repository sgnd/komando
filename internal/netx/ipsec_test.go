package netx

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/sgnd/komando/internal/ipsec"
	"github.com/sgnd/komando/internal/out"
	"github.com/sgnd/komando/internal/ppp"
	"github.com/sgnd/komando/internal/store"
)

// The VPN's opt-ins reach the IPsec client, and a server that needs one
// gets a hint that names the flag.
func TestIPsecOptIns(t *testing.T) {
	v := &store.Vpn{Name: "kantor", Kind: "l2tp", Server: "vpn.kantor.id", LegacyCrypto: true}
	o, err := ipsecOptions(v)
	if err != nil || !o.LegacyCrypto {
		t.Fatalf("legacy crypto did not reach the client: %+v %v", o, err)
	}
	for err, flag := range map[error]string{
		&ipsec.LegacyCryptoError{Msg: "the server accepted none of komando's proposals"}: "komando vpn edit kantor --legacy-crypto",
		fmt.Errorf("l2tp: %w", ppp.ErrPAPRefused):                                        "komando vpn edit kantor --allow-pap",
	} {
		var oe *out.Error
		if e := ipsecErr(v, err); !errors.As(e, &oe) || oe.Code != "VPN_DOWN" || !strings.Contains(oe.Hint, flag) {
			t.Errorf("%v: %+v", err, e)
		}
	}
}
