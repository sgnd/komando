package cli

import (
	"time"

	"github.com/sgnd/komando/internal/netx"
)

// red skeleton (C655): replaced by the fix
func gateDial(dial netx.Dialer) netx.Dialer { return dial }

func gateDialFor(_ *call, _ time.Duration) netx.Dialer { return nil }
