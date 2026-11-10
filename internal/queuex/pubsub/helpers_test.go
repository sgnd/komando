package pubsub

import (
	"errors"

	"github.com/sgnd/komando/internal/out"
)

func code(err error) string {
	var e *out.Error
	if errors.As(err, &e) {
		return e.Code
	}
	if err == nil {
		return ""
	}
	return "not an out.Error: " + err.Error()
}
