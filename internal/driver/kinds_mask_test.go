package driver

import (
	"testing"

	"github.com/sgnd/komando/internal/out"
)

// AI agents see output with secret-looking values masked: the examples
// `conn kinds` shows must come through whole.
func TestKindExamplesSurviveMasking(t *testing.T) {
	for _, k := range Kinds() {
		if got := out.MaskSecrets(k.Example); got != k.Example {
			t.Errorf("%s: an agent reads %q", k.Name, got)
		}
	}
}
