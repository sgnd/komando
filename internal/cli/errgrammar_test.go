package cli

import (
	"slices"
	"strings"
	"testing"
)

// codeOutcomes is the S-8.2 table: the last part of a new code, and the
// exit code it goes with.
var codeOutcomes = []struct {
	suffix string
	exit   int
}{
	{"_NOT_FOUND", 3}, {"_MISSING", 3},
	{"_EXISTS", 8}, {"_IN_USE", 8}, {"_CONFLICT", 8}, {"_BUSY", 8},
	{"_INVALID", 2}, {"_UNSUPPORTED", 2},
	{"_AUTH", 4}, {"_UNREACHABLE", 4}, {"_TLS", 4},
	{"_DENIED", 5}, {"_FAILED", 5}, {"_ERROR", 5},
	{"_REQUIRED", 6},
	{"_TIMEOUT", 7},
}

// TestErrorCodeGrammar: a new code is <SUBJECT>_<OUTCOME> with the exit
// code S-8.2 gives its outcome (C-E04). A local failure may end in
// _FAILED or _ERROR with exit 1. Today's codes that do not follow it are
// frozen in codeGrammarExceptions; that list may only shrink.
func TestErrorCodeGrammar(t *testing.T) {
	for _, c := range errorCodes {
		if slices.Contains(codeGrammarExceptions, c.Code) {
			continue
		}
		ok := false
		for _, o := range codeOutcomes {
			if strings.HasSuffix(c.Code, o.suffix) && len(c.Code) > len(o.suffix) &&
				(c.Exit == o.exit || c.Exit == 1 && (o.suffix == "_FAILED" || o.suffix == "_ERROR")) {
				ok = true
			}
		}
		if !ok {
			t.Errorf("%s (exit %d) does not follow S-8.2: name a new code <SUBJECT>_<OUTCOME> with the outcome's exit code", c.Code, c.Exit)
		}
	}
	for _, c := range codeGrammarExceptions {
		if !slices.ContainsFunc(errorCodes, func(e errorCode) bool { return e.Code == c }) {
			t.Errorf("codeGrammarExceptions lists %s, which komando no longer gives: drop it", c)
		}
	}
}
