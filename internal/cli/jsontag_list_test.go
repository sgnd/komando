package cli

// jsonTagAllowed are the JSON keys from before S-9.1 and S-9.2 that break
// them; contract 1 keeps them as they are (TestJSONTagLint). Only shrink it.
var jsonTagAllowed = []string{
	"cli.certInfo.not_after",     // a moment is <event>_at
	"cli.certInfo.not_before",    // a moment is <event>_at
	"cli.errorCode.exit",         // say the unit: _at, _ms, _seconds, _bytes, _count, exit_code
	"cli.fileInfo.mod_time",      // a moment is <event>_at
	"cli.fileInfo.size",          // say the unit: _at, _ms, _seconds, _bytes, _count, exit_code
	"cli.holderError.exit",       // say the unit: _at, _ms, _seconds, _bytes, _count, exit_code
	"cli.jobStatus.runtime_sec",  // say the unit: _at, _ms, _seconds, _bytes, _count, exit_code
	"cli.loginResult.until",      // a moment is <event>_at
	"cli.pruneItem.created",      // a moment is <event>_at
	"cli.pruneItem.size",         // say the unit: _at, _ms, _seconds, _bytes, _count, exit_code
	"cli.runningLogin.since",     // a moment is <event>_at
	"cli.runningLogin.until",     // a moment is <event>_at
	"cli.runningVpn.last_used",   // a moment is <event>_at
	"cli.runningVpn.since",       // a moment is <event>_at
	"cli.serveErr.exit",          // say the unit: _at, _ms, _seconds, _bytes, _count, exit_code
	"cli.syncAction.size",        // say the unit: _at, _ms, _seconds, _bytes, _count, exit_code
	"cli.vpnStatusRow.last_used", // a moment is <event>_at
	"cli.vpnStatusRow.since",     // a moment is <event>_at
	"cli.winEntry.size",          // say the unit: _at, _ms, _seconds, _bytes, _count, exit_code
}
