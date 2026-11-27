package gatehere

// The server mode runs few commands, and fails closed: a command runs only
// when runs names it, so one added later is refused until someone decides
// it belongs on a phone's key (rule d). exec and the other commands that
// take a program to run are a shell on this server: refused in phase 1,
// whatever the key's line says. The dangerous tier is refused by the cli,
// which reads the command's words (risk table).

type key struct{ typ, area, verb string }

// runs are the commands a key runs on this server: readings, the typed
// service and package commands, and the file reads.
var runs = map[key]bool{
	{"host", "", "info"}: true, {"host", "", "logs"}: true,
	{"host", "file", "cat"}: true, {"host", "file", "list"}: true, {"host", "file", "stat"}: true,
	{"host", "service", "list"}: true, {"host", "service", "status"}: true, {"host", "service", "logs"}: true,
	{"host", "service", "start"}: true, {"host", "service", "stop"}: true, {"host", "service", "restart"}: true,
	{"host", "service", "reload"}: true, {"host", "service", "enable"}: true, {"host", "service", "disable"}: true,
	{"host", "service", "daemon-reload"}: true,
	{"host", "package", "installed"}:     true, {"host", "package", "upgradable"}: true, {"host", "package", "security"}: true,
	{"host", "package", "install"}: true, {"host", "package", "update"}: true, {"host", "package", "upgrade"}: true,
	{"host", "package", "rm"}:  true,
	{"ssh-gate", "", "status"}: true, {"", "", "version"}: true,
}

// shells take a program or a script to run: on this server that is a shell.
var shells = map[key]bool{
	{"host", "", "exec"}: true, {"host", "", "shell"}: true, {"host", "job", "start"}: true,
	{"host", "docker", "exec"}: true, {"host", "docker", "raw"}: true, {"host", "docker", "compose"}: true,
	{"snippet", "", "exec"}: true, {"cluster", "", "exec"}: true, {"cluster", "", "shell"}: true,
	{"database", "", "shell"}: true,
}

// Runs says whether the command with this safety key runs in server mode,
// and why not.
func Runs(typ, area, verb string) (bool, string) {
	k := key{typ, area, verb}
	switch {
	case shells[k]:
		return false, "it runs a program of your choosing, which is a shell on this server; a phone's key opens no shell"
	case runs[k]:
		return true, ""
	}
	return false, "a phone's key runs only readings and the service, package and file-read commands on this server"
}

// ThisServer is how a command through the server mode names the server
// it runs on: the only target there.
const ThisServer = "localhost"

// Target says why word is no target in server mode, or "".
func Target(word string) string {
	if word == ThisServer {
		return ""
	}
	return "the target " + word + " is not this server: through this key komando acts on this server only, named " + ThisServer
}
