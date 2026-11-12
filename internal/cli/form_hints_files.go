package cli

// The Files area as questions: read, edit, copy and move files on servers
// and in file storage.

// formFsServer is the first question of fs commands that work on one
// server; formFsServers of those that can do the same on several.
var formFsServer = formArg{ask: "On which server?", pick: "server",
	help: "One server: this command reads or edits one file at a time."}

var formFsServers = formArg{ask: "On which server?", pick: "host", free: true,
	help: "Pick one, or type a group like @web to do the same on several."}

// formFsSudo asks for --sudo, which root-owned files need.
func formFsSudo(what string) formFlag {
	return formFlag{name: "sudo", ask: "Run it with sudo (as root)?",
		help: what}
}

// formFsBackup asks for --backup before a file is changed.
var formFsBackup = formFlag{name: "backup", ask: "Keep a copy of the old file?", def: "true",
	help: "Saved next to it as the same name plus .bak, so you can put it back."}

// formCopyFrom and formCopyTo are the two sides of cp.
var formCopyFrom = formArg{ask: "Copy from where?", example: "./site",
	help: "A file or folder on this computer (./site), or on a server as SERVER:PATH (web1:/var/log/app)."}

var formCopyTo = formArg{ask: "Copy to where?", example: "web1:/var/www/site",
	help: "SERVER:PATH on servers (@web:/var/www/site for a group), or a folder on this computer (./logs/)."}

func init() {
	addFormHints(formFsHints)
	addFormHints(formTransferHints)
}

// formFsHints are the fs commands: one file or folder on servers.
var formFsHints = map[string]formHint{
	"fs cat": {args: []formArg{formFsServer,
		{ask: "Which file?", example: "/etc/nginx/nginx.conf", help: "The full path of the file on the server."}},
		flags: []formFlag{
			{name: "tail", ask: "Show only the last lines? How many?", example: "50",
				help: "Handy for long logs. Empty shows the whole file."},
			formFsSudo("Needed when the file can only be read by root."),
		}},
	"fs list": {args: []formArg{formFsServer,
		{ask: "Which folder?", example: "/var/www",
			help: "The full path of the folder. Empty lists the login user's home folder."}},
		flags: []formFlag{
			{name: "all", ask: "Also show hidden files (names starting with a dot)?"},
			{name: "recursive", ask: "Also list everything inside the folders in it?"},
		}},
	"fs stat": {args: []formArg{formFsServer,
		{ask: "Which file or folder?", example: "/etc/nginx/nginx.conf",
			help: "Shows its size, owner, permissions and when it changed, or that it does not exist."}},
		flags: []formFlag{
			{name: "sha256", ask: "Also compute its checksum (sha256)?",
				help: "A fingerprint of the content, to check two copies are the same."},
		}},
	"fs chmod": {args: []formArg{formFsServers,
		{ask: "Which permissions? (as a number)", example: "640",
			help: "640: owner reads and writes, group reads, others nothing. 755: everyone can read and run, only the owner writes."},
		{ask: "Which files or folders?", example: "/etc/app/config.yml",
			help: "Full paths on the server. Several: separate them with spaces."}},
		flags: []formFlag{
			{name: "recursive", ask: "Also change everything inside the folders?"},
			formFsSudo("Needed for files owned by root or another user."),
		}},
	"fs mkdir": {args: []formArg{formFsServers,
		{ask: "Which folder should be made?", example: "/srv/app/releases",
			help: "Full path on the server; missing folders on the way are made too. Several: separate them with spaces."}},
		flags: []formFlag{formFsSudo("Needed to make folders where only root may write, like /srv or /etc.")}},
	"fs mv": {args: []formArg{formFsServers,
		{ask: "Which file or folder do you want to move or rename?", example: "/srv/app/current",
			help: "Its full path on the server."},
		{ask: "Where to? (the new path or name)", example: "/srv/app/previous",
			help: "When this is a folder that exists, it moves into that folder."}},
		flags: []formFlag{
			{name: "overwrite", ask: "Replace a file that is already there?",
				help: "No stops instead of replacing anything."},
			formFsSudo("Needed for files owned by root or another user."),
		}},
	"fs rm": {args: []formArg{formFsServers,
		{ask: "Which files should be removed?", example: "/tmp/upload.tar.gz",
			help: "Full paths on the server; several: separate them with spaces. Patterns like *.log are not read as patterns."}},
		flags: []formFlag{
			{name: "recursive", ask: "Is it a folder? (remove it and everything in it)",
				help: "Yes makes komando ask you to confirm first, since it cannot be undone."},
			formFsSudo("Needed for files owned by root or another user."),
		}},
	"fs replace": {next: []string{"fs restore {} PATH --dry-run", "fs cat {} PATH"}, args: []formArg{formFsServer,
		{ask: "Which file do you want to edit?", example: "/etc/nginx/nginx.conf",
			help: "The full path of the file on the server."}},
		flags: []formFlag{
			{name: "old", ask: "Which text should be changed?", required: true, example: "worker_connections 768;",
				help: "Copy it exactly from the file (komando fs cat shows it). It must appear once."},
			{name: "new", ask: "What should it become?", empty: true, need: func(formAnswers) bool { return true }, example: "worker_connections 4096;",
				help: "The new text, put in place of the old. Empty removes the old text."},
			formFsSudo("Needed for system files, like most files under /etc."),
			formFsBackup,
			{name: "all", ask: "Change it everywhere it appears?",
				help: "No stops when the text is in the file more than once, so nothing changes by surprise."},
		}},
	"fs write": {args: []formArg{formFsServer,
		{ask: "Which file should be written?", example: "/srv/app/config.yml",
			help: "Full path on the server. A file that is there is replaced; a new one is made."}},
		flags: []formFlag{
			{name: "from", ask: "Copy the content from a file on this computer?", example: "./config.yml", local: true,
				help: "Its path here. Leave it empty to type the content in the next question."},
			{name: "content", ask: "Or type the content", example: "PORT=8080", show: func(a formAnswers) bool { return a["flag:from"] == "" },
				help: "Used when no file was given. Never type a password here: write {{secret:NAME}} and komando puts in the saved password."},
			formFsSudo("Needed for system files, like most files under /etc."),
			formFsBackup,
		}},
	"fs restore": {args: []formArg{formFsServer,
		{ask: "Which file should go back to how it was?", example: "/etc/nginx/nginx.conf",
			help: "The file you changed, not its .bak copy. Try it first to see the difference."}},
		flags: []formFlag{
			{name: "copy", ask: "Which backup? (leave empty for the newest)", example: "/etc/nginx/nginx.conf.bak",
				help: "Empty puts back the newest copy. The file as it is now is kept, so you can undo this too."},
			formFsSudo("Needed for system files, like most files under /etc."),
		}},
}

// formTransferHints copy files between this computer, servers and storage.
var formTransferHints = map[string]formHint{
	"upload": {args: []formArg{
		{ask: "To which servers or file storage?", pick: "files", free: true,
			help: "A server, a group like @web, all, or a file storage (S3, SFTP, FTP). Several servers: separate them with spaces or commas."},
		{ask: "Which file or folder on this computer?", example: "./app.tar.gz", local: true,
			help: "Its path here. ./ means the folder you are in, ~/ your home folder."},
		{ask: "Where should it go?", example: "/tmp/app.tar.gz",
			help: "The full path on the server, or the name in the storage. Empty uses the same name, in the login user's home folder."}},
		flags: []formFlag{
			{name: "recursive", ask: "Is it a folder? (copy everything in it)"},
			{name: "sudo", ask: "Put it in place as root (sudo)?",
				help: "Yes for system places, like /etc. Works for single files."},
			{name: "parents", ask: "Make missing folders on the way?"},
		}},
	"download": {args: []formArg{
		{ask: "From which servers or file storage?", pick: "files", free: true,
			help: "A server, a group like @web (one folder per server), all, or a file storage (S3, SFTP, FTP)."},
		{ask: "Which file or folder?", example: "/var/log/nginx/error.log",
			help: "The full path on the server, or the name in the storage."}},
		flags: []formFlag{
			{name: "to", ask: "Where should it be saved on this computer?", example: "./logs/", local: true,
				help: "A folder or file name here. Empty saves it in the folder you are in."},
			{name: "recursive", ask: "Is it a folder? (download everything in it)"},
			{name: "sudo", ask: "Read it as root (sudo)?",
				help: "Yes for files only root can read. Works for single files."},
			{name: "overwrite", ask: "Replace files that are already here?"},
		}},
	"cp": {args: []formArg{formCopyFrom, formCopyTo},
		flags: []formFlag{
			{name: "recursive", ask: "Is it a folder? (copy everything in it)",
				help: "Ending the source with / copies what is in the folder, not the folder itself."},
			{name: "sudo", ask: "Run it with sudo (as root)?",
				help: "Yes for system files, like /etc. Works for single files."},
		}},
	"sync": {args: []formArg{
		{ask: "Copy from where?", example: "./site",
			help: "A folder on this computer, SERVER:PATH on a server, or STORAGE:PREFIX in file storage."},
		{ask: "Copy to where?", example: "web1:/var/www/site",
			help: "The other side: SERVER:PATH (@web:/var/www/site for a group), STORAGE:PREFIX, or a folder here."}},
		flags: []formFlag{
			{name: "exclude", ask: "Skip some names?", example: ".git",
				help: "Files or folders to leave out, like .git or *.log. Empty copies everything."},
		}},
}

// Next: lines for the file commands (fs replace has its own above).
func init() {
	addFormHints(map[string]formHint{
		"fs cat":     {next: []string{"fs replace {} PATH --old A --new B --backup --dry-run", "fs stat {} PATH"}},
		"fs write":   {next: []string{"fs cat {} PATH", "fs restore {} PATH"}},
		"fs restore": {next: []string{"fs cat {} PATH"}},
		"fs list":    {next: []string{"fs cat {} PATH", "fs stat {} PATH"}},
		"upload":     {next: []string{"fs stat {} DEST --sha256", "svc reload {} UNIT"}},
		"download":   {next: []string{"fs cat {} PATH", "download {} PATH --overwrite"}},
	})
}
