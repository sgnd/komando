package cli

// The approval window's words in each language (approval_language). Only
// komando's own words change: the command, the script, names and the
// agent are shown as they are. text() stays English: it is the key of the
// request, not what a window shows.
type approvalWords struct {
	panel, deny, allow                   string // the window's title bar and buttons
	change, runOn, queryOn, runKomando   string // the action title
	servers                              string // "%s 3 servers": a verb, then the count and this
	show, allowAny                       string // titles of a window with no parts
	askedBy, targets, protected, risk    string
	skips, alsoLets, options, command    string
	ownerAllow, thisCommand, lines, byts string
	scrollAll                            string            // the hint over the buttons when what runs scrolls: %d is its line count
	keys                                 string            // shown when a key that cannot allow is pressed
	flagSkip                             map[string]string // the check each approval flag skips
	aSafetyCheck                         string
	kinds                                map[string]string // what a body is ("script"): its heading
}

var approvalWordsEN = approvalWords{
	panel: "komando needs your OK", deny: "Deny", allow: "Allow once",
	change: "Change", runOn: "Run a command on", queryOn: "Run a query on", runKomando: "Run a komando command",
	servers: "servers", show: "Show ", allowAny: "komando: allow?",
	askedBy: "Asked by ", targets: "Targets: ", protected: "Status: Protected", risk: "Risk: ",
	skips: "Skips: ", alsoLets: "Also lets through: ", options: "Options: ", command: "Command: ",
	ownerAllow: "komando: allow ", thisCommand: "this command", lines: " lines", byts: " bytes",
	scrollAll: "Scroll to read all %d lines",
	keys:      "Keys do not allow. Click Allow once, or use Voice Control (\"click Allow once\") or the Accessibility Keyboard. Esc denies.",
	flagSkip: map[string]string{
		"--yes":             "the safety-change check",
		"--allow-dangerous": "the dangerous-command check",
		"--reveal":          "the secret-hiding check",
	},
	aSafetyCheck: "a safety check",
}

var approvalWordsID = approvalWords{
	panel: "komando minta persetujuan Anda", deny: "Tolak", allow: "Izinkan sekali",
	change: "Ubah", runOn: "Jalankan perintah di", queryOn: "Jalankan query di", runKomando: "Jalankan perintah komando",
	servers: "server", show: "Tampilkan ", allowAny: "komando: izinkan?",
	askedBy: "Diminta oleh ", targets: "Target: ", protected: "Status: Dilindungi", risk: "Risiko: ",
	skips: "Pengecekan dilewati: ", alsoLets: "Juga mengizinkan: ", options: "Opsi: ", command: "Perintah: ",
	ownerAllow: "komando: izinkan ", thisCommand: "perintah ini", lines: " baris", byts: " byte",
	scrollAll: "Gulir untuk membaca semua %d baris",
	keys:      "Tombol keyboard tidak mengizinkan. Klik Izinkan sekali, atau pakai Kontrol Suara (\"klik Izinkan sekali\") atau Papan Ketik Aksesibilitas. Esc menolak.",
	flagSkip: map[string]string{
		"--yes":             "pengecekan perubahan berisiko",
		"--allow-dangerous": "pengecekan perintah berbahaya",
		"--reveal":          "pengecekan penyembunyian rahasia",
	},
	aSafetyCheck: "sebuah pengecekan keamanan",
	kinds: map[string]string{
		"script": "Skrip", "input": "Input", "content": "Isi", "message": "Pesan",
		"file": "File", "files": "File", "archive": "Arsip",
	},
}

func wordsFor(lang string) approvalWords {
	if lang == "id" {
		return approvalWordsID
	}
	return approvalWordsEN
}

// riskID is each built-in rule's reason in Indonesian, with the English
// reason it was written for: when a rule's reason changes, the window
// shows the new English one until these words are written again
// (TestApprovalRiskWordsIndonesian). The words keep the reason's force.
var riskID = map[string]struct{ en, id string }{
	"rm-root":              {"deletes / or the home folder recursively", "menghapus / atau folder home secara rekursif"},
	"rm-cd-root":           {"deletes everything in / or the home folder recursively", "menghapus semua isi / atau folder home secara rekursif"},
	"find-delete-root":     {"deletes files across / or a system folder", "menghapus file di seluruh / atau di folder sistem"},
	"rm-system-dir":        {"deletes a system folder recursively", "menghapus folder sistem secara rekursif"},
	"mkfs":                 {"formats a filesystem", "memformat filesystem"},
	"dd-device":            {"writes raw data to a block device", "menulis data mentah ke block device"},
	"redirect-device":      {"overwrites a block device", "menimpa block device"},
	"wipefs":               {"wipes disks or partition tables", "menghapus bersih disk atau tabel partisi"},
	"fdisk":                {"edits partition tables", "mengubah tabel partisi"},
	"power":                {"powers off or reboots the server", "mematikan atau me-reboot server"},
	"power-systemctl":      {"powers off or reboots the server", "mematikan atau me-reboot server"},
	"fork-bomb":            {"starts a fork bomb (the server runs out of processes)", "menjalankan fork bomb (server kehabisan proses)"},
	"chmod-root":           {"changes the permissions of / recursively", "mengubah izin akses / secara rekursif"},
	"chown-root":           {"changes the owner of / recursively", "mengubah pemilik / secara rekursif"},
	"firewall-flush":       {"drops firewall rules (may lock you out)", "menghapus aturan firewall (akses Anda ke server bisa terputus)"},
	"firewall-drop-all":    {"drops all traffic by default (may lock you out)", "menolak semua lalu lintas secara default (akses Anda ke server bisa terputus)"},
	"sshd-stop":            {"stops sshd (locks out remote access)", "menghentikan sshd (akses jarak jauh terkunci)"},
	"passwd-files":         {"overwrites authentication files", "menimpa file autentikasi"},
	"passwd-files-write":   {"overwrites authentication files", "menimpa file autentikasi"},
	"db-drop":              {"drops a database", "menghapus database"},
	"docker-prune-all":     {"deletes docker volumes/images", "menghapus volume/image docker"},
	"kubectl-delete-ns":    {"deletes kubernetes namespaces or nodes", "menghapus namespace atau node kubernetes"},
	"base64-pipe-sh":       {"runs hidden (base64) text as a script", "menjalankan teks tersembunyi (base64) sebagai skrip"},
	"decode-run":           {"decodes hidden data and runs it (it cannot be reviewed)", "mendekode data tersembunyi lalu menjalankannya (tidak bisa diperiksa)"},
	"curl-pipe-sh":         {"pipes a remote script into a shell", "menjalankan skrip dari internet langsung di shell"},
	"crontab-r":            {"removes all cron jobs", "menghapus semua cron job"},
	"userdel":              {"deletes a user account", "menghapus akun pengguna"},
	"rm-files":             {"deletes files", "menghapus file"},
	"docker-rm":            {"deletes docker containers, images, volumes or services", "menghapus container, image, volume, atau service docker"},
	"docker-prune":         {"deletes unused docker containers, images, networks or build cache", "menghapus container, image, network, atau cache build docker yang tidak dipakai"},
	"docker-kill":          {"stops containers or services, or changes the swarm (kill, scale to 0, swarm, node)", "menghentikan container atau service, atau mengubah swarm (kill, scale ke 0, swarm, node)"},
	"docker-host":          {"gives a container the server (privileged, host namespaces, system folders, plugins)", "memberi container akses ke server (privileged, namespace host, folder sistem, plugin)"},
	"pkg-remove":           {"removes packages", "menghapus paket"},
	"pkg-remove-essential": {"removes a package the server needs (ssh, sudo, systemd, libc ...), which can lock you out or break it", "menghapus paket yang dibutuhkan server (ssh, sudo, systemd, libc ...), sehingga akses Anda bisa terputus atau server rusak"},
	"cron-remove":          {"replaces the crontab or edits cron files, which removes cron jobs", "mengganti crontab atau mengubah file cron, sehingga cron job terhapus"},
	"kubectl-scale-zero":   {"scales a kubernetes workload to zero (an outage)", "menurunkan workload kubernetes ke nol (layanan mati)"},
	"db-drop-user":         {"deletes a database user or role", "menghapus pengguna atau role database"},
	"win-rm-root":          {"deletes the system drive, a system folder or the users folder recursively", "menghapus drive sistem, folder sistem, atau folder users secara rekursif"},
	"win-format":           {"formats or wipes a disk", "memformat atau menghapus bersih disk"},
	"win-power":            {"powers off or restarts the server", "mematikan atau me-restart server"},
	"win-remote-access":    {"stops remote access (SSH or WinRM), which locks you out", "menghentikan akses jarak jauh (SSH atau WinRM), sehingga akses Anda ke server terputus"},
	"win-firewall-block":   {"blocks all incoming traffic (may lock you out)", "memblokir semua lalu lintas masuk (akses Anda ke server bisa terputus)"},
	"win-user-delete":      {"deletes a user account", "menghapus akun pengguna"},
	"win-encoded":          {"runs hidden (base64) text as a script", "menjalankan teks tersembunyi (base64) sebagai skrip"},
	"win-decode-run":       {"decodes hidden data and runs it (it cannot be reviewed)", "mendekode data tersembunyi lalu menjalankannya (tidak bisa diperiksa)"},
	"win-download-run":     {"runs a script downloaded from the network", "menjalankan skrip yang diunduh dari jaringan"},
	"win-backups":          {"deletes backups (shadow copies) or changes how Windows boots", "menghapus cadangan (shadow copy) atau mengubah cara Windows booting"},
	"win-registry-hive":    {"deletes a whole registry hive", "menghapus satu hive registry utuh"},
}
