# Analisis celah fitur komando: SSH, fleet, file, job, tunnel, key, host, modul sistem

Dibuat 2026-11-02 pada branch `feat/v0.3` (commit `4784fc9`). Sumber: `bin/komando --help`
(semua perintah), kode di `internal/cli` dan `internal/sshx`, `docs/design/{vision,ux,network}.md`,
`docs/features/*.md`. Tidak ada server yang dihubungi.

**Cara membaca status**

- **ADA**: ada perintah/flag yang menanganinya secara terstruktur dan aman.
- **SEBAGIAN**: sebagian ada; yang kurang disebut di kolom catatan.
- **TIDAK ADA**: tidak ada dukungan first-class. "bisa lewat exec" berarti tetap bisa dikerjakan
  lewat `komando exec` (jalur mentah yang diaudit, dianggap *write*, kena policy), tapi tanpa
  output terstruktur, idempotensi, atau dry-run yang berarti.
- **NON-GOAL**: dikecualikan oleh `docs/design/vision.md` (kutipan alasannya disertakan).

**Prioritas** (untuk celah saja): **P1** = kebutuhan harian / keamanan / penghambat alur kerja
agent; **P2** = berguna; **P3** = niche. Baris ADA diberi tanda "–".

Kutipan non-goal yang dipakai berulang (vision.md, "Bukan tujuan" dan "Aturan teknis"):

- NG-TUI: "GUI, TUI, sistem plugin, atau daemon/server. komando tetap CLI murni."
- NG-IaC: "Infrastructure as Code, provisioning cloud, atau GitOps."
- NG-POOL: "Tanpa pool dan tanpa daemon. Satu koneksi per perintah."
- NG-MON: "Monitoring atau alerting yang berjalan terus-menerus."
- NG-FULL: "Mengganti alat lengkap (...). komando menangani 80% pekerjaan harian dengan aman."
- NG-NET (network.md, Keamanan): "komando tidak pernah mengubah rute, DNS, atau firewall laptop."

---

## 1. Koneksi dan autentikasi SSH (OpenSSH `ssh`, `ssh_config`)

| Kemampuan | Tools pembanding | Status komando | Bukti/catatan | Prioritas |
|---|---|---|---|---|
| Login dengan private key file | ssh `-i`, `IdentityFile` | ADA | `host add/edit --identity PATH`, `--key NAME` (keychain) | – |
| Pakai ssh-agent (termasuk 1Password/Secretive agent lewat `SSH_AUTH_SOCK`) | ssh-agent, `IdentityAgent` | ADA | `internal/sshx/client.go` membaca `SSH_AUTH_SOCK`; `doctor` mengecek ssh-agent | – |
| Fallback otomatis ke `~/.ssh/id_ed25519/id_ecdsa/id_rsa` | ssh default identities | ADA | `client.go` (hanya bila tidak ada `--key/--identity`) | – |
| Key terenkripsi (passphrase dari vault) | ssh + ssh-agent | ADA | `key add/edit --passphrase-ref secret:NAME` | – |
| Password login (tersimpan aman) | ssh + sshpass | ADA | `--password-ref secret:/env:/file:/op:///vault:/aws-sm:/gcp-sm:`; ditolak sebagai argumen | – |
| Keyboard-interactive / 2FA SSH (OTP Google Authenticator, Duo) | ssh, Teleport | SEBAGIAN | keyboard-interactive dijawab dengan password untuk semua pertanyaan; OTP tidak bisa. `shell` interaktif pun memakai jawaban otomatis yang sama. Sejalan dengan prinsip "MFA selalu oleh manusia" (network.md), tapi belum ada jalur manusia untuk SSH MFA (mis. prompt di `shell`/`test` interaktif) | P3 |
| `IdentitiesOnly` (batasi key yang dicoba, hindari "Too many authentication failures") | ssh_config | SEBAGIAN | bila `--key/--identity` diset, key default tidak dicoba, tapi semua key ssh-agent tetap dicoba lebih dulu/bersama | P2 |
| `IdentityAgent` per host (agent berbeda per host) | ssh_config | TIDAK ADA | hanya `SSH_AUTH_SOCK` global | P3 |
| Jump host / bastion (`-J`, `ProxyJump`), rantai banyak lompatan | ssh, Teleport | ADA | `--via bastion,db1` untuk host dan conn; `--jump` alias; diimpor dari `ProxyJump` | – |
| `ProxyCommand` (mis. `aws ssm start-session`, `cloudflared access ssh`, `gcloud compute start-iap-tunnel`) | ssh_config, Teleport | TIDAK ADA | `parseSSHConfig` mengabaikan `ProxyCommand` (tanpa laporan); tidak ada transport SSM/IAP/Cloudflare Access. Umum di cloud tanpa IP publik | P2 |
| Akses lewat VPN per koneksi (banyak VPN sekaligus) | tsh, Tailscale SSH, klien VPN | ADA | `vpn add` (wireguard, tailscale, openconnect family, openvpn, socks, system) + `--via vpn,bastion` | – |
| Tailscale SSH (auth berbasis identitas tailnet, tanpa key) | Tailscale SSH | SEBAGIAN | `vpn add ... tailscale` memberi jalur, tapi komando tetap butuh metode auth (`NO_AUTH` bila tidak ada key/agent/password) | P3 |
| SSH certificate login (user cert ditandatangani CA, `CertificateFile`) | OpenSSH CA, Teleport, Vault SSH, step-ca | TIDAK ADA | tidak ada `ssh.CertSigner` di `internal/sshx`; cert di agent juga tidak dijamin terpakai. Penting untuk tim yang memakai short-lived cert | P2 |
| Agent forwarding (`-A`, `ForwardAgent`) — mis. `git pull` dari server memakai key laptop | ssh | TIDAK ADA | tidak ada `agent.ForwardToAgent` di kode. Kalau ditambah harus opt-in per host + diaudit (berisiko) | P2 |
| X11 forwarding (`-X/-Y`) | ssh | TIDAK ADA | tidak ada di kode; GUI jarak jauh di luar fokus 80% harian | P3 |
| Keepalive (`ServerAliveInterval`) | ssh_config, autossh | ADA | `keepalive@komando` otomatis di `client.go`; interval tidak bisa diatur per host | – |
| Connect timeout | ssh `ConnectTimeout` | ADA | `--connect-timeout`, `config set connect_timeout` (berlaku untuk seluruh rantai via/VPN) | – |
| Pilihan cipher/KEX/HostKeyAlgorithms per host (server lama) | ssh_config | TIDAK ADA | tidak ada opsi; server legacy (RSA-SHA1, DH group1) bisa gagal tanpa jalan keluar | P3 |
| Kompresi (`-C`) untuk link lambat | ssh | TIDAK ADA | tidak ada | P3 |
| Multiplexing koneksi (`ControlMaster/ControlPersist`) antar-perintah | ssh_config | NON-GOAL | NG-POOL: "Tanpa pool dan tanpa daemon. Satu koneksi per perintah." Satu perintah memakai satu koneksi per host | – |
| Retry otomatis saat koneksi gagal sementara | Ansible `retries`, pssh | TIDAK ADA | `exec`/modul tidak me-retry; tunnel saja yang reconnect | P2 |
| IPv6, port non-standar | ssh | ADA | `user@[addr]:port`, `--port`; edge case IPv6 tercatat di ux.md | – |
| Host ad-hoc tanpa didaftarkan | ssh `user@host` | ADA | target `user@addr:port` | – |
| `Match` blok di ssh_config (Match host/user/exec) | ssh_config | SEBAGIAN | `host import` membaca `Include`, wildcard `Host` sebagai default, tapi `Match` diabaikan diam-diam (`cur = nil`) — melanggar ux.md §9 "Field yang tidak didukung dilaporkan, tidak dibuang diam-diam" | P2 |
| Laporan direktif ssh_config yang tidak didukung (`ProxyCommand`, `LocalForward`, `ForwardAgent`, `CertificateFile`, ...) saat import | ssh_config | TIDAK ADA | `host import` hanya membaca Host/HostName/User/Port/IdentityFile/ProxyJump/Include; sisanya dibuang tanpa peringatan | P2 |
| Cetak perintah OpenSSH setara (interop) | — | ADA | `host ssh-command NAME` | – |
| Ekspor inventaris ke `ssh_config` (supaya ssh/scp/VS Code Remote memakai inventaris komando) | Termius, Teleport `tsh config` | TIDAK ADA | hanya per host (`host ssh-command`) dan JSON (`host export`) | P3 |
| Host Windows (OpenSSH di Windows / WinRM / PowerShell) | Ansible winrm, Salt | TIDAK ADA | model host = "SSH (Linux)" (vision.md); `exec` ke Windows OpenSSH mungkin jalan, modul sistem tidak | P3 |

## 2. Kunci SSH dan sertifikat (`ssh-keygen`, `ssh-agent`, `ssh-copy-id`, SSH CA)

| Kemampuan | Tools pembanding | Status komando | Bukti/catatan | Prioritas |
|---|---|---|---|---|
| Buat key pair ed25519 / RSA | ssh-keygen | ADA | `key gen NAME --type ed25519|rsa --bits --comment` | – |
| Buat key ECDSA | ssh-keygen `-t ecdsa` | TIDAK ADA | `--type` hanya ed25519/rsa (key ECDSA yang sudah ada bisa `key add`) | P3 |
| Key hardware FIDO2 (`ed25519-sk`, YubiKey) | ssh-keygen `-t ed25519-sk` | SEBAGIAN | hanya bila key sk ada di ssh-agent; `key gen` tidak bisa membuat | P3 |
| Passphrase saat membuat key | ssh-keygen `-N` | TIDAK ADA | `key gen` menulis private key tanpa enkripsi (0600, `ssh.MarshalPrivateKey`). Secure-by-default menyarankan opsi `--passphrase-ref` | P2 |
| Daftarkan key yang sudah ada | ssh-add / ssh_config | ADA | `key add NAME PATH [--passphrase-ref]` (file tidak disalin) | – |
| Lihat public key dan fingerprint | ssh-keygen `-y`, `-l` | ADA | `key show`, `key list` (fingerprint SHA256 disimpan di state) | – |
| Pasang public key ke server (idempoten) | ssh-copy-id, Ansible `authorized_key` | ADA | `key deploy KEY TARGET [--set-default]`, banyak host paralel | – |
| Cabut / hapus public key dari `authorized_keys` di banyak server (offboarding, rotasi) | Ansible `authorized_key state=absent`, Teleport | TIDAK ADA | `key deploy` dan `user add --key` hanya menambah. Saat anggota tim keluar atau key bocor, tidak ada cara aman/terstruktur; bisa lewat exec (`sed` — justru dilarang aturan agent) | P1 |
| Daftar `authorized_keys` per server/user (audit siapa bisa login) | Ansible, Teleport | TIDAK ADA | bisa lewat `fs cat ~/.ssh/authorized_keys`, tanpa parsing/fingerprint dan tanpa cocokkan ke keychain | P2 |
| Rotasi key end-to-end (deploy baru → switch → cabut lama) | Teleport, Vault SSH | SEBAGIAN | dua langkah pertama ada (`key deploy --set-default`), langkah cabut tidak ada (lihat baris di atas) | P2 |
| Tambahkan key ke ssh-agent | ssh-add | TIDAK ADA | komando membaca agent, tidak menambah ke agent; tidak perlu karena komando memuat key sendiri | P3 |
| Opsi `authorized_keys` (`from=`, `command=`, `no-port-forwarding`) | Ansible `authorized_key key_options` | TIDAK ADA | key dipasang tanpa batasan; berguna untuk key otomatisasi/agent yang dibatasi | P3 |
| SSH CA: tanda tangani user/host cert | ssh-keygen `-s`, step-ca, Vault SSH | TIDAK ADA | komando tidak bisa menjadi CA; bisa memakai ssh-keygen di laptop | P3 |
| Short-lived cert otomatis per sesi | Teleport `tsh login`, Vault SSH | TIDAK ADA | butuh server CA; dekat ke daftar NG-TUI ("daemon/server") bila komando harus menjadi CA | P3 |

## 3. Host key dan kepercayaan server (`known_hosts`, `ssh-keyscan`)

| Kemampuan | Tools pembanding | Status komando | Bukti/catatan | Prioritas |
|---|---|---|---|---|
| Kebijakan host key accept-new / strict / off | ssh `StrictHostKeyChecking` | ADA | `--host-key-policy`, `config set host_key_policy` (`off` butuh `--yes`, `SAFETY_SETTING`) | – |
| Tolak host key berubah | ssh | ADA | `HOSTKEY_MISMATCH`, tidak pernah dilewati otomatis | – |
| Ambil & pin host key (keyscan), juga di balik bastion | ssh-keyscan | ADA | `host trust NAME` (langsung; di balik `--via` lewat koneksi accept-new) | – |
| Lupakan / ganti key setelah server dibangun ulang | ssh-keygen `-R` | ADA | `host trust NAME --reset` | – |
| Impor `~/.ssh/known_hosts` yang sudah ada (hindari TOFU ulang) | — | TIDAK ADA | komando memakai `~/.komando/known_hosts` sendiri; host yang sudah dipercaya OpenSSH dipercaya ulang secara TOFU | P2 |
| Host certificate / `@cert-authority` di known_hosts | OpenSSH, Teleport | TIDAK ADA | fleet besar yang memakai host CA tetap kena TOFU per host | P2 |
| Verifikasi fingerprint dari sumber lain (DNS SSHFP, out-of-band) | ssh `VerifyHostKeyDNS` | TIDAK ADA | `host trust` tidak menerima `--fingerprint SHA256:...` untuk dicocokkan sebelum pin | P2 |
| Daftar host key yang dipin | `ssh-keygen -F`, Termius known hosts | SEBAGIAN | fingerprint muncul di output `host trust`; tidak ada perintah daftar (file `known_hosts` bisa dibaca manual) | P3 |

## 4. Inventaris dan manajemen host (Termius, Warp, Ansible inventory, Salt, ClusterSSH)

| Kemampuan | Tools pembanding | Status komando | Bukti/catatan | Prioritas |
|---|---|---|---|---|
| Tambah/ubah/hapus/lihat host | Termius, Ansible inventory | ADA | `host add/edit/rm/show`, `--rename` memperbarui referensi | – |
| Grup, tag, label key=value, catatan | Termius tags, Ansible groups/vars | ADA | `--group/--tag/--label/--notes`; `group add/rm/list` | – |
| Grup bersarang (group of groups / `children`) | Ansible | TIDAK ADA | selector `@a,@b` bisa menggabung, tapi tidak ada definisi grup induk | P3 |
| Selector: nama, glob, `@group`, `tag:`, `label:`, `kind:`, `all`, gabungan, `!` | Ansible patterns, Salt targeting, pssh `-h` | ADA | ux.md §2; "did you mean" untuk typo | – |
| Target berdasarkan facts (os=ubuntu, arch, versi) | Salt grains targeting (`-G`), Ansible `group_by` | TIDAK ADA | label harus diisi manual | P3 |
| Variabel per host (env, user default, sudo) | Ansible host_vars | ADA | `--env KEY=VALUE` diekspor ke setiap perintah, `--user`, `--sudo-ref`, `config set default_user` | – |
| Variabel per host untuk recipe/template (`{{app}}` per host) | Ansible host_vars | TIDAK ADA | `recipe run --var` sama untuk semua host; label tidak bisa dipakai sebagai nilai `{{var}}` | P3 |
| Tandai host produksi (perlu konfirmasi) | Teleport labels+RBAC, Termius — | ADA | `--protected`; protected mengikuti alamat | – |
| Import `~/.ssh/config` | Termius, Warp | ADA | `import ssh-config` / `host import` (Include, ProxyJump, wildcard) — lihat celah `Match` di §1 | – |
| Import inventaris Ansible (INI/YAML) | — | TIDAK ADA | tidak ada di `import` sources; banyak tim sudah punya inventory Ansible | P2 |
| Import dari Termius / Royal TSX / MobaXterm / PuTTY | Termius export | TIDAK ADA | vision.md mencantumkan `termius` di tabel migrasi tapi belum diimplementasikan | P2 |
| Inventaris dinamis dari cloud (EC2/DO/Hetzner tag) | Ansible dynamic inventory, Salt cloud | TIDAK ADA | vision.md: "VM cloud (DigitalOcean, Hetzner, AWS EC2)" kandidat setelah v1.0; provisioning = NG-IaC, tapi *membaca* daftar VM bukan provisioning | P2 |
| Export / pindah komputer | Termius sync | ADA | `export`, `import komando`, `host export --target` | – |
| Sinkronisasi inventaris antar perangkat/tim (cloud) | Termius cloud sync, Teleport | NON-GOAL | NG-TUI "... daemon/server"; jalur yang ada: `export`/`import` file | – |
| Cek bisa login ke semua host | `ansible -m ping`, Termius | ADA | `test TARGET` (host, conn, VPN) | – |
| Cek sudo berfungsi saat `test` | `ansible -b -m ping` | TIDAK ADA | `test` mengecek koneksi+login; sudo-ref yang salah baru ketahuan saat perintah pertama | P2 |
| Riwayat koneksi / "recent hosts" | Termius, Warp | SEBAGIAN | `audit --target` memberi riwayat per host; tidak ada daftar "terakhir dipakai" di `list` | P3 |

## 5. Eksekusi jarak jauh dan fleet (pssh, ClusterSSH, Fabric, pyinfra, Ansible ad-hoc, Salt)

| Kemampuan | Tools pembanding | Status komando | Bukti/catatan | Prioritas |
|---|---|---|---|---|
| Jalankan perintah di satu / banyak host paralel | pssh, `ansible -m shell`, `salt cmd.run`, Fabric | ADA | `exec TARGET -- CMD`, `-P/--parallel`, hasil per host terurut | – |
| Output terstruktur per host (stdout, stderr, exit, durasi) + exit code terburuk | Ansible JSON callback, Salt `--out json` | ADA | envelope JSON, `data.results[]`, `summary`, exit 5 bila ada non-zero | – |
| Streaming output saat berjalan | pssh `-P`, Fabric | ADA | `--stream` (NDJSON) | – |
| Hentikan setelah kegagalan pertama | Ansible `any_errors_fatal` | ADA | `--fail-fast` | – |
| Rolling / batch bertahap (`serial: 2` / `25%`), jeda & cek sehat antar-batch | Ansible `serial`, Fabric, Salt `--batch-size` | SEBAGIAN | `-P 1 --fail-fast` = satu per satu; tidak ada ukuran batch persen, jeda, atau health check antar batch (penting untuk restart fleet tanpa downtime) | P2 |
| Kelompokkan output identik (500 host → "480 host: OK") | clush `-b`, `ansible -o`, dshbak | TIDAK ADA | output per host selalu penuh; mahal untuk agent di fleet besar | P2 |
| Simpan output per host ke folder | pssh `-o/-e` | TIDAK ADA | JSON stdout bisa diproses; `--max-output` membatasi | P3 |
| sudo non-interaktif, sudo dengan password dari vault, sudo -u | Ansible `become`, Fabric `sudo` | ADA | `--sudo`, `--sudo-user`, host `--sudo-ref` | – |
| `su`/`doas`/`pbrun` sebagai metode become | Ansible `become_method` | TIDAK ADA | hanya sudo | P3 |
| Env var dan working dir | Fabric `cd`, `env` | ADA | `-e KEY=VAL`, `-C DIR`, host `--env` | – |
| stdin dari file lokal | pssh `-I`, ssh `< file` | ADA | `--stdin-file FILE|-` | – |
| Jalankan skrip lokal di remote tanpa menyalin | Ansible `script`, pyinfra, `ssh 'bash -s' < x` | ADA | `script TARGET FILE --arg --interpreter` | – |
| PTY untuk tool yang memintanya | ssh `-t` | ADA | `--pty` (non-interaktif) | – |
| Dry-run / check mode | `ansible --check`, pyinfra `--dry` | ADA | `--dry-run` global (tampilkan perintah + apakah diblok policy) | – |
| Guardrail perintah berbahaya | — (Teleport hanya RBAC) | ADA | `policy list/check/deny/allow`, `--allow-dangerous` | – |
| Deklarasi read-only untuk host protected | — | ADA | `--read-only` | – |
| Batas waktu per host dan batas output | pssh `-t`, Ansible `timeout` | ADA | `--timeout`, `--max-output` | – |
| Batas eksekusi async (`async`/`poll`) | Ansible async | ADA | via `job start` (lihat §7) | – |
| Interaktif ke banyak terminal sekaligus (ketik sekali, semua host) | ClusterSSH, tmux synchronize-panes, Termius multi-exec | NON-GOAL | NG-TUI: "GUI, TUI ... komando tetap CLI murni." `exec` paralel sudah menutup kebutuhan non-interaktifnya | – |
| Playbook / state deklaratif (orkestrasi banyak langkah, handler) | Ansible playbook, Salt state, pyinfra deploy | NON-GOAL | NG-IaC: "Infrastructure as Code, provisioning cloud, atau GitOps." | – |
| Perintah lokal di laptop sebagai bagian alur | Fabric `local` | NON-GOAL | NG-FULL; komando mengurus target jarak jauh | – |

## 6. Shell interaktif dan sesi (ssh, mosh, Teleport, Termius)

| Kemampuan | Tools pembanding | Status komando | Bukti/catatan | Prioritas |
|---|---|---|---|---|
| Shell login interaktif (PTY, resize) | ssh, Termius, tsh ssh | ADA | `shell TARGET` (alias `ssh`, `connect`), `WindowChange` ditangani, lewat `--via`/VPN | – |
| Jalankan perintah interaktif dengan TTY (`ssh -t host htop`, `docker exec -it`, `sudo -i`) | ssh `-t host CMD` | TIDAK ADA | `shell` hanya membuka login shell; `exec --pty` tidak interaktif | P2 |
| Konfirmasi/penanda saat shell ke host protected | Teleport | SEBAGIAN | `shell` diaudit (hanya "dibuka"); tidak ada peringatan/konfirmasi untuk host protected | P2 |
| Rekaman sesi (session recording / replay) | Teleport, `script`, asciinema | TIDAK ADA | audit hanya mencatat sesi dimulai, bukan isinya | P3 |
| Roaming / koneksi tahan putus (ganti Wi-Fi, laptop sleep) | mosh, Eternal Terminal | TIDAK ADA | untuk kerja panjang ada `job`; untuk shell manusia tidak ada | P3 |
| Escape sequence (`~.`), pindah ke port-forward di tengah sesi | ssh | TIDAK ADA | niche | P3 |
| Berbagi sesi / join sesi orang lain | Teleport, tmate | NON-GOAL | NG-TUI ("daemon/server") | – |

## 7. Job jangka panjang (tmux/screen/nohup, Ansible async)

| Kemampuan | Tools pembanding | Status komando | Bukti/catatan | Prioritas |
|---|---|---|---|---|
| Mulai proses terlepas yang bertahan saat SSH putus | nohup, setsid, tmux, screen | ADA | `job start TARGET -- CMD` (setsid nohup, log di `~/.komando/jobs/<id>`), banyak host | – |
| Status, exit code, runtime, tail log | `jobs`, tmux | ADA | `job status`, `job list --refresh --target` | – |
| Baca log inkremental | `tail -f` | ADA | `job logs --offset/next_offset`, `--tail`, `--max-bytes` | – |
| Tunggu selesai dengan batas waktu | Ansible `async_status`, `wait` | ADA | `job wait --wait-timeout --interval` | – |
| Hentikan (sinyal ke process group) | kill | ADA | `job kill --signal TERM|KILL|INT|HUP` | – |
| Bersihkan job | — | ADA | `job rm [--keep-remote]` | – |
| Jalankan skrip lokal sebagai job | Ansible `script` + async | TIDAK ADA | `job start` hanya menerima perintah; skrip panjang (`deploy.sh`) harus diunggah dulu (`upload` + `job start`) | P2 |
| Batas waktu maksimum job (bunuh otomatis setelah X) | `timeout`, Ansible `async: N` | TIDAK ADA | bisa lewat perintah `timeout 2h ...` di dalam job | P3 |
| Attach interaktif ke job / kirim input | tmux attach, screen -r | TIDAK ADA | job tidak punya stdin/TTY | P3 |
| Notifikasi saat job selesai | — | NON-GOAL | NG-MON ("monitoring atau alerting yang berjalan terus-menerus"); `job wait` cukup | – |
| Modul lambat otomatis jadi job (`pkg upgrade`, `db dump` di server) | Ansible async per task | TIDAK ADA | `pkg upgrade` berjalan sinkron dengan `--timeout` default 5m; agent harus ingat memakai `job start` + perintah mentah | P2 |

## 8. Tunnel dan forwarding (ssh `-L/-R/-D`, autossh, sshuttle)

| Kemampuan | Tools pembanding | Status komando | Bukti/catatan | Prioritas |
|---|---|---|---|---|
| Local forward `-L` | ssh | ADA | `tunnel start HOST -L [bind:]LPORT:RHOST:RPORT` | – |
| Remote forward `-R` | ssh | ADA | `tunnel start HOST -R ...` | – |
| SOCKS5 `-D` | ssh | ADA | `tunnel start HOST -D [bind:]PORT` | – |
| Tunnel ke conn berdasarkan nama (port lokal bebas) | Teleport `tsh proxy db`, Termius | ADA | `tunnel start app-db [--port 15432]` lewat `--via`/VPN | – |
| Tunnel di latar, list, stop | autossh `-f`, Termius | ADA | `tunnel list` (liveness, prune), `tunnel stop [--all]` | – |
| Reconnect otomatis saat SSH putus | autossh | SEBAGIAN | `connMgr` reconnect untuk forward local/dynamic; komentar kode menyebut hanya local/dynamic, remote forward (`-R`) tidak | P2 |
| Bind default ke 127.0.0.1; bind ke alamat lain butuh `--yes` | ssh `GatewayPorts` | SEBAGIAN | default 127.0.0.1 sudah benar, tapi `-L 0.0.0.0:8080:...` diterima tanpa `--yes` — network.md: "Tunnel dan proxy hanya mendengarkan di 127.0.0.1, kecuali diberi `--bind` (butuh `--yes`)". Membuka DB internal ke LAN tanpa konfirmasi | P1 |
| Tunnel bertahan setelah reboot laptop (service launchd/systemd) | autossh + systemd | NON-GOAL | NG-POOL/NG-TUI ("daemon"); tunnel hanya proses latar sementara | – |
| Batas umur tunnel (stop otomatis setelah X / saat idle) | Teleport TTL | TIDAK ADA | VPN punya `vpn_idle`, tunnel tidak; tunnel yang lupa dimatikan tetap membuka akses | P3 |
| "VPN lewat SSH" transparan (ubah rute laptop) | sshuttle | NON-GOAL | NG-NET: "komando tidak pernah mengubah rute, DNS, atau firewall laptop." Alternatif: `tunnel -D` + `vpn add ... socks` | – |
| Forward Unix socket (`-L /tmp/x.sock:/var/run/docker.sock`) | ssh | TIDAK ADA | spec hanya host:port | P3 |

## 9. File dan transfer (scp, sftp, rsync, Ansible copy/fetch/synchronize/get_url/unarchive)

| Kemampuan | Tools pembanding | Status komando | Bukti/catatan | Prioritas |
|---|---|---|---|---|
| Upload file ke banyak server paralel | scp, pssh `pscp`, Ansible `copy` | ADA | `upload TARGET FILE [DEST]`, `cp SRC TARGET:PATH`, sha256 dilaporkan | – |
| Upload dengan mode, buat folder induk, pasang via sudo | Ansible `copy mode/become` | SEBAGIAN | `--mode`, `-p`, `--sudo` hanya untuk satu file (folder + sudo ditolak), tidak ada `--owner` di upload (ada di `fs write`) | P2 |
| Download dari banyak server (folder per server) | scp, Ansible `fetch` | ADA | `download @web PATH --to DIR` → `DIR/<host>/...` | – |
| Download file milik root (`/var/log/...`, `/etc/shadow`-like) | Ansible `fetch become` | TIDAK ADA | `download` tidak punya `--sudo` (`fs cat --sudo` hanya untuk teks ≤ 1 MiB) | P2 |
| Rekursif folder | scp `-r`, sftp | ADA | `-r` di upload/download | – |
| Tidak menimpa tanpa `--overwrite` | scp `-n`, rsync `--ignore-existing` | TIDAK ADA | upload ke server menimpa diam-diam; download dari server membuka file lokal dengan `O_TRUNC` (hanya storage yang "never overwrite"). Bertentangan dengan edge case ux.md: "File tujuan sudah ada: tidak ditimpa tanpa `--overwrite`" | P1 |
| Download atomik (tmp lalu rename; tidak ada file setengah jadi) | rsync | TIDAK ADA | `fetchFile` menulis langsung ke tujuan. ux.md: "Unduhan terputus: tulis ke file sementara lalu rename" | P1 |
| File besar tanpa memuat ke memori (stream) | scp, rsync | TIDAK ADA | upload satu file memakai `os.ReadFile` (seluruh file ke RAM) lalu `writeRemote`; dump DB/ISO/backup GB bisa kehabisan memori | P1 |
| Progress di stderr untuk file besar | scp, rsync `--progress` | TIDAK ADA | ux.md edge case: "file sangat besar (progress di stderr)" | P2 |
| Lanjutkan transfer terputus (resume) | rsync `--partial`, sftp `reget` | TIDAK ADA | ada di FTP storage, tidak untuk SFTP host | P3 |
| Sinkronisasi delta (hanya yang berubah), `--delete`, `--exclude` | rsync, Ansible `synchronize` | TIDAK ADA | `upload -r` menyalin ulang semua file, tidak menghapus file lama, tanpa exclude. Deploy situs/folder adalah pekerjaan harian; vision mencantumkan verb `sync` | P1 |
| Dry-run transfer yang menunjukkan file apa yang akan berubah | rsync `-n -i` | SEBAGIAN | `--dry-run` ada di `cp`, tapi tidak membandingkan isi (tidak ada daftar changed/unchanged) | P2 |
| Lewati upload bila isi sama (idempoten) | Ansible `copy` (checksum) | SEBAGIAN | `fs write --from FILE --if-changed` untuk satu file; `upload`/`cp` tidak | P2 |
| Pertahankan symlink | rsync `-l`, scp | TIDAK ADA | upload/download rekursif melewati non-regular file (symlink) tanpa laporan | P2 |
| Pertahankan waktu modifikasi (`-p`) | scp `-p`, rsync `-t` | TIDAK ADA | mode dipertahankan, mtime tidak | P3 |
| Kompresi saat transfer | rsync `-z`, scp `-C` | TIDAK ADA | SFTP tanpa kompresi; kompres manual (`tar czf`) lewat exec | P3 |
| Salin server → server (remote ke remote) | scp `host1:a host2:b`, rsync | TIDAK ADA | harus download lalu upload | P3 |
| Salin file di dalam satu server | Ansible `copy remote_src` | TIDAK ADA | `fs mv` ada, `fs cp` tidak; bisa lewat exec `cp` | P3 |
| Unduh URL langsung di server (dengan checksum) | Ansible `get_url`, `curl -o` | TIDAK ADA | bisa lewat exec `curl -o`; pola curl-pipe-sh diblok policy (bagus) | P2 |
| Ekstrak arsip di server | Ansible `unarchive` | TIDAK ADA | bisa lewat exec `tar xzf` | P3 |
| Browsing interaktif ala sftp shell | sftp, Cyberduck | NON-GOAL | NG-TUI; `fs ls/stat/cat` menutup versi non-interaktif | – |

## 10. Edit file dan konfigurasi (Ansible lineinfile/blockinfile/template/file)

| Kemampuan | Tools pembanding | Status komando | Bukti/catatan | Prioritas |
|---|---|---|---|---|
| Baca file (head/tail/line numbers, batas byte, sudo) | cat, Ansible `slurp` | ADA | `fs cat --head --tail --line-numbers --max-bytes --sudo` | – |
| Ganti teks persis / regex, gagal bila tidak ada/ambigu, dengan diff & backup | Ansible `replace`, `sed -i` | ADA | `fs replace --old --new [--regex --all --backup]`; `--dry-run` menampilkan diff | – |
| Pastikan satu baris ada (tambahkan bila belum ada, ganti bila cocok regex) | Ansible `lineinfile` | SEBAGIAN | `fs replace --regex` gagal bila tidak ditemukan; `fs write --append` tidak idempoten. Butuh dua langkah dan logika di agent (mis. `PasswordAuthentication no` di sshd_config) | P2 |
| Hapus baris yang cocok | Ansible `lineinfile state=absent` | SEBAGIAN | `fs replace --regex --new ''` meninggalkan baris kosong | P3 |
| Blok terkelola dengan marker (`# BEGIN komando x` / `# END`) | Ansible `blockinfile` | TIDAK ADA | pola marker sudah dipakai `cron` (`# komando:<id>`), belum untuk file | P2 |
| Tulis file atomik, mode/owner, backup, idempoten | Ansible `copy content=` | ADA | `fs write --content/--from/stdin --mode --owner --backup --if-changed --parents` | – |
| Diff saat dry-run `fs write` | `ansible --check --diff` | TIDAK ADA | dry-run `fs write` hanya melaporkan jumlah byte, tidak membandingkan isi lama (padahal `fs replace` sudah punya `unifiedDiff`). Aturan agent no. 4 mewajibkan `--dry-run` dulu, tapi untuk `fs write` tidak terlihat apa yang berubah | P1 |
| Render template dengan variabel | Ansible `template` (Jinja2), pyinfra `files.template` | TIDAK ADA | `{{var}}` hanya untuk perintah recipe | P2 |
| Validasi file sebelum dipasang (`validate: nginx -t -c %s`, `visudo -cf`) | Ansible `validate` | TIDAK ADA | salah edit `sudoers`/`sshd_config` lewat `fs write/replace` bisa mengunci akses ke server (agent kehilangan jalan kembali); recipe `nginx-test` hanya cek setelah ditulis | P1 |
| mkdir -p, mv, chmod (rekursif), rm (rekursif) | Ansible `file` | ADA | `fs mkdir/mv/chmod/rm` (+`--sudo`) | – |
| chown / chgrp mandiri | Ansible `file owner=` | TIDAK ADA | hanya lewat `fs write/replace --owner`; tidak ada `fs chown` (rekursif) | P2 |
| Buat symlink | Ansible `file state=link`, `ln -s` | TIDAK ADA | `fs stat/ls` mengenali symlink, tapi tidak bisa membuat | P2 |
| touch / ubah mtime | Ansible `file state=touch` | TIDAK ADA | `fs write --content ''` menimpa isi | P3 |
| stat (exists, ukuran, mode, sha256) | Ansible `stat` | ADA | `fs stat [--sha256]` (`exists:false` bukan error) | – |
| ls (rekursif, dotfiles, batas) | ls, sftp | ADA | `fs ls -a -r --max` | – |
| Cari file (nama/ukuran/umur) | find, Ansible `find` | SEBAGIAN | recipe `big-files`, `big-dirs`; tidak ada `fs find` terstruktur | P3 |
| Cari isi (grep di file/folder) | grep -r | SEBAGIAN | `logs --file --grep` untuk satu file; bisa lewat exec `grep -r` | P3 |
| Restore dari `.bak` | — | TIDAK ADA | `--backup` membuat `PATH.bak` (satu generasi), tidak ada `fs restore`/rollback; harus `fs mv` manual | P2 |
| Edit di editor lokal ($EDITOR) lalu simpan balik | `vim scp://`, VS Code Remote | TIDAK ADA | berguna untuk manusia; bisa lewat download→edit→`fs write --if-changed` | P3 |

## 11. Service (systemctl/service, Ansible `service`/`systemd`)

| Kemampuan | Tools pembanding | Status komando | Bukti/catatan | Prioritas |
|---|---|---|---|---|
| Status terstruktur | systemctl show | ADA | `svc status TARGET UNIT...` (active_state, sub_state, main_pid, n_restarts, memory) | – |
| start/stop/restart/reload + laporan state + journal saat gagal | systemctl, Ansible `systemd` | ADA | `svc start/stop/restart/reload` (journal 20 baris bila gagal) | – |
| enable/disable | systemctl | ADA | `svc enable/disable` | – |
| enable `--now` dalam satu langkah | Ansible `enabled+state` | TIDAK ADA | dua perintah | P3 |
| Daftar unit + filter failed/state | systemctl list-units | ADA | `svc list --failed --state` | – |
| `daemon-reload` setelah mengubah unit file | systemctl, Ansible `daemon_reload` | TIDAK ADA | tidak ada di `svc`; alur agent "tulis unit → reload → restart" harus memakai `exec` | P1 |
| mask/unmask | systemctl | TIDAK ADA | bisa lewat exec | P3 |
| Lihat unit file & drop-in (`systemctl cat`) | systemctl cat | TIDAK ADA | bisa lewat `fs cat` bila tahu path; bisa lewat exec | P2 |
| Buat/ubah override drop-in (`systemctl edit`) | systemctl edit | TIDAK ADA | bisa lewat `fs write` ke `/etc/systemd/system/X.d/override.conf` + daemon-reload (yang tidak ada) | P2 |
| Daftar & kelola systemd timer | systemctl list-timers | SEBAGIAN | recipe `cron-all` menampilkan `list-timers`; tidak terstruktur, tidak bisa membuat | P3 |
| User unit (`systemctl --user`) | systemctl --user | SEBAGIAN | `--no-sudo` disebut "untuk --user units" tapi tidak ada flag `--user`; harus exec | P3 |
| Init non-systemd (OpenRC/Alpine, sysvinit) | Ansible `service` | TIDAK ADA | `svc` hanya systemd (padahal `pkg` mendukung apk) | P3 |
| Validasi config sebelum reload (nginx -t, apachectl configtest) | Ansible handlers | SEBAGIAN | recipe `nginx-test`, `apache-test`; `svc reload` tidak memvalidasi | P3 |

## 12. Paket (apt/dnf/yum/apk/zypper/pacman, Ansible `package`)

| Kemampuan | Tools pembanding | Status komando | Bukti/catatan | Prioritas |
|---|---|---|---|---|
| Install / remove / update index / upgrade (semua manajer, auto-detect) | apt, dnf, Ansible `package` | ADA | `pkg install/rm/update/upgrade`, `DEBIAN_FRONTEND=noninteractive` | – |
| Daftar upgrade tertunda | apt list --upgradable | SEBAGIAN | `pkg upgradable` ada, tapi output teks mentah per manajer (bukan baris terstruktur name/current/candidate) | P2 |
| Hanya update keamanan | unattended-upgrades, `dnf upgrade --security` | SEBAGIAN | recipe `security-updates` hanya membaca; `pkg upgrade` tidak punya `--security` | P2 |
| Versi terinstal | dpkg-query, rpm -q | ADA | `pkg installed [PKG...]` (tab-separated) | – |
| Cari paket / info paket | apt search, dnf info | TIDAK ADA | bisa lewat exec | P3 |
| Install versi tertentu | `apt install x=1.2` | SEBAGIAN | apt `nginx=1.24*` lolos validasi nama; tidak ada sintaks lintas-manajer | P3 |
| Hold/pin versi (cegah upgrade) | apt-mark hold, dnf versionlock | TIDAK ADA | penting untuk kernel/DB di produksi | P2 |
| Tambah repo/PPA + kunci GPG | Ansible `apt_repository`, `yum_repository` | TIDAK ADA | bisa lewat `fs write` + exec | P2 |
| Autoremove / bersihkan cache | apt autoremove | SEBAGIAN | recipe `apt-clean` (apt saja) | P3 |
| dist-upgrade / full-upgrade | apt full-upgrade | TIDAK ADA | `pkg upgrade` = `apt-get upgrade` (paket yang butuh dependensi baru tertahan) | P3 |
| Deteksi reboot diperlukan setelah upgrade | needrestart, `/var/run/reboot-required` | ADA | `facts` → `reboot_required` | – |
| Pasang dari file .deb/.rpm lokal | apt install ./x.deb | TIDAK ADA | `upload` + exec | P3 |
| Paket non-OS (snap, flatpak, pip, npm global) | Ansible `snap`, `pip` | TIDAK ADA | NG-FULL — bisa lewat exec | P3 |

## 13. User dan akses (useradd, Ansible `user`/`group`/`authorized_key`, sudoers)

| Kemampuan | Tools pembanding | Status komando | Bukti/catatan | Prioritas |
|---|---|---|---|---|
| Daftar user (manusia / semua) + anggota sudo | getent, Ansible | ADA | `user list [--all]` | – |
| Buat user idempoten + key SSH + sudo | Ansible `user` + `authorized_key` | ADA | `user add TARGET NAME --key/--pubkey --admin --shell` | – |
| Kunci akun | usermod -L | ADA | `user lock` | – |
| Buka kunci akun | usermod -U, chage -E -1 | TIDAK ADA | `lock` bisa dibalik secara konsep tapi tidak ada `user unlock`; harus exec | P2 |
| Hapus user (dangerous) | userdel | ADA | `user rm [--remove-home]` (butuh `--allow-dangerous`) | – |
| Cabut key SSH dari user | Ansible `authorized_key state=absent` | TIDAK ADA | lihat §2 (offboarding) | P1 |
| Kelola grup (groupadd, tambah/hapus anggota grup apa pun, mis. `docker`) | Ansible `group`, usermod -aG | TIDAK ADA | `--admin` hanya sudo/wheel | P2 |
| Aturan sudoers terbatas (NOPASSWD untuk perintah tertentu) + validasi visudo | Ansible `community.general.sudoers` | TIDAK ADA | recipe `sudoers` hanya membaca; menulis sudoers tanpa validasi bisa mengunci akses | P2 |
| Set/expire password user | passwd, chage, Ansible `user password` | TIDAK ADA | sengaja tidak ada lebih aman; bila ditambah harus lewat ref vault | P3 |
| Ubah shell/home/UID user yang sudah ada | usermod | TIDAK ADA | `user add` tidak mengubah user yang sudah ada | P3 |
| Login terakhir / gagal login | last, lastlog, auth.log | ADA | recipe `last-logins`, `auth-failures` (teks) | – |
| Hardening sshd (lihat setting efektif) | sshd -T | ADA | recipe `sshd-config` (baca); ubah lewat `fs replace --backup` | – |

## 14. Cron dan penjadwalan (crontab, Ansible `cron`, systemd timer)

| Kemampuan | Tools pembanding | Status komando | Bukti/catatan | Prioritas |
|---|---|---|---|---|
| Entri crontab idempoten berdasarkan ID | Ansible `cron name=` | ADA | `cron set TARGET ID CMD --schedule`, marker `# komando:<id>` | – |
| Daftar entri (dengan ID) | crontab -l | ADA | `cron list` (baris + id) | – |
| Hapus entri | Ansible `cron state=absent` | ADA | `cron rm` | – |
| Crontab user lain | crontab -u | ADA | `--user NAME --sudo` | – |
| Semua cron sistem (/etc/crontab, /etc/cron.d, semua user) | — | ADA | recipe `cron-all` (teks) | – |
| Validasi jadwal | — | SEBAGIAN | hanya cek 5 field atau `@daily`; nilai tidak divalidasi (mis. `61 * * * *`) | P3 |
| Env cron (MAILTO, PATH, SHELL) | Ansible `cronvar` | TIDAK ADA | `cron set` hanya baris jadwal; env bisa ditulis di dalam perintah | P3 |
| Nonaktifkan sementara tanpa menghapus | Ansible `cron disabled=yes` | TIDAK ADA | hanya `cron rm` lalu `cron set` ulang | P3 |
| File di `/etc/cron.d` | Ansible `cron cron_file=` | TIDAK ADA | bisa lewat `fs write` | P3 |
| Buat systemd timer | systemd | TIDAK ADA | bisa lewat `fs write` unit + exec | P3 |
| Jadwal sekali jalan (`at`) | at | TIDAK ADA | `job start -- 'sleep 3600; ...'` sebagai gantinya | P3 |

## 15. Log (journalctl, file log, logrotate)

| Kemampuan | Tools pembanding | Status komando | Bukti/catatan | Prioritas |
|---|---|---|---|---|
| journald per unit, since/until, priority, grep, limit | journalctl | ADA | `logs --unit --since --until --priority --grep -n` | – |
| File log (tail/grep, sudo) | tail, grep | ADA | `logs --file PATH --grep -n --sudo` | – |
| Ikuti terus (`-f`) termasuk banyak host | journalctl -f, tail -F, multitail | ADA | `logs --follow` (NDJSON stream per host) | – |
| Log container | docker logs | ADA | `logs --container` | – |
| Log kernel / boot tertentu (`-k`, `-b -1`) | journalctl -k/-b, dmesg | SEBAGIAN | recipe `oom` dan `journal-errors`; `logs` tidak punya `--kernel`/`--boot` | P2 |
| Log terstruktur (field journald sebagai JSON) | journalctl -o json | TIDAK ADA | output baris teks `short-iso` | P3 |
| File log terkompresi/terotasi (`.gz`, `.1`) | zgrep, lnav | TIDAK ADA | `--file` satu path; bisa lewat exec `zgrep` | P3 |
| Beberapa unit sekaligus | journalctl -u a -u b | TIDAK ADA | `--unit` satu nilai | P3 |
| Atur logrotate / paksa rotate | logrotate | TIDAK ADA | `fs write` ke `/etc/logrotate.d` + exec | P3 |
| Kecilkan journal | journalctl --vacuum | ADA | recipe `journal-vacuum` | – |

## 16. Facts, proses, disk (facts/grains, htop, iotop, ncdu, lsof)

| Kemampuan | Tools pembanding | Status komando | Bukti/catatan | Prioritas |
|---|---|---|---|---|
| Facts terstruktur (OS, kernel, arch, CPU, RAM, swap, load, uptime, IP, virt, init, pkg manager, tools, reboot_required, failed_units, timezone) | Ansible setup, Salt grains | ADA | `facts TARGET` | – |
| Facts semua mount/disk, NIC, hardware (DMI), versi tool | Ansible setup | SEBAGIAN | facts hanya disk root; recipe `disk`/`inodes` memberi teks | P3 |
| Ringkasan kesehatan | — | ADA | recipe `health`, `memory`, `failed-units`, `time-sync` | – |
| Proses top CPU/memori, cari proses | ps, htop | ADA | recipe `top-cpu`, `top-mem`, `process` (teks) | – |
| Daftar proses terstruktur (JSON) | ps, Salt `ps` | TIDAK ADA | hanya teks lewat recipe | P2 |
| Kill proses dengan aman (PID/nama, sinyal, konfirmasi) | kill, pkill, Ansible | TIDAK ADA | bisa lewat exec `kill`; tidak ada laporan proses mana yang kena | P2 |
| Monitor interaktif (htop, top, iotop, ncdu) | htop, iotop, ncdu | NON-GOAL | NG-TUI ("TUI ... komando tetap CLI murni"); versi sekali-jalan: recipe `top-*`, `big-dirs` | – |
| I/O disk per proses / iostat | iotop, iostat | TIDAK ADA | `memory` recipe memakai vmstat; I/O tidak ada | P3 |
| Penggunaan disk & folder/file terbesar | df, du, ncdu | ADA | recipe `disk`, `inodes`, `big-dirs`, `big-files` | – |
| File terbuka / siapa memegang file/port | lsof, fuser | SEBAGIAN | `net ports --sudo` memberi proses per port; file terbuka tidak ada | P3 |
| OOM kill terbaru | dmesg | ADA | recipe `oom` | – |

## 17. Jaringan dari server (ss, dig, curl, mtr, traceroute, nmap)

| Kemampuan | Tools pembanding | Status komando | Bukti/catatan | Prioritas |
|---|---|---|---|---|
| Cek TCP port tujuan dari server (banyak sekaligus) | nc -z, Ansible `wait_for` | ADA | `net check TARGET HOST:PORT...` (terstruktur) | – |
| HTTP dari server (status, timing, IP) | curl -w | ADA | `net http TARGET URL` | – |
| DNS resolve dari server | getent, dig | SEBAGIAN | `net dns` memakai `getent ahosts` (A/AAAA saja); tidak bisa pilih tipe record (MX/TXT/CNAME), resolver tertentu, atau TTL | P2 |
| Port listening + proses | ss -tulpn, netstat | ADA | `net ports [--sudo]` | – |
| Statistik koneksi | ss -s | ADA | recipe `connections` | – |
| Ping / latensi ICMP | ping | TIDAK ADA | bisa lewat exec | P2 |
| Traceroute / mtr | traceroute, mtr | TIDAK ADA | bisa lewat exec bila terpasang | P2 |
| Cek sertifikat TLS terstruktur (expiry hari, issuer, SAN) | openssl s_client, certbot certificates | SEBAGIAN | recipe `cert-expiry`, `certbot-certs` (teks); tidak ada "sisa hari" untuk agent. vision: "sertifikat/ACME" kandidat setelah v1.0 | P2 |
| Tunggu sampai port/URL siap (`wait_for`) | Ansible `wait_for`, `wait-for-it` | TIDAK ADA | `net check` sekali jalan, tanpa `--wait`/retry | P2 |
| Route, interface, ARP | ip route/addr | SEBAGIAN | `facts` → `ips`; route tidak ada | P3 |
| Scan port host lain | nmap | TIDAK ADA | sensitif keamanan; bisa lewat exec | P3 |
| Bandwidth antar server | iperf3 | TIDAK ADA | bisa lewat exec bila iperf3 terpasang | P3 |
| IP publik/egress server | `curl ifconfig.me` | TIDAK ADA | `net http` ke layanan IP bisa dipakai | P3 |
| Tangkap paket | tcpdump | TIDAK ADA | bisa lewat `job start` + `download` | P3 |
| Cek dari laptop ke server (bukan dari server) | nc, ssh -v | ADA | `test TARGET` | – |

## 18. Konfigurasi sistem (sysctl, mount/fstab, firewall, hostname/timedatectl, reboot, wait_for, certbot, git)

| Kemampuan | Tools pembanding | Status komando | Bukti/catatan | Prioritas |
|---|---|---|---|---|
| Reboot terkendali + tunggu server kembali + verifikasi | Ansible `reboot`, pyinfra `server.reboot` | TIDAK ADA | `reboot` diblok policy (benar), dengan `--allow-dangerous` putus koneksi tanpa menunggu/memverifikasi. Alur patch (`pkg upgrade` → `facts.reboot_required` → reboot → tunggu → `test`) tidak bisa diselesaikan agent secara aman | P1 |
| Status firewall | ufw status, firewall-cmd | ADA | recipe `firewall` (ufw/firewalld/nftables/iptables, teks) | – |
| Kelola aturan firewall (allow/deny port, sumber) dengan pengaman anti-lockout (port SSH) | ufw, firewalld, Ansible `ufw`/`firewalld` | TIDAK ADA | policy memblok flush; menambah aturan harus exec. Anti-lockout tidak ada | P2 |
| sysctl get/set (+ persist ke `/etc/sysctl.d`) | sysctl, Ansible `sysctl` | TIDAK ADA | bisa lewat exec + `fs write` | P3 |
| mount / fstab (tambah, mount, unmount) | mount, Ansible `mount` | TIDAK ADA | berisiko (salah fstab = gagal boot); bisa lewat exec | P3 |
| Swap file | mkswap, Ansible | TIDAK ADA | bisa lewat exec; `facts` membaca swap | P3 |
| Hostname set | hostnamectl, Ansible `hostname` | TIDAK ADA | `facts` membaca hostname | P3 |
| Timezone / NTP set | timedatectl, Ansible `timezone` | SEBAGIAN | recipe `time-sync` dan `facts.timezone` membaca; set tidak ada | P3 |
| Locale | localectl | TIDAK ADA | bisa lewat exec | P3 |
| Sertifikat Let's Encrypt (issue/renew) | certbot, acme.sh | SEBAGIAN | recipe `certbot-certs` membaca; renew/issue lewat exec. vision: ACME kandidat setelah v1.0 | P3 |
| Git checkout/pull di server (deploy) | Ansible `git` | TIDAK ADA | contoh recipe `deploy-app` memakai `git pull` lewat exec | P3 |
| SELinux/AppArmor status & mode | Ansible `selinux` | TIDAK ADA | bisa lewat exec | P3 |
| Kernel module / limits.conf | Ansible `modprobe`, `pam_limits` | TIDAK ADA | bisa lewat exec / `fs write` | P3 |
| Bersihkan page cache, docker prune, apt clean | — | ADA | recipe `drop-caches`, `docker-prune`, `apt-clean` | – |

## 19. Recipe / snippet (Termius snippets, Fabric tasks, Salt modules)

| Kemampuan | Tools pembanding | Status komando | Bukti/catatan | Prioritas |
|---|---|---|---|---|
| 39 recipe bawaan (health, disk, certs, security, network, db, web) | Termius snippets, Salt modules | ADA | `recipe list [--category]`, `recipe run NAME TARGET` | – |
| Recipe sendiri dengan blank `{{var}}` dan default `{{var=x}}` | Termius snippets, Fabric | ADA | `recipe add --desc --sudo --read-only --overwrite`, `--var` | – |
| Recipe dianggap write kecuali `--read-only` | — | ADA | ux.md §3 polaritas | – |
| Berbagi recipe ke tim / mesin lain | Termius team vault | ADA | ikut `export`/`import komando` | – |
| Recipe multi-langkah / berisi file (skrip) | Fabric tasks, Ansible roles | TIDAK ADA | recipe = satu baris perintah; skrip panjang lewat `script` | P3 |
| Output recipe terstruktur (parser) | Salt modules | TIDAK ADA | recipe bawaan mengembalikan teks; yang penting sudah punya perintah terstruktur (`svc`, `net`, `facts`) | P3 |
| Katalog recipe komunitas / plugin | Ansible Galaxy, Salt formulas | NON-GOAL | NG-TUI: "... sistem plugin ..." | – |

## 20. Keamanan, akses, dan audit (Teleport tsh, Tailscale SSH)

| Kemampuan | Tools pembanding | Status komando | Bukti/catatan | Prioritas |
|---|---|---|---|---|
| Audit setiap aksi (siapa, apa, di mana, hasil) | Teleport audit log | ADA | `audit --command --failed --limit --target`; `KOMANDO_ACTOR`; gagal tertutup bila audit tak bisa ditulis | – |
| Filter audit berdasarkan waktu / export | Teleport | SEBAGIAN | tidak ada `--since/--until`; file `audit.jsonl` bisa dibaca | P3 |
| Kirim audit ke pusat (syslog/SIEM/webhook) | Teleport, auditd | TIDAK ADA | audit hanya lokal per laptop; tim tidak bisa melihat aksi agent di mesin lain | P2 |
| Konfirmasi manusia untuk target produksi & perintah berbahaya | Teleport access requests | ADA | protected → `--yes`/prompt `[y/N]`; dangerous → ketik ulang nama; agent tidak bisa menjawab prompt | – |
| Approval jarak jauh (minta izin orang lain, just-in-time access) | Teleport access requests | NON-GOAL | butuh server; NG-TUI "daemon/server" | – |
| RBAC multi-user terpusat | Teleport roles | NON-GOAL | NG-TUI "daemon/server"; pengganti: user SSH dengan hak minimum (docs/features/safety.md) | – |
| Session recording | Teleport | TIDAK ADA | lihat §6 | P3 |
| Secret tidak pernah di argumen/output/audit | — | ADA | vault AES-256-GCM, `SECRET_IN_ARGS`, ref eksternal (1Password, Vault, AWS SM, GCP SM) | – |
| Policy perintah berbahaya yang bisa ditambah | — | ADA | `policy deny REGEX`, `policy check` | – |
| Allowlist (hanya perintah tertentu yang boleh untuk agent) | Teleport `command` restrictions, `authorized_keys command=` | TIDAK ADA | policy hanya deny-list; mode "agent hanya boleh read-only" global tidak ada | P2 |

---

## Ringkasan hitungan

Total 270 kemampuan dinilai.

| Status | Jumlah |
|---|---|
| ADA | 103 |
| SEBAGIAN | 36 |
| TIDAK ADA | 117 |
| NON-GOAL | 14 |

| Prioritas celah (SEBAGIAN + TIDAK ADA) | Jumlah |
|---|---|
| P1 | 11 (celah "cabut key" muncul di dua tabel, §2 dan §13) |
| P2 | 57 |
| P3 | 85 |

## 10 celah P1 teratas

1. **Cabut key SSH dari `authorized_keys`** (offboarding/rotasi; `key deploy`/`user add` hanya menambah) — §2, §13.
2. **Sinkronisasi folder (delta, `--delete`, `--exclude`, dry-run daftar perubahan)** untuk deploy — §9.
3. **Transfer tidak menimpa tanpa `--overwrite`** (upload dan download server menimpa diam-diam; melanggar ux.md) — §9.
4. **Download atomik (tmp + rename)** — §9.
5. **Upload file besar secara streaming** (sekarang `os.ReadFile` seluruh file ke RAM) — §9.
6. **Reboot terkendali + tunggu kembali + verifikasi** untuk alur patch — §18.
7. **`svc daemon-reload`** untuk alur "tulis unit → reload → restart" — §11.
8. **Tunnel bind non-loopback tanpa `--yes`** (bertentangan dengan network.md) — §8.
9. **Diff saat `fs write --dry-run`** (dry-run wajib bagi agent tapi tidak menunjukkan perubahan) — §10.
10. **Validasi file sebelum dipasang** (`visudo -cf`, `sshd -t`, `nginx -t`) agar edit tidak mengunci akses — §10.

Kandidat P2 terkuat berikutnya: `ProxyCommand`/transport AWS SSM, GCP IAP, Cloudflare Access (§1), rolling batch `serial` (§5), `download --sudo` (§9), `lineinfile` idempoten (§10), dan SSH certificate (§1, §3).
