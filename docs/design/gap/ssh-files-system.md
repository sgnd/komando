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
| Password login (tersimpan aman) | ssh + sshpass | SEBAGIAN | login password jalan lewat ref `secret:/env:/file:/op:///vault:/aws-sm:/gcp-sm:` (password + keyboard-interactive). Tapi `host add/edit` tidak memvalidasi bentuk ref: `--password-ref hunter2` (juga `--sudo-ref`) diterima, disimpan polos di `state.json` dan dicetak di output. `conn add` dan `vpn add` sudah menolaknya lewat `vault.ValidRef`, host belum | P1 |
| Keyboard-interactive / 2FA SSH (OTP Google Authenticator, Duo) | ssh, Teleport | SEBAGIAN | keyboard-interactive dijawab dengan password untuk semua pertanyaan; OTP tidak bisa. `shell` interaktif pun memakai jawaban otomatis yang sama. Sejalan dengan prinsip "MFA selalu oleh manusia" (network.md), tapi belum ada jalur manusia untuk SSH MFA (mis. prompt di `shell`/`test` interaktif) | P3 |
| `IdentitiesOnly` (batasi key yang dicoba, hindari "Too many authentication failures") | ssh_config | SEBAGIAN | bila `--key/--identity` diset, key default tidak dicoba; key eksplisit dicoba dulu, lalu semua key ssh-agent tetap ikut dicoba sesudahnya (tidak ada opsi mematikan agent per host) | P2 |
| `IdentityAgent` per host (agent berbeda per host) | ssh_config | TIDAK ADA | hanya `SSH_AUTH_SOCK` global | P3 |
| Jump host / bastion (`-J`, `ProxyJump`), rantai banyak lompatan | ssh, Teleport | ADA | `--via bastion,db1` untuk host dan conn; `--jump` alias; diimpor dari `ProxyJump` | – |
| `ProxyCommand` (mis. `aws ssm start-session`, `cloudflared access ssh`, `gcloud compute start-iap-tunnel`) | ssh_config, Teleport | TIDAK ADA | `parseSSHConfig` mengabaikan `ProxyCommand` (tanpa laporan); tidak ada transport SSM/IAP/Cloudflare Access. Umum di cloud tanpa IP publik | P2 |
| Akses lewat VPN per koneksi (banyak VPN sekaligus) | tsh, Tailscale SSH, klien VPN | ADA | `vpn add` (wireguard, tailscale, openconnect family, openvpn, socks, system) + `--via vpn,bastion` | – |
| Tailscale SSH (auth berbasis identitas tailnet, tanpa key) | Tailscale SSH | SEBAGIAN | `vpn add ... tailscale` memberi jalur, tapi komando tetap butuh metode auth (`NO_AUTH` bila tidak ada key/agent/password) | P3 |
| SSH certificate login (user cert ditandatangani CA, `CertificateFile`) | OpenSSH CA, Teleport, Vault SSH, step-ca | SEBAGIAN | user cert yang sudah dimuat di ssh-agent ikut terpakai (signer dari agent membawa cert-nya); tidak ada `CertificateFile`/flag cert per host atau per key, jadi cert berbasis file tidak bisa dipakai. Penting untuk tim yang memakai short-lived cert | P2 |
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
| Buat key pair ed25519 / RSA | ssh-keygen | ADA | `key gen NAME --type ed25519\|rsa --bits --comment` | – |
| Buat key ECDSA | ssh-keygen `-t ecdsa` | TIDAK ADA | `--type` hanya ed25519/rsa (key ECDSA yang sudah ada bisa `key add`) | P3 |
| Key hardware FIDO2 (`ed25519-sk`, YubiKey) | ssh-keygen `-t ed25519-sk` | SEBAGIAN | hanya bila key sk ada di ssh-agent; `key gen` tidak bisa membuat | P3 |
| Passphrase saat membuat key | ssh-keygen `-N` | TIDAK ADA | `key gen` menulis private key tanpa enkripsi (0600, `ssh.MarshalPrivateKey`). Secure-by-default menyarankan opsi `--passphrase-ref` | P2 |
| Daftarkan key yang sudah ada | ssh-add / ssh_config | ADA | `key add NAME PATH [--passphrase-ref]` (file tidak disalin) | – |
| Lihat public key dan fingerprint | ssh-keygen `-y`, `-l` | ADA | `key show`, `key list` (fingerprint SHA256 disimpan di state) | – |
| Pasang public key ke server (idempoten) | ssh-copy-id, Ansible `authorized_key` | ADA | `key deploy KEY TARGET [--set-default]`, banyak host paralel | – |
| Cabut / hapus public key dari `authorized_keys` di banyak server (offboarding, rotasi) | Ansible `authorized_key state=absent`, Teleport | TIDAK ADA | `key deploy` dan `user add --key` hanya menambah. Saat anggota tim keluar atau key bocor, tidak ada perintah untuk banyak server sekaligus; per host bisa `fs replace HOST ~/.ssh/authorized_keys --old '<baris key>' --new '' --backup` (satu host per perintah, baris harus disalin persis, tanpa lookup dari keychain) | P1 |
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
| Host certificate / `@cert-authority` di known_hosts | OpenSSH, Teleport | SEBAGIAN | parser known_hosts (x/crypto) membaca baris `@cert-authority` bila ditulis manual ke `~/.komando/known_hosts`, tapi tidak ada perintah untuk menambah CA. Tanpa baris itu, host yang menyajikan host cert gagal (`CONNECT_FAILED`: "no authorities for hostname"), bukan TOFU | P2 |
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
| Cek sudo berfungsi saat `test` | `ansible -b -m ping` | SEBAGIAN | `test` sudah melaporkan `sudo_nopasswd` (`sudo -n true`); password dari `--sudo-ref` tidak diuji, jadi sudo-ref yang salah baru ketahuan saat perintah pertama | P2 |
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
| stdin dari file lokal | pssh `-I`, ssh `< file` | ADA | `--stdin-file FILE\|-` | – |
| Jalankan skrip lokal di remote tanpa menyalin | Ansible `script`, pyinfra, `ssh 'bash -s' < x` | ADA | `script TARGET FILE --arg --interpreter` | – |
| PTY untuk tool yang memintanya | ssh `-t` | ADA | `--pty` (non-interaktif) | – |
| Dry-run / check mode | `ansible --check`, pyinfra `--dry` | ADA | `--dry-run` global (tampilkan perintah + apakah diblok policy) | – |
| Guardrail perintah berbahaya | — (Teleport hanya RBAC) | ADA | `policy list/check/deny/allow`, `--allow-dangerous` | – |
| Deklarasi read-only untuk host protected | — | ADA | `--read-only` | – |
| Batas waktu per host dan batas output | pssh `-t`, Ansible `timeout` | ADA | `--timeout`, `--max-output` | – |
| Batas eksekusi async (`async`/`poll`) | Ansible async | ADA | via `job start` (lihat §7) | – |
| Interaktif ke banyak terminal sekaligus (ketik sekali, semua host) | ClusterSSH, tmux synchronize-panes, Termius multi-exec | NON-GOAL | NG-TUI: "GUI, TUI ... komando tetap CLI murni." `exec` paralel sudah menutup kebutuhan non-interaktifnya | – |
| Playbook / state deklaratif (orkestrasi banyak langkah, handler) | Ansible playbook, Salt state, pyinfra deploy | NON-GOAL | NG-IaC: "Infrastructure as Code, provisioning cloud, atau GitOps." | – |
| Perintah lokal di laptop sebagai bagian alur | Fabric `local` | TIDAK ADA | tidak dikecualikan eksplisit oleh vision.md ("Bukan tujuan" tidak menyebut perintah lokal); nilainya kecil karena manusia/agent sudah punya shell lokal | P3 |

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
| Hentikan (sinyal ke process group) | kill | ADA | `job kill --signal TERM\|KILL\|INT\|HUP` | – |
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
| Download file milik root (`/var/log/...`, `/etc/shadow`-like) | Ansible `fetch become` | TIDAK ADA | `download` tidak punya `--sudo`; `fs cat --sudo` hanya untuk teks (isi biner dibuang) dengan batas default 1 MiB (`--max-bytes`) | P2 |
| Rekursif folder | scp `-r`, sftp | ADA | `-r` di upload/download | – |
| Tidak menimpa tanpa `--overwrite` | scp `-n`, rsync `--ignore-existing` | TIDAK ADA | upload ke server menimpa diam-diam; download dari server membuka file lokal dengan `O_TRUNC` (hanya storage yang "never overwrite"). Bertentangan dengan edge case ux.md: "File tujuan sudah ada: tidak ditimpa tanpa `--overwrite`" | P1 |
| Download atomik (tmp lalu rename; tidak ada file setengah jadi) | rsync | TIDAK ADA | `fetchFile` menulis langsung ke tujuan. ux.md: "Unduhan terputus: tulis ke file sementara lalu rename" | P1 |
| File besar tanpa memuat ke memori (stream) | scp, rsync | SEBAGIAN | download dan `upload -r` sudah streaming (`io.Copy`), tapi upload satu file memakai `os.ReadFile` (seluruh file ke RAM) lalu `writeRemote`; satu file dump DB/ISO/backup berukuran GB bisa kehabisan memori | P1 |
| Progress di stderr untuk file besar | scp, rsync `--progress` | TIDAK ADA | ux.md edge case: "file sangat besar (progress di stderr)" | P2 |
| Lanjutkan transfer terputus (resume) | rsync `--partial`, sftp `reget` | TIDAK ADA | tidak ada untuk SFTP host; FTP storage juga tidak punya resume | P3 |
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
| Hapus baris yang cocok | Ansible `lineinfile state=absent` | SEBAGIAN | `fs replace --regex` dengan pola yang ikut menangkap `\n` bisa menghapus baris utuh (`--new ''` tanpa itu meninggalkan baris kosong), tapi gagal `NO_MATCH` bila baris sudah tidak ada (tidak idempoten) | P3 |
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
| User unit (`systemctl --user`) | systemctl --user | TIDAK ADA | `--no-sudo` hanya melepas sudo (bantuannya menyebut "--user units"), tapi `systemctl` tidak pernah dipanggil dengan `--user`; harus exec | P3 |
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
| IP publik/egress server | `curl ifconfig.me` | TIDAK ADA | `net http` membuang body (`-o /dev/null`), jadi tidak bisa membaca IP egress; bisa lewat exec `curl ifconfig.me` | P3 |
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
| Audit setiap aksi (siapa, apa, di mana, hasil) | Teleport audit log | ADA | `audit --command --failed --limit --target`; `KOMANDO_ACTOR`. Catatan: audit ditulis setelah aksi dan kegagalan menulis file diabaikan diam-diam (tidak gagal tertutup); mematikan audit lewat `config set audit off` butuh `--yes` | – |
| Filter audit berdasarkan waktu / export | Teleport | SEBAGIAN | tidak ada `--since/--until`; file `audit.jsonl` bisa dibaca | P3 |
| Kirim audit ke pusat (syslog/SIEM/webhook) | Teleport, auditd | TIDAK ADA | audit hanya lokal per laptop; tim tidak bisa melihat aksi agent di mesin lain | P2 |
| Konfirmasi manusia untuk target produksi & perintah berbahaya | Teleport access requests | ADA | protected → `--yes`/prompt `[y/N]`; dangerous → ketik ulang nama; agent tidak bisa menjawab prompt | – |
| Approval jarak jauh (minta izin orang lain, just-in-time access) | Teleport access requests | NON-GOAL | butuh server; NG-TUI "daemon/server" | – |
| RBAC multi-user terpusat | Teleport roles | NON-GOAL | NG-TUI "daemon/server"; pengganti: user SSH dengan hak minimum (docs/features/safety.md) | – |
| Session recording | Teleport | TIDAK ADA | lihat §6 | P3 |
| Secret tidak pernah di argumen/output/audit | — | SEBAGIAN | vault AES-256-GCM, `secret set` menolak nilai di argumen (`SECRET_IN_ARGS`), ref eksternal (1Password, Vault, AWS SM, GCP SM); tapi `host add/edit --password-ref/--sudo-ref` menerima nilai polos lalu menyimpan dan mencetaknya (lihat §1) | P1 |
| Policy perintah berbahaya yang bisa ditambah | — | ADA | `policy deny REGEX`, `policy check` | – |
| Allowlist (hanya perintah tertentu yang boleh untuk agent) | Teleport `command` restrictions, `authorized_keys command=` | TIDAK ADA | policy hanya deny-list; mode "agent hanya boleh read-only" global tidak ada | P2 |

---

## Ringkasan hitungan

Total 273 kemampuan dinilai (diperbarui setelah verifikasi per baris; hitungan awal "270, ADA 103"
salah hitung, dan 8 status serta 3 prioritas dikoreksi, lihat bagian terakhir).

| Status | Jumlah |
|---|---|
| ADA | 104 |
| SEBAGIAN | 41 |
| TIDAK ADA | 115 |
| NON-GOAL | 13 |

| Prioritas celah (SEBAGIAN + TIDAK ADA) | Jumlah |
|---|---|
| P1 | 13 (celah "cabut key" muncul di §2 dan §13; celah `--password-ref` tanpa validasi muncul di §1 dan §20) |
| P2 | 57 |
| P3 | 86 |

## Celah P1 teratas

1. **Cabut key SSH dari `authorized_keys`** (offboarding/rotasi; `key deploy`/`user add` hanya menambah) — §2, §13.
2. **Sinkronisasi folder (delta, `--delete`, `--exclude`, dry-run daftar perubahan)** untuk deploy — §9.
3. **Transfer tidak menimpa tanpa `--overwrite`** (upload dan download server menimpa diam-diam; melanggar ux.md) — §9.
4. **Download atomik (tmp + rename)** — §9.
5. **Upload file besar secara streaming** (upload satu file masih `os.ReadFile` seluruh file ke RAM) — §9.
6. **Reboot terkendali + tunggu kembali + verifikasi** untuk alur patch — §18.
7. **`svc daemon-reload`** untuk alur "tulis unit → reload → restart" — §11.
8. **Tunnel bind non-loopback tanpa `--yes`** (bertentangan dengan network.md) — §8.
9. **Diff saat `fs write --dry-run`** (dry-run wajib bagi agent tapi tidak menunjukkan perubahan) — §10.
10. **Validasi file sebelum dipasang** (`visudo -cf`, `sshd -t`, `nginx -t`) agar edit tidak mengunci akses — §10.
11. **`host add/edit` menerima password polos di `--password-ref`/`--sudo-ref`** (tersimpan di `state.json` dan tercetak; `conn`/`vpn` sudah memakai `vault.ValidRef`) — §1, §20.

Kandidat P2 terkuat berikutnya: `ProxyCommand`/transport AWS SSM, GCP IAP, Cloudflare Access (§1), rolling batch `serial` (§5), `download --sudo` (§9), `lineinfile` idempoten (§10), dan SSH certificate (§1, §3).

## Verifikasi per baris

Dicek ulang 2026-11-02 terhadap kode di `feat/v0.3` (commit `4784fc9`): setiap baris dibaca ulang dari
`internal/cli`, `internal/sshx`, `internal/store`, `internal/vault`, `internal/policy`, `bin/komando schema`
dan `--help` (dengan `KOMANDO_HOME` sementara), plus kode `golang.org/x/crypto` v0.58.0 untuk perilaku
agent/known_hosts. Satu uji lokal tanpa server: `host add ... --password-ref hunter2` di `KOMANDO_HOME`
sementara. Baris NON-GOAL dicocokkan dengan vision.md "Bukan tujuan" (baris 221-228) atau "Aturan teknis".
Nomor `#` adalah urutan baris di tabel-tabel di atas.

| # | Kemampuan (short) | Status akhir | Hasil cek | Bukti di kode |
|---|---|---|---|---|
| 1 | Login dengan private key file | ADA | Benar | host.go:51 `--key`, host.go:39/52 `--identity`; client.go:301-317 |
| 2 | Pakai ssh-agent (termasuk 1Password/Secretive… | ADA | Benar | sshx/client.go:320-327 (SSH_AUTH_SOCK); meta.go:565 doctor |
| 3 | Fallback otomatis ke ~/.ssh/id_ed25519/id_ecds… | ADA | Benar | sshx/client.go:328-333 (hanya bila tidak ada key eksplisit) |
| 4 | Key terenkripsi (passphrase dari vault) | ADA | Benar | key.go:163, key.go:171-190 `--passphrase-ref`; client.go:278-290 |
| 5 | Password login (tersimpan aman) | SEBAGIAN | Dikoreksi: ADA→SEBAGIAN, –→P1 | host.go:95-96 menyimpan `--password-ref`/`--sudo-ref` tanpa `vault.ValidRef` (dipakai di conn.go:100, vpn.go:167); uji lokal `host add t1 a@192.0.2.1 --password-ref hunter2` → exit 0, nilai tersimpan & tercetak |
| 6 | Keyboard-interactive / 2FA SSH (OTP Google Aut… | SEBAGIAN | Benar | sshx/client.go:345-351 (semua pertanyaan dijawab password, hanya bila PasswordRef ada); shell.go:37 memakai Dial yang sama |
| 7 | IdentitiesOnly (batasi key yang dicoba, hindar… | SEBAGIAN | Dikoreksi: bukti (status tetap) | sshx/client.go:301-335: key eksplisit masuk `signers` dulu, lalu semua key agent ditambahkan sesudahnya (bukan lebih dulu) |
| 8 | IdentityAgent per host (agent berbeda per host) | TIDAK ADA | Benar | grep IdentityAgent: 0 hasil; store.go:17-36 tanpa field agent |
| 9 | Jump host / bastion (-J, ProxyJump), rantai ba… | ADA | Benar | host.go:55 `--via`, host.go:56 alias `--jump`; host.go:547 ProxyJump; client.go:119-162 |
| 10 | ProxyCommand (mis. aws ssm start-session, clou… | TIDAK ADA | Benar | grep ProxyCommand: 0 hasil; host.go:512-517 opsi lain hanya disimpan di map, tidak dipakai |
| 11 | Akses lewat VPN per koneksi (banyak VPN sekali… | ADA | Benar | vpn.go:25-44 daftar kind (netx.Kinds); client.go:63-69 VPN di awal --via |
| 12 | Tailscale SSH (auth berbasis identitas tailnet… | SEBAGIAN | Benar | client.go:353-355 NO_AUTH bila tidak ada key/agent/password |
| 13 | SSH certificate login (user cert ditandatangan… | SEBAGIAN | Dikoreksi: TIDAK ADA→SEBAGIAN | client.go:322-325 `ag.Signers()` (x/crypto agent client.go:819-829) ikut membawa user cert dari agent; grep CertificateFile/NewCertSigner: 0 hasil |
| 14 | Agent forwarding (-A, ForwardAgent) — mis. git… | TIDAK ADA | Benar | grep ForwardToAgent/RequestAgentForwarding: 0 hasil |
| 15 | X11 forwarding (-X/-Y) | TIDAK ADA | Benar | grep X11: 0 hasil |
| 16 | Keepalive (ServerAliveInterval) | ADA | Benar | sshx/client.go:103-115 (keepalive@komando tiap 30 dtk, tetap) |
| 17 | Connect timeout | ADA | Benar | root.go:165 `--connect-timeout`; meta.go:358 `connect_timeout`; client.go:64,89-91 |
| 18 | Pilihan cipher/KEX/HostKeyAlgorithms per host… | TIDAK ADA | Benar | grep Ciphers/KeyExchanges/HostKeyAlgorithms: 0 hasil; client.go:256-261 |
| 19 | Kompresi (-C) untuk link lambat | TIDAK ADA | Benar | grep Compression: 0 hasil |
| 20 | Multiplexing koneksi (ControlMaster/ControlPer… | NON-GOAL | Benar (catatan: dasarnya "Aturan teknis", bukan "Bukan tujuan") | vision.md:189-190; common.go:135-158 satu Dial per host per perintah |
| 21 | Retry otomatis saat koneksi gagal sementara | TIDAK ADA | Benar | common.go:135-158 fanout tanpa retry; satu-satunya reconnect di tunnel.go:440-491 |
| 22 | IPv6, port non-standar | ADA | Benar | sshx/client.go:165-183 ParseAdhoc (SplitHostPort); host.go:49 `--port`; ux.md:294 |
| 23 | Host ad-hoc tanpa didaftarkan | ADA | Benar | client.go:139-147 ad-hoc user@host:port; select.go (target ad-hoc) |
| 24 | Match blok di ssh_config (Match host/user/exec) | SEBAGIAN | Benar | host.go:509-510 `case "match": cur = nil`; ux.md:211 |
| 25 | Laporan direktif ssh_config yang tidak didukun… | TIDAK ADA | Benar | host.go:465-564 hanya hostname/user/port/identityfile/proxyjump/include dipakai; grep unsupported di importer: 0 hasil |
| 26 | Cetak perintah OpenSSH setara (interop) | ADA | Benar | host.go:709-759 `host ssh-command` |
| 27 | Ekspor inventaris ke ssh_config (supaya ssh/sc… | TIDAK ADA | Benar | host.go:596-619 hanya JSON; grep ssh_config writer: 0 hasil |
| 28 | Host Windows (OpenSSH di Windows / WinRM / Pow… | TIDAK ADA | Benar | vision.md:91 "SSH (Linux)"; factsScript ops.go:19-38 khusus Linux |
| 29 | Buat key pair ed25519 / RSA | ADA | Benar | key.go:53-75, key.go:107 `--type ed25519\|rsa` |
| 30 | Buat key ECDSA | TIDAK ADA | Benar | key.go:75 "--type must be ed25519 or rsa" |
| 31 | Key hardware FIDO2 (ed25519-sk, YubiKey) | SEBAGIAN | Benar | x/crypto common.go:208-225 mendukung sk-* lewat agent; key.go:53-75 tidak membuat sk |
| 32 | Passphrase saat membuat key | TIDAK ADA | Benar | key.go:58,70 `ssh.MarshalPrivateKey` tanpa passphrase; key.go:88 0600 |
| 33 | Daftarkan key yang sudah ada | ADA | Benar | key.go:118-163 `key add` (path direferensikan) |
| 34 | Lihat public key dan fingerprint | ADA | Benar | key.go:95 Fingerprint SHA256; key.go:196 list, key.go:227 show |
| 35 | Pasang public key ke server (idempoten) | ADA | Benar | key.go:280-360 (grep -qF lalu append; fanout; `--set-default`) |
| 36 | Cabut / hapus public key dari authorized_keys… | TIDAK ADA | Dikoreksi: bukti (status tetap) | key.go:308-309 & modules.go:673-675 hanya append; grep revoke/absent: 0 hasil. Per host bisa `fs replace` (fs.go:563-672, satu host) |
| 37 | Daftar authorized_keys per server/user (audit… | TIDAK ADA | Benar | grep parser authorized_keys: 0 hasil; hanya fs.go:260 `fs cat` |
| 38 | Rotasi key end-to-end (deploy baru → switch →… | SEBAGIAN | Benar | key.go:360 `--set-default`; langkah cabut tidak ada (lihat #36) |
| 39 | Tambahkan key ke ssh-agent | TIDAK ADA | Benar | grep agent.Add: 0 hasil |
| 40 | Opsi authorized_keys (from=, command=, no-port… | TIDAK ADA | Benar | key.go:309 menulis baris key apa adanya tanpa opsi |
| 41 | SSH CA: tanda tangani user/host cert | TIDAK ADA | Benar | grep CertSigner/ssh-keygen -s: 0 hasil |
| 42 | Short-lived cert otomatis per sesi | TIDAK ADA | Benar | grep cert/CA: 0 hasil |
| 43 | Kebijakan host key accept-new / strict / off | ADA | Benar | root.go:148-149 `off` → guardSafety (SAFETY_SETTING, common.go:328); meta.go:366-369 |
| 44 | Tolak host key berubah | ADA | Benar | client.go:396-397, 218-221 HOSTKEY_MISMATCH |
| 45 | Ambil & pin host key (keyscan), juga di balik… | ADA | Benar | host.go:651-707 (ScanHostKey langsung; via → Dial accept-new) |
| 46 | Lupakan / ganti key setelah server dibangun ul… | ADA | Benar | host.go:669-673 `--reset` → ForgetHost (client.go:414) |
| 47 | Impor ~/.ssh/known_hosts yang sudah ada (hinda… | TIDAK ADA | Benar | client.go:369,375 hanya ~/.komando/known_hosts; grep import known_hosts: 0 hasil |
| 48 | Host certificate / @cert-authority di known_ho… | SEBAGIAN | Dikoreksi: TIDAK ADA→SEBAGIAN | client.go:384 `knownhosts.New` (x/crypto knownhosts.go:439-444 CertChecker) menerima baris @cert-authority tulisan tangan; tanpa itu CheckHostKey (certs.go:372-373) gagal → CONNECT_FAILED, bukan TOFU; grep cert-authority: 0 hasil |
| 49 | Verifikasi fingerprint dari sumber lain (DNS S… | TIDAK ADA | Benar | host.go:705 hanya `--reset`; grep fingerprint flag: 0 hasil |
| 50 | Daftar host key yang dipin | SEBAGIAN | Benar | host.go:695-699 fingerprint di output; tidak ada subperintah daftar |
| 51 | Tambah/ubah/hapus/lihat host | ADA | Benar | host.go:84 add, 154 edit (--rename 157), 317 rm, 297 show |
| 52 | Grup, tag, label key=value, catatan | ADA | Benar | host.go:58-68 --group/--tag/--label/--notes; host.go:770-852 group |
| 53 | Grup bersarang (group of groups / children) | TIDAK ADA | Benar | grep children/parent group: 0 hasil; store.go:28 Groups datar |
| 54 | Selector: nama, glob, @group, tag:, label:, ki… | ADA | Benar | select.go:125 kind:, 208 all, 210 @, 212 tag:, 214 label:, 224 glob; did-you-mean select.go:77,251 |
| 55 | Target berdasarkan facts (os=ubuntu, arch, ver… | TIDAK ADA | Benar | select.go:205-230 hanya atribut inventaris |
| 56 | Variabel per host (env, user default, sudo) | ADA | Benar | host.go:65 --env, 54 --sudo-ref; meta.go:358 default_user; sshx/run.go:102-108 |
| 57 | Variabel per host untuk recipe/template ({{app… | TIDAK ADA | Benar | ops.go:355-359 render sekali sebelum runFleet (satu nilai untuk semua host) |
| 58 | Tandai host produksi (perlu konfirmasi) | ADA | Benar | host.go:58 --protected; common.go:184-196, 233 |
| 59 | Import ~/.ssh/config | ADA | Benar | importer.go:49,370 ssh-config; host.go:365 host import |
| 60 | Import inventaris Ansible (INI/YAML) | TIDAK ADA | Benar | importer.go sources (help `import`): tidak ada ansible; grep ansible: 0 hasil |
| 61 | Import dari Termius / Royal TSX / MobaXterm /… | TIDAK ADA | Benar | vision.md:170 termius; grep termius di importer: 0 hasil |
| 62 | Inventaris dinamis dari cloud (EC2/DO/Hetzner… | TIDAK ADA | Benar | vision.md:208-209 kandidat setelah v1.0; grep ec2/hetzner di cli: 0 hasil |
| 63 | Export / pindah komputer | ADA | Benar | importer.go:612 export; importer.go:49 `komando` source; host.go:596 host export --target |
| 64 | Sinkronisasi inventaris antar perangkat/tim (c… | NON-GOAL | Benar | vision.md:227 "daemon/server" |
| 65 | Cek bisa login ke semua host | ADA | Benar | everything.go:151,174 test (host/conn/VPN) |
| 66 | Cek sudo berfungsi saat test | SEBAGIAN | Dikoreksi: TIDAK ADA→SEBAGIAN | host.go:637-647 `test` menjalankan `sudo -n true` → `sudo_nopasswd`; sudo-ref (run.go:102-108) tidak diuji |
| 67 | Riwayat koneksi / "recent hosts" | SEBAGIAN | Benar | meta.go:276 audit --target; everything.go:61 list tanpa last-used |
| 68 | Jalankan perintah di satu / banyak host paralel | ADA | Benar | exec.go:191-314 runFleet + fanout; root.go:166 -P |
| 69 | Output terstruktur per host (stdout, stderr, e… | ADA | Benar | exec.go:275-313 results/summary; worst → exit 5 (exec.go:289) |
| 70 | Streaming output saat berjalan | ADA | Benar | exec.go:80 --stream, 241-265 NDJSON |
| 71 | Hentikan setelah kegagalan pertama | ADA | Benar | exec.go:81, 232-238 --fail-fast |
| 72 | Rolling / batch bertahap (serial: 2 / 25%), je… | SEBAGIAN | Benar | exec.go:81 + root.go:166; grep serial/batch: 0 hasil |
| 73 | Kelompokkan output identik (500 host → "480 ho… | TIDAK ADA | Benar | exec.go:275-299 hasil per host tanpa pengelompokan |
| 74 | Simpan output per host ke folder | TIDAK ADA | Benar | grep output-dir: 0 hasil |
| 75 | sudo non-interaktif, sudo dengan password dari… | ADA | Benar | exec.go:74-75 --sudo/--sudo-user; host.go:54 --sudo-ref; run.go:102-108 |
| 76 | su/doas/pbrun sebagai metode become | TIDAK ADA | Benar | grep doas/pbrun di sshx: 0 hasil (doas hanya di policy.go:26) |
| 77 | Env var dan working dir | ADA | Benar | exec.go:76-77 -e/-C; host.go:65 --env |
| 78 | stdin dari file lokal | ADA | Benar | exec.go:78, 113-118 --stdin-file |
| 79 | Jalankan skrip lokal di remote tanpa menyalin | ADA | Benar | exec.go:129-177 script --arg --interpreter |
| 80 | PTY untuk tool yang memintanya | ADA | Benar | exec.go:79 --pty |
| 81 | Dry-run / check mode | ADA | Benar | root.go:161; exec.go:212-226 would_run + would_be_blocked |
| 82 | Guardrail perintah berbahaya | ADA | Benar | meta.go:441-530 policy list/check/deny/allow; root.go:163 |
| 83 | Deklarasi read-only untuk host protected | ADA | Benar | exec.go:125 --read-only; common.go:184 |
| 84 | Batas waktu per host dan batas output | ADA | Benar | root.go:164 --timeout, 168 --max-output |
| 85 | Batas eksekusi async (async/poll) | ADA | Benar | job.go:52-148 job start |
| 86 | Interaktif ke banyak terminal sekaligus (ketik… | NON-GOAL | Benar | vision.md:227 "GUI, TUI ... CLI murni" |
| 87 | Playbook / state deklaratif (orkestrasi banyak… | NON-GOAL | Benar | vision.md:226 "Infrastructure as Code ... GitOps" |
| 88 | Perintah lokal di laptop sebagai bagian alur | TIDAK ADA | Dikoreksi: NON-GOAL→TIDAK ADA, –→P3 | vision.md:221-228 tidak mengecualikan perintah lokal; grep exec lokal untuk alur: 0 hasil |
| 89 | Shell login interaktif (PTY, resize) | ADA | Benar | shell.go:18-74 (alias ssh/connect, WindowChange shell.go:59-66) |
| 90 | Jalankan perintah interaktif dengan TTY (ssh -… | TIDAK ADA | Benar | shell.go:23 ExactArgs(1), sess.Shell(); exec --pty tanpa stdin terminal |
| 91 | Konfirmasi/penanda saat shell ke host protected | SEBAGIAN | Benar | shell.go:36 hanya audit; tidak memanggil guard/protectedHost |
| 92 | Rekaman sesi (session recording / replay) | TIDAK ADA | Benar | shell.go:36 audit sekali; grep record: 0 hasil |
| 93 | Roaming / koneksi tahan putus (ganti Wi-Fi, la… | TIDAK ADA | Benar | grep mosh/roam: 0 hasil |
| 94 | Escape sequence (~.), pindah ke port-forward d… | TIDAK ADA | Benar | shell.go:57 stdin mentah ke sesi; tidak ada escape |
| 95 | Berbagi sesi / join sesi orang lain | NON-GOAL | Benar | vision.md:227 "daemon/server" |
| 96 | Mulai proses terlepas yang bertahan saat SSH p… | ADA | Benar | job.go:29 $HOME/.komando/jobs, job.go:104-106 setsid nohup |
| 97 | Status, exit code, runtime, tail log | ADA | Benar | job.go:225 status, 417/463-465 list --refresh --target |
| 98 | Baca log inkremental | ADA | Benar | job.go:266, 308-311 --offset/--max-bytes/--tail |
| 99 | Tunggu selesai dengan batas waktu | ADA | Benar | job.go:320, 367-368 --interval/--wait-timeout |
| 100 | Hentikan (sinyal ke process group) | ADA | Benar | job.go:376-409 kill -SIG -- -PGID |
| 101 | Bersihkan job | ADA | Benar | job.go:472, 497 --keep-remote |
| 102 | Jalankan skrip lokal sebagai job | TIDAK ADA | Benar | job.go:52 start menerima perintah saja (flag job.go:144-148) |
| 103 | Batas waktu maksimum job (bunuh otomatis setel… | TIDAK ADA | Benar | job.go:144-148 tanpa flag batas waktu |
| 104 | Attach interaktif ke job / kirim input | TIDAK ADA | Benar | job.go:105 stdin </dev/null |
| 105 | Notifikasi saat job selesai | NON-GOAL | Benar | vision.md:228 "Monitoring atau alerting ... terus-menerus" (dan :227 daemon) |
| 106 | Modul lambat otomatis jadi job (pkg upgrade, d… | TIDAK ADA | Benar | modules.go:427,472-492 pkg upgrade lewat runOne (timeout biasa) |
| 107 | Local forward -L | ADA | Benar | tunnel.go:57-71, 222 -L |
| 108 | Remote forward -R | ADA | Benar | tunnel.go:223 -R; tunnel.go:391-393 c.Listen |
| 109 | SOCKS5 -D | ADA | Benar | tunnel.go:224 -D; tunnel.go:73-81 |
| 110 | Tunnel ke conn berdasarkan nama (port lokal be… | ADA | Benar | tunnel.go:101-117 conn + --port (tunnel.go:225) |
| 111 | Tunnel di latar, list, stop | ADA | Benar | tunnel.go:261 list (alive/prune), 306 stop --all |
| 112 | Reconnect otomatis saat SSH putus | SEBAGIAN | Benar | tunnel.go:440 connMgr (local/dynamic); tunnel.go:408-409 -R berhenti saat listener putus |
| 113 | Bind default ke 127.0.0.1; bind ke alamat lain… | SEBAGIAN | Benar | tunnel.go:65-70 bind dari spec diterima tanpa cek g.yes; network.md:163-164 |
| 114 | Tunnel bertahan setelah reboot laptop (service… | NON-GOAL | Benar | vision.md:227 daemon; vision.md:189-190 "tanpa daemon" |
| 115 | Batas umur tunnel (stop otomatis setelah X / s… | TIDAK ADA | Benar | meta.go:358 vpn_idle hanya untuk VPN; grep idle di tunnel.go: 0 hasil |
| 116 | "VPN lewat SSH" transparan (ubah rute laptop) | NON-GOAL | Benar (catatan: sumber network.md:169 dan vision.md:200) | network.md:169; vision.md:200 "jaringan laptop tidak berubah" |
| 117 | Forward Unix socket (-L /tmp/x.sock:/var/run/d… | TIDAK ADA | Benar | tunnel.go:57-83 spec dipisah ":" → host:port saja |
| 118 | Upload file ke banyak server paralel | ADA | Benar | transfer.go:42-76; cp.go:55-84; cp.go:184 sha256 (file tunggal) |
| 119 | Upload dengan mode, buat folder induk, pasang… | SEBAGIAN | Benar | cp.go:49-52 --mode/-p/--sudo; cp.go:189-191 folder+sudo ditolak; tanpa --owner |
| 120 | Download dari banyak server (folder per server) | ADA | Benar | cp.go:127-133 DIR/<host>/ |
| 121 | Download file milik root (/var/log/..., /etc/s… | TIDAK ADA | Dikoreksi: bukti (status tetap) | transfer.go:109-110 hanya --to/-r; fs.go:311-312 `fs cat --sudo` default 1 MiB (`--max-bytes`), fs.go:278-281 biner dibuang |
| 122 | Rekursif folder | ADA | Benar | cp.go:49 -r; transfer.go:110 |
| 123 | Tidak menimpa tanpa --overwrite | TIDAK ADA | Benar | cp.go:180 writeRemote menimpa; cp.go:210,284 O_TRUNC; storage.go:316 hanya storage FILE_EXISTS; ux.md:318 |
| 124 | Download atomik (tmp lalu rename; tidak ada fi… | TIDAK ADA | Benar | cp.go:278-292 fetchFile O_TRUNC langsung ke tujuan; ux.md:319 |
| 125 | File besar tanpa memuat ke memori (stream) | SEBAGIAN | Dikoreksi: TIDAK ADA→SEBAGIAN | cp.go:173 `os.ReadFile` untuk upload satu file; cp.go:205-214 (upload -r) dan cp.go:290 (download) sudah io.Copy streaming |
| 126 | Progress di stderr untuk file besar | TIDAK ADA | Benar | grep progress: 0 hasil; ux.md:321 |
| 127 | Lanjutkan transfer terputus (resume) | TIDAK ADA | Dikoreksi: bukti (status tetap) | grep resume/offset di cp.go & storex: 0 hasil (ftp.go:41 hanya komentar koneksi kontrol) — FTP storage juga tanpa resume |
| 128 | Sinkronisasi delta (hanya yang berubah), --del… | TIDAK ADA | Benar | cp.go:193-223 salin ulang semua, tanpa delete/exclude; grep exclude di cp.go: 0 hasil |
| 129 | Dry-run transfer yang menunjukkan file apa yan… | SEBAGIAN | Benar | cp.go:114-117 dry-run hanya src/dst/hosts/direction |
| 130 | Lewati upload bila isi sama (idempoten) | SEBAGIAN | Benar | fs.go:517-531 --if-changed; cp.go:172-185 upload tanpa perbandingan |
| 131 | Pertahankan symlink | TIDAK ADA | Benar | cp.go:202-204 & 265-267 non-regular (symlink) dilewati tanpa laporan |
| 132 | Pertahankan waktu modifikasi (-p) | TIDAK ADA | Benar | cp.go:219 & 284 hanya mode; grep Chtimes: 0 hasil |
| 133 | Kompresi saat transfer | TIDAK ADA | Benar | grep compress di sftp/cp: 0 hasil |
| 134 | Salin server → server (remote ke remote) | TIDAK ADA | Benar | cp.go:72-73 remote-to-remote ditolak |
| 135 | Salin file di dalam satu server | TIDAK ADA | Benar | fs.go:36 tidak ada `fs cp`; fs.go:771 mv |
| 136 | Unduh URL langsung di server (dengan checksum) | TIDAK ADA | Benar | grep get_url/download URL: 0 hasil; policy.go:37 curl-pipe-sh |
| 137 | Ekstrak arsip di server | TIDAK ADA | Benar | grep unarchive/tar x: 0 hasil |
| 138 | Browsing interaktif ala sftp shell | NON-GOAL | Benar | vision.md:227 TUI/CLI murni; fs.go:110-317 ls/stat/cat |
| 139 | Baca file (head/tail/line numbers, batas byte,… | ADA | Benar | fs.go:260-317 --head/--tail/--line-numbers/--max-bytes/--sudo |
| 140 | Ganti teks persis / regex, gagal bila tidak ad… | ADA | Benar | fs.go:563-672; diff di dry-run fs.go:645-648 |
| 141 | Pastikan satu baris ada (tambahkan bila belum… | SEBAGIAN | Benar | fs.go:617-623 NO_MATCH (teks biasa: changed:false bila --new sudah ada); fs.go:549 --append |
| 142 | Hapus baris yang cocok | SEBAGIAN | Dikoreksi: bukti (status tetap) | fs.go:612-640: `--regex` dengan `\n` di pola bisa menghapus baris utuh, tapi gagal NO_MATCH bila baris sudah tidak ada (tidak idempoten) |
| 143 | Blok terkelola dengan marker (# BEGIN komando… | TIDAK ADA | Benar | grep BEGIN komando/blockinfile: 0 hasil; modules.go:757 marker hanya cron |
| 144 | Tulis file atomik, mode/owner, backup, idempoten | ADA | Benar | fs.go:327-447 tmp+rename; fs.go:547-560 flag |
| 145 | Diff saat dry-run fs write | TIDAK ADA | Benar | fs.go:506-508 dry-run hanya host/path/bytes; unifiedDiff fs.go:675 dipakai replace saja |
| 146 | Render template dengan variabel | TIDAK ADA | Benar | ops.go:151 render hanya untuk recipe |
| 147 | Validasi file sebelum dipasang (validate: ngin… | TIDAK ADA | Benar | grep validate/visudo: 0 hasil; ops.go:130 nginx-test terpisah |
| 148 | mkdir -p, mv, chmod (rekursif), rm (rekursif) | ADA | Benar | fs.go:755-785 rm/mkdir/mv/chmod (+--sudo, -r) |
| 149 | chown / chgrp mandiri | TIDAK ADA | Benar | fs.go:560 --owner hanya write/replace; fs.go:36 tanpa chown |
| 150 | Buat symlink | TIDAK ADA | Benar | fs.go:98-99,190-191 hanya mengenali; tanpa pembuat symlink |
| 151 | touch / ubah mtime | TIDAK ADA | Benar | grep touch/Chtimes: 0 hasil |
| 152 | stat (exists, ukuran, mode, sha256) | ADA | Benar | fs.go:174-217 (--sha256, exists:false) |
| 153 | ls (rekursif, dotfiles, batas) | ADA | Benar | fs.go:110-172 -a/-r/--max |
| 154 | Cari file (nama/ukuran/umur) | SEBAGIAN | Benar | ops.go:109-110 big-dirs/big-files; tidak ada fs find |
| 155 | Cari isi (grep di file/folder) | SEBAGIAN | Benar | modules.go:203-205,232-236 logs --file --grep (satu file) |
| 156 | Restore dari .bak | TIDAK ADA | Benar | fs.go:371,421 satu PATH.bak; grep restore: 0 hasil |
| 157 | Edit di editor lokal ($EDITOR) lalu simpan balik | TIDAK ADA | Benar | grep EDITOR: 0 hasil |
| 158 | Status terstruktur | ADA | Benar | modules.go:32,77-86 svc status |
| 159 | start/stop/restart/reload + laporan state + jo… | ADA | Benar | modules.go:91-111 (journal 20 baris saat start/restart/reload gagal) |
| 160 | enable/disable | ADA | Benar | modules.go:91 svcActionCmd untuk enable/disable |
| 161 | enable --now dalam satu langkah | TIDAK ADA | Benar | modules.go:100 `systemctl enable` tanpa --now |
| 162 | Daftar unit + filter failed/state | ADA | Benar | modules.go:117-143 --failed/--state |
| 163 | daemon-reload setelah mengubah unit file | TIDAK ADA | Benar | grep daemon-reload: 0 hasil |
| 164 | mask/unmask | TIDAK ADA | Benar | grep mask di modules: 0 hasil (hanya policy.go:32) |
| 165 | Lihat unit file & drop-in (systemctl cat) | TIDAK ADA | Benar | grep 'systemctl cat': 0 hasil |
| 166 | Buat/ubah override drop-in (systemctl edit) | TIDAK ADA | Benar | grep 'systemctl edit'/override: 0 hasil |
| 167 | Daftar & kelola systemd timer | SEBAGIAN | Benar | ops.go:137 cron-all (list-timers, teks) |
| 168 | User unit (systemctl --user) | TIDAK ADA | Dikoreksi: SEBAGIAN→TIDAK ADA | modules.go:109 `--no-sudo` hanya melepas sudo; perintah modules.go:82,100,121 tidak pernah memakai `--user`; grep 'systemctl --user': 0 hasil |
| 169 | Init non-systemd (OpenRC/Alpine, sysvinit) | TIDAK ADA | Benar | modules.go:82-121 hanya systemctl; modules.go:418 apk di pkg |
| 170 | Validasi config sebelum reload (nginx -t, apac… | SEBAGIAN | Benar | ops.go:130,132 nginx-test/apache-test; modules.go:100 reload tanpa validasi |
| 171 | Install / remove / update index / upgrade (sem… | ADA | Benar | modules.go:413-503 pkgShell + DEBIAN_FRONTEND |
| 172 | Daftar upgrade tertunda | SEBAGIAN | Benar | modules.go:428-452 upgradable teks mentah per manajer |
| 173 | Hanya update keamanan | SEBAGIAN | Benar | ops.go:127 security-updates (baca); grep --security: 0 hasil |
| 174 | Versi terinstal | ADA | Benar | modules.go:429,435 dpkg-query/rpm tab-separated |
| 175 | Cari paket / info paket | TIDAK ADA | Benar | modules.go:423-453 tanpa search/info |
| 176 | Install versi tertentu | SEBAGIAN | Benar | modules.go:485 validasi nama tidak menolak = dan * |
| 177 | Hold/pin versi (cegah upgrade) | TIDAK ADA | Benar | grep apt-mark/versionlock: 0 hasil |
| 178 | Tambah repo/PPA + kunci GPG | TIDAK ADA | Benar | grep add-apt-repository/yum_repository: 0 hasil |
| 179 | Autoremove / bersihkan cache | SEBAGIAN | Benar | ops.go:144 apt-clean (apt saja) |
| 180 | dist-upgrade / full-upgrade | TIDAK ADA | Benar | modules.go:427 `apt-get upgrade`; grep full-upgrade: 0 hasil |
| 181 | Deteksi reboot diperlukan setelah upgrade | ADA | Benar | ops.go:33 reboot_required |
| 182 | Pasang dari file .deb/.rpm lokal | TIDAK ADA | Benar | modules.go:485 PKGS hanya nama paket; tanpa file lokal |
| 183 | Paket non-OS (snap, flatpak, pip, npm global) | TIDAK ADA | Benar | modules.go:414-419 hanya manajer OS |
| 184 | Daftar user (manusia / semua) + anggota sudo | ADA | Benar | modules.go:611-642 user list --all + grup sudo/wheel/admin |
| 185 | Buat user idempoten + key SSH + sudo | ADA | Benar | modules.go:646-684 --key/--pubkey/--admin/--shell |
| 186 | Kunci akun | ADA | Benar | modules.go:686-692 usermod -L -e 1 |
| 187 | Buka kunci akun | TIDAK ADA | Benar | grep 'usermod -U'/unlock di modules: 0 hasil |
| 188 | Hapus user (dangerous) | ADA | Benar | modules.go:696-707; policy.go:39 userdel |
| 189 | Cabut key SSH dari user | TIDAK ADA | Benar | lihat #36; modules.go:673-675 hanya append |
| 190 | Kelola grup (groupadd, tambah/hapus anggota gr… | TIDAK ADA | Benar | modules.go:670 hanya sudo/wheel; grep groupadd/gpasswd: 0 hasil |
| 191 | Aturan sudoers terbatas (NOPASSWD untuk perint… | TIDAK ADA | Benar | ops.go:124 sudoers (baca); grep visudo: 0 hasil |
| 192 | Set/expire password user | TIDAK ADA | Benar | grep chpasswd/chage/passwd: 0 hasil |
| 193 | Ubah shell/home/UID user yang sudah ada | TIDAK ADA | Benar | modules.go:668 `id \|\| useradd` (user lama tidak diubah) |
| 194 | Login terakhir / gagal login | ADA | Benar | ops.go:122-123 auth-failures/last-logins |
| 195 | Hardening sshd (lihat setting efektif) | ADA | Benar | ops.go:125 sshd-config |
| 196 | Entri crontab idempoten berdasarkan ID | ADA | Benar | modules.go:754-770 cron set --schedule, marker # komando:<id> |
| 197 | Daftar entri (dengan ID) | ADA | Benar | modules.go:731-752 cron list (line + id) |
| 198 | Hapus entri | ADA | Benar | modules.go:772-779 cron rm |
| 199 | Crontab user lain | ADA | Benar | modules.go:722-723 --user/--sudo |
| 200 | Semua cron sistem (/etc/crontab, /etc/cron.d,… | ADA | Benar | ops.go:137 cron-all |
| 201 | Validasi jadwal | SEBAGIAN | Benar | modules.go:759-761 hanya cek jumlah field / awalan @ |
| 202 | Env cron (MAILTO, PATH, SHELL) | TIDAK ADA | Benar | modules.go:765 hanya baris jadwal |
| 203 | Nonaktifkan sementara tanpa menghapus | TIDAK ADA | Benar | modules.go:716-781 hanya list/set/rm |
| 204 | File di /etc/cron.d | TIDAK ADA | Benar | grep cron.d di modules: 0 hasil |
| 205 | Buat systemd timer | TIDAK ADA | Benar | grep timer di modules: 0 hasil |
| 206 | Jadwal sekali jalan (at) | TIDAK ADA | Benar | grep '\bat\b' scheduler: 0 hasil |
| 207 | journald per unit, since/until, priority, grep… | ADA | Benar | modules.go:176-183 flag; 237-255 journalctl |
| 208 | File log (tail/grep, sudo) | ADA | Benar | modules.go:232-236 --file; modules.go:186 --sudo |
| 209 | Ikuti terus (-f) termasuk banyak host | ADA | Benar | modules.go:272-273,785-790 followLogs → runFleet stream |
| 210 | Log container | ADA | Benar | modules.go:201,216-230 --container |
| 211 | Log kernel / boot tertentu (-k, -b -1) | SEBAGIAN | Benar | ops.go:115 oom (journalctl -k), ops.go:121 journal-errors; tanpa flag --kernel/--boot |
| 212 | Log terstruktur (field journald sebagai JSON) | TIDAK ADA | Benar | modules.go:206,238 `-o short-iso` |
| 213 | File log terkompresi/terotasi (.gz, .1) | TIDAK ADA | Benar | modules.go:232-236 satu path, tanpa zgrep |
| 214 | Beberapa unit sekaligus | TIDAK ADA | Benar | modules.go:176 --unit string tunggal |
| 215 | Atur logrotate / paksa rotate | TIDAK ADA | Benar | grep logrotate: 0 hasil |
| 216 | Kecilkan journal | ADA | Benar | ops.go:142 journal-vacuum |
| 217 | Facts terstruktur (OS, kernel, arch, CPU, RAM,… | ADA | Benar | ops.go:19-38 factsScript |
| 218 | Facts semua mount/disk, NIC, hardware (DMI), v… | SEBAGIAN | Benar | ops.go:27 hanya disk root |
| 219 | Ringkasan kesehatan | ADA | Benar | ops.go:106,111,120,136 |
| 220 | Proses top CPU/memori, cari proses | ADA | Benar | ops.go:112-114 top-cpu/top-mem/process |
| 221 | Daftar proses terstruktur (JSON) | TIDAK ADA | Benar | ops.go:112-114 teks; grep ps terstruktur: 0 hasil |
| 222 | Kill proses dengan aman (PID/nama, sinyal, kon… | TIDAK ADA | Benar | grep pkill/kill proses di modules: 0 hasil (kill hanya job.go:388) |
| 223 | Monitor interaktif (htop, top, iotop, ncdu) | NON-GOAL | Benar | vision.md:227 TUI |
| 224 | I/O disk per proses / iostat | TIDAK ADA | Benar | ops.go:111 vmstat; grep iostat/iotop: 0 hasil |
| 225 | Penggunaan disk & folder/file terbesar | ADA | Benar | ops.go:107-110 |
| 226 | File terbuka / siapa memegang file/port | SEBAGIAN | Benar | modules.go:549-573 net ports --sudo; grep lsof/fuser: 0 hasil |
| 227 | OOM kill terbaru | ADA | Benar | ops.go:115 oom |
| 228 | Cek TCP port tujuan dari server (banyak sekali… | ADA | Benar | modules.go:512-546 net check |
| 229 | HTTP dari server (status, timing, IP) | ADA | Benar | modules.go:575-588 net http |
| 230 | DNS resolve dari server | SEBAGIAN | Benar | modules.go:590-598 getent ahosts |
| 231 | Port listening + proses | ADA | Benar | modules.go:549-573 ss -tulpnH |
| 232 | Statistik koneksi | ADA | Benar | ops.go:117 connections |
| 233 | Ping / latensi ICMP | TIDAK ADA | Benar | grep ping di cli: 0 hasil |
| 234 | Traceroute / mtr | TIDAK ADA | Benar | grep traceroute/mtr: 0 hasil |
| 235 | Cek sertifikat TLS terstruktur (expiry hari, i… | SEBAGIAN | Benar | ops.go:128-129 cert-expiry/certbot-certs (teks); vision.md:208 |
| 236 | Tunggu sampai port/URL siap (wait_for) | TIDAK ADA | Benar | modules.go:512-546 sekali jalan |
| 237 | Route, interface, ARP | SEBAGIAN | Benar | ops.go:28 ips; grep 'ip route': 0 hasil |
| 238 | Scan port host lain | TIDAK ADA | Benar | grep nmap: 0 hasil |
| 239 | Bandwidth antar server | TIDAK ADA | Benar | grep iperf: 0 hasil |
| 240 | IP publik/egress server | TIDAK ADA | Dikoreksi: bukti (status tetap) | modules.go:579 `net http` memakai `-o /dev/null` (body dibuang), jadi tidak bisa membaca IP egress; hanya lewat exec |
| 241 | Tangkap paket | TIDAK ADA | Benar | grep tcpdump: 0 hasil |
| 242 | Cek dari laptop ke server (bukan dari server) | ADA | Benar | everything.go:151 test |
| 243 | Reboot terkendali + tunggu server kembali + ve… | TIDAK ADA | Benar | policy.go:26 power (reboot); grep wait-for-reboot: 0 hasil |
| 244 | Status firewall | ADA | Benar | ops.go:118 firewall |
| 245 | Kelola aturan firewall (allow/deny port, sumbe… | TIDAK ADA | Benar | policy.go:31 firewall-flush; grep ufw allow: 0 hasil |
| 246 | sysctl get/set (+ persist ke /etc/sysctl.d) | TIDAK ADA | Benar | grep sysctl: 0 hasil |
| 247 | mount / fstab (tambah, mount, unmount) | TIDAK ADA | Benar | grep fstab/mount: 0 hasil |
| 248 | Swap file | TIDAK ADA | Benar | grep mkswap: 0 hasil; ops.go:24 swap facts |
| 249 | Hostname set | TIDAK ADA | Benar | grep hostnamectl: 0 hasil; ops.go:20 |
| 250 | Timezone / NTP set | SEBAGIAN | Benar | ops.go:136 time-sync, ops.go:37 timezone; tanpa set |
| 251 | Locale | TIDAK ADA | Benar | grep localectl: 0 hasil |
| 252 | Sertifikat Let's Encrypt (issue/renew) | SEBAGIAN | Benar | ops.go:129 certbot-certs; vision.md:208 |
| 253 | Git checkout/pull di server (deploy) | TIDAK ADA | Benar | ops.go:265 hanya contoh `recipe add`; grep git di modules: 0 hasil |
| 254 | SELinux/AppArmor status & mode | TIDAK ADA | Benar | grep selinux/getenforce: 0 hasil |
| 255 | Kernel module / limits.conf | TIDAK ADA | Benar | grep modprobe/limits.conf: 0 hasil |
| 256 | Bersihkan page cache, docker prune, apt clean | ADA | Benar | ops.go:141,143,144 |
| 257 | 39 recipe bawaan (health, disk, certs, securit… | ADA | Benar | `recipe list` = 39 entri (ops.go:106-144); ops.go:334 run |
| 258 | Recipe sendiri dengan blank {{var}} dan defaul… | ADA | Benar | ops.go:263-275 add (--desc/--sudo/--read-only/--overwrite); ops.go:151 render |
| 259 | Recipe dianggap write kecuali --read-only | ADA | Benar | ops.go:275 ReadOnly hanya bila --read-only; ux.md:121-126 |
| 260 | Berbagi recipe ke tim / mesin lain | ADA | Benar | importer.go:612 export memuat recipe; importer.go:196 |
| 261 | Recipe multi-langkah / berisi file (skrip) | TIDAK ADA | Benar | ops.go:275 Snippet satu Command |
| 262 | Output recipe terstruktur (parser) | TIDAK ADA | Benar | ops.go:359 runFleet → stdout teks |
| 263 | Katalog recipe komunitas / plugin | NON-GOAL | Benar | vision.md:227 "sistem plugin" |
| 264 | Audit setiap aksi (siapa, apa, di mana, hasil) | ADA | Dikoreksi: bukti (status tetap) | common.go:369-396 audit ditulis setelah aksi dan error OpenFile diabaikan (`return`) — tidak gagal tertutup; meta.go:276 flag --command/--failed/--limit/--target |
| 265 | Filter audit berdasarkan waktu / export | SEBAGIAN | Benar | meta.go:276 tanpa --since/--until |
| 266 | Kirim audit ke pusat (syslog/SIEM/webhook) | TIDAK ADA | Benar | common.go:391 hanya file lokal |
| 267 | Konfirmasi manusia untuk target produksi & per… | ADA | Benar | common.go:307-347 [y/N] dan ketik nama; non-interaktif → tolak |
| 268 | Approval jarak jauh (minta izin orang lain, ju… | NON-GOAL | Benar | vision.md:227 daemon/server |
| 269 | RBAC multi-user terpusat | NON-GOAL | Benar | vision.md:227; safety.md:24 |
| 270 | Session recording | TIDAK ADA | Benar | lihat #92 |
| 271 | Secret tidak pernah di argumen/output/audit | SEBAGIAN | Dikoreksi: ADA→SEBAGIAN, –→P1 | vault.go:142 AES-GCM, key.go:385 SECRET_IN_ARGS (secret set); tapi host.go:95-96 tidak memvalidasi --password-ref/--sudo-ref (lihat #5) |
| 272 | Policy perintah berbahaya yang bisa ditambah | ADA | Benar | meta.go:496 deny, meta.go:464 check |
| 273 | Allowlist (hanya perintah tertentu yang boleh… | TIDAK ADA | Benar | policy.go deny-list saja; grep allowlist: 0 hasil |
