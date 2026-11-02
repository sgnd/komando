# Analisis celah fitur: VPN & jaringan, secrets & identitas, UX lintas-fungsi & platform

Repo: `komando` cabang `feat/v0.3`, commit `4784fc9` (biner `bin/komando` versi `v0.1.1-0.20261102014502-4784fc9fe746`).
Metode: membaca `inventory.txt`, `extras.txt`, `roothelp.txt`, `docs/design/{vision,ux,network}.md`,
`docs/features/*`, `skills/komando/SKILL.md`, `README.md`, `install.sh`, `Makefile`, `.github/workflows/*`,
dan kode `internal/cli` (`vpn.go`, `vpnsession.go`, `tunnel.go`, `key.go`, `root.go`, `meta.go`, `common.go`,
`host.go`, `importer.go`, `everything.go`), `internal/vault/vault.go`, `internal/netx`, `internal/out/out.go`,
`internal/sshx/client.go`. Biner hanya dijalankan dengan `--help`/`schema`/`config show`/`__complete`
di `KOMANDO_HOME` scratch; tidak ada koneksi ke server mana pun.

Legenda status: **ADA** (sudah ada, ada bukti) · **SEBAGIAN** (ada, tapi ada yang kurang) ·
**TIDAK ADA** (dicek di kode/dokumen, tidak ditemukan) · **NON-GOAL** (dikecualikan oleh `vision.md`).
Prioritas hanya untuk celah: **P1** (kebutuhan harian / keamanan / penghambat agent), **P2**, **P3**.
Kutipan non-goal dari `vision.md` bagian "Bukan tujuan":
- N1: "GUI, TUI, sistem plugin, atau daemon/server. komando tetap CLI murni."
- N2: "Infrastructure as Code, provisioning cloud, atau GitOps."
- N3: "Monitoring atau alerting yang berjalan terus-menerus."
- N4: "Mengganti alat lengkap (`psql`, `kubectl`, `terraform`, `helm`)."

---

## A. VPN & akses jaringan

### A1. Model umum VPN dan jalur (`--via`)

| Kemampuan | Tools pembanding | Status komando | Bukti/catatan | Prioritas |
|---|---|---|---|---|
| Rantai jalur VPN → bastion → target untuk semua target | `ssh -J`, Termius | ADA | `--via a,b` di `host add/edit`, `conn add/edit`; `docs/design/network.md` "Satu konsep: `--via`" | — |
| Banyak VPN aktif sekaligus, subnet bentrok aman | — (OS VPN biasanya satu) | ADA | userspace/netstack per perintah; `network.md` "Ide utama"; `docs/features/vpn.md` | — |
| Sambung otomatis saat target butuh VPN | — | ADA | `vpn.go` Long help: "A command that needs it connects it" | — |
| Sesi latar per VPN dipakai ulang + putus saat idle | `tailscale up`, `nmcli` | ADA | `vpn up/down/status`, `vpn serve` (tersembunyi), `config set vpn_idle` (default 30m); `netx.ReapIdle()` di `root.go` | — |
| MFA selalu oleh manusia, agent dapat `VPN_LOGIN_REQUIRED` | — | ADA | `--mfa`, `vpnsession.go` (VPN_LOGIN_REQUIRED), keputusan pemilik di `network.md` | — |
| Status VPN: tersambung sejak kapan, dipakai siapa | `wg show`, `tailscale status` | SEBAGIAN | `vpn status` menampilkan sesi; belum ada statistik (handshake terakhir, byte rx/tx, latency, IP yang didapat) | P3 — diagnosa ringan, bukan kebutuhan harian |
| Uji konektivitas lewat VPN | `tailscale ping`, `ping` | ADA | `komando test kind:vpn` memakai `--check host:port`; alias `test`/`ping` | — |
| Ubah VPN tanpa hapus-tambah | `nmcli con modify` | SEBAGIAN | tidak ada `vpn edit` (inventory hanya add/down/list/rm/show/status/test/up); ganti lewat `vpn add --overwrite`. Mengganti `--password-ref`/`--check`/grup harus mengulang semua flag | P2 — konsistensi dengan `host edit`/`conn edit` (ux.md §1 kata kerja `edit`) |
| Deteksi bentrok rute untuk VPN mode OS | — | ADA | `internal/netx/routes.go`, commit 7149b1c; `network.md` fase 4 | — |
| Audit sambung/putus VPN | — | ADA | `audit(st, "vpn.up", ...)` di `vpnsession.go` | — |
| `doctor` mengecek klien VPN yang dibutuhkan | — | ADA | `meta.go` doctor: `vpnClients(v)` + `installHint` | — |
| DNS di dalam VPN (split DNS) tanpa mengubah DNS laptop | `wg-quick` DNS=, Tailscale MagicDNS | SEBAGIAN | WireGuard: resolver userspace dari `DNS=` (`netx/wireguard.go` baris 93; search domain diabaikan). Search domain dan MagicDNS untuk openconnect/ocproxy tidak dijamin | P3 |
| Kill switch / ubah rute default laptop | WARP, Mullvad | NON-GOAL | `network.md`: "komando tidak pernah mengubah rute, DNS, atau firewall laptop" (keputusan desain, bukan vision.md; sejalan N1) | — |
| VPN di menu bar / GUI status | Tunnelblick, Viscosity | NON-GOAL | N1 "GUI, TUI ... komando tetap CLI murni" | — |
| Proxy perusahaan HTTP(S) (`HTTPS_PROXY`, CONNECT proxy) | `aws`, `kubectl`, `gh` menghormati `HTTPS_PROXY` | TIDAK ADA | `kube.go:236`, `registry.go:43` membuat `http.Transport{}` tanpa `Proxy: http.ProxyFromEnvironment`; kind VPN hanya `socks`, tidak ada `http-proxy`. `ux.md` edge case menyebut "proxy perusahaan" | P2 — kantor dengan proxy wajib tidak bisa memakai cluster/registry |

### A2. WireGuard (wg / wg-quick)

| Kemampuan | Tools pembanding | Status komando | Bukti/catatan | Prioritas |
|---|---|---|---|---|
| Impor config wg-quick, kunci pindah ke vault | `wg-quick up` | ADA | `vpn add NAME wireguard --config`; `netx.StripWGKeys` → `secret:NAME-key`, `-psk` | — |
| Jalan di dalam proses tanpa root | wireguard-go, `wg-quick` (root) | ADA | `netstack.CreateNetTUN` di `netx/wireguard.go:225` | — |
| MTU, beberapa alamat, PSK | `wg-quick` | ADA | `WGConfig.MTU`, PSK ref | — |
| `PostUp`/`Table`/`ListenPort` | `wg-quick` | NON-GOAL | sengaja diabaikan (`wireguard.go:119`): tidak menyentuh jaringan laptop | — |
| Buat pasangan kunci WG / peer baru | `wg genkey`, `wg pubkey` | TIDAK ADA | tidak ada `vpn key`/gen; `key gen` hanya SSH | P3 — biasanya admin VPN yang membuat config |
| Statistik handshake/transfer | `wg show` | TIDAK ADA | `vpn status` tidak menampilkannya | P3 |
| Peringatan file `.conf` asli masih berisi kunci | — | ADA | catatan di output `vpn add` ("still holds the keys") | — |

### A3. OpenVPN / Pritunl

| Kemampuan | Tools pembanding | Status komando | Bukti/catatan | Prioritas |
|---|---|---|---|---|
| Profil `.ovpn` (juga Pritunl) | `openvpn`, Pritunl client | ADA | kind `openvpn`, alias `pritunl` (`vpn.go`) | — |
| Tanpa mengubah jaringan laptop (container Docker) | — | ADA | `openvpnContainer` di `vpnsession.go`; butuh Docker | — |
| Mode OS dengan sudo | `sudo openvpn` | ADA | `--os-mode`; pid di `/var/run`, log ke syslog | — |
| Penyaringan direktif berbahaya (`up`, `script-security`, path file) | — | ADA | `ovpnAllowed`, `checkOVPN` (inline-only untuk ca/cert/key) | — |
| Static challenge / OTP OpenVPN | `openvpn --static-challenge` | SEBAGIAN | direktif diizinkan; hanya manusia via `vpn up` interaktif; tidak ada dokumentasi alurnya | P3 |
| OpenVPN 3 / DCO / Access Server SAML | `openvpn3` | TIDAK ADA | hanya OpenVPN 2 | P3 |
| OpenVPN tanpa Docker dan tanpa sudo (userspace) | `ooni/minivpn` | TIDAK ADA | `network.md` menyebut evaluasi minivpn; tidak dibangun | P3 |

### A4. Keluarga openconnect

| Kemampuan | Tools pembanding | Status komando | Bukti/catatan | Prioritas |
|---|---|---|---|---|
| GlobalProtect, Fortinet, AnyConnect/ocserv, Pulse/Ivanti, F5 | `openconnect --protocol=` | ADA | `netx.Kinds` protocol `gp`, `fortinet`, `anyconnect`, `pulse`, `f5`; lewat `ocproxy` (SOCKS lokal) | — |
| Protokol Juniper Network Connect (`nc`) dan Array (`array`) | `openconnect --protocol=nc/array` | TIDAK ADA | tidak ada di `netx.Kinds` | P3 — jarang |
| Login SAML/SSO lewat browser (GP/AnyConnect/Fortinet SSO) | `openconnect --external-browser`, `gp-saml-gui` | TIDAK ADA | `vpnsession.go:205` hanya `--user`, `--passwd-on-stdin`; tidak ada opsi SSO. Banyak VPN korporat kini SAML-only | P2 — VPN korporat SAML tidak bisa dipakai |
| Pin sertifikat server (`--servercert`) | `openconnect --servercert` | TIDAK ADA | tidak ada flag; bergantung pada CA sistem | P2 — secure by default untuk portal self-signed |
| Auth group / realm (`--authgroup`, `--usergroup`) | `openconnect --authgroup` | TIDAK ADA | tidak ada flag | P2 — banyak portal AnyConnect butuh grup |
| Sertifikat klien (`-c`, `-k`, PKCS#12) | `openconnect -c` | TIDAK ADA | tidak ada flag | P3 |
| HIP report GlobalProtect (`--csd-wrapper`) | `openconnect --csd-wrapper` | TIDAK ADA | — | P3 |
| `tunsocks` sebagai alternatif `ocproxy` | `tunsocks` | TIDAK ADA | hanya `ocproxy` | P3 |

### A5. Tailscale / Headscale

| Kemampuan | Tools pembanding | Status komando | Bukti/catatan | Prioritas |
|---|---|---|---|---|
| Gabung tailnet userspace dengan auth key / login browser | `tailscale up` | ADA | kind `tailscale`; auth key via `--password-ref`, tanpa key → `MFA` (login browser) | — |
| Headscale (login server sendiri) | `tailscale up --login-server` | ADA | `--server` | — |
| `tailscale status` / daftar peer | `tailscale status` | SEBAGIAN | hanya `vpn status`/`test`; tidak ada daftar node tailnet | P3 |
| `tailscale ping` (direct/DERP) | `tailscale ping` | TIDAK ADA | — | P3 |
| Exit node | `tailscale up --exit-node` | TIDAK ADA | tidak relevan untuk akses target (exit node mengubah egress) | P3 |
| Tailscale SSH | `tailscale ssh` | SEBAGIAN | host di tailnet bisa dicapai lewat `--via tailnet` dengan SSH biasa; Tailscale SSH (auth oleh tailnet, tanpa kunci) tidak didukung | P3 |
| `serve` / `funnel` | `tailscale serve/funnel` | NON-GOAL | mempublikasi layanan lokal; di luar "client" devops; mendekati N1 (server) | — |
| Kirim file (`tailscale file cp`) | Taildrop | TIDAK ADA | `upload`/`download` via SFTP sudah memenuhi kebutuhan | P3 |
| Tag ACL / ephemeral node | `--advertise-tags`, auth key ephemeral | SEBAGIAN | bergantung pada jenis auth key; tidak ada flag | P3 |

### A6. Mesh/VPN lain

| Kemampuan | Tools pembanding | Status komando | Bukti/catatan | Prioritas |
|---|---|---|---|---|
| ZeroTier | `zerotier-cli join` | SEBAGIAN | hanya lewat kind `system` + `--check` (VPN dikelola OS); tidak ada kind `zerotier` (libzt userspace ada) | P3 |
| Nebula, NetBird | `nebula`, `netbird up` | SEBAGIAN | hanya via `system` | P3 |
| L2TP/IPsec/IKEv2 bawaan OS | `scutil --nc`, `nmcli` | ADA | alias `l2tp/ipsec/ikev2 = system`, `--service` | — |
| Cloudflare WARP (Zero Trust client) | `warp-cli connect` | SEBAGIAN | via `system --check`; `vpn up` tidak menjalankan `warp-cli` | P3 |

### A7. Akses zero-trust / just-in-time

| Kemampuan | Tools pembanding | Status komando | Bukti/catatan | Prioritas |
|---|---|---|---|---|
| AWS SSM Session Manager: shell/exec ke EC2 tanpa SSH terbuka | `aws ssm start-session`, ProxyCommand `AWS-StartSSHSession` | TIDAK ADA | tidak ada kind/step `--via` untuk SSM; `ProxyCommand` tidak ada di model host | **P1** — cara standar akses EC2 privat; universal devops client |
| AWS SSM port forwarding (ke RDS/ElastiCache) | `AWS-StartPortForwardingSessionToRemoteHost` | TIDAK ADA | sama | **P1** — sama, untuk `db`/`cache` di AWS |
| `ProxyCommand` generik (jalur keluar darurat untuk SSM/IAP/cloudflared/tsh) | OpenSSH `ProxyCommand` | TIDAK ADA | `host.go` `import ssh-config` hanya membaca `HostName/User/Port/IdentityFile/ProxyJump`; `ProxyCommand` dibuang **diam-diam**, melanggar `ux.md` §9 "Field yang tidak didukung dilaporkan" | **P1** — host hasil import gagal konek tanpa penjelasan |
| GCP IAP TCP tunnel | `gcloud compute start-iap-tunnel`, `gcloud compute ssh --tunnel-through-iap` | TIDAK ADA | — | P2 |
| Azure Bastion | `az network bastion ssh/tunnel` | TIDAK ADA | — | P3 |
| Cloudflare Access (SSH/TCP) | `cloudflared access ssh/tcp` | TIDAK ADA | — | P2 — umum di startup |
| Cloudflare Tunnel (mengekspos layanan) | `cloudflared tunnel` | NON-GOAL | menjalankan konektor = server/daemon (N1) | — |
| Teleport (`tsh ssh`, `tsh db`, `tsh kube`), sertifikat singkat | `tsh` | TIDAK ADA | tidak ada integrasi; sertifikat SSH dari file juga tidak dimuat (lihat B5) | P2 |
| HashiCorp Boundary | `boundary connect` | TIDAK ADA | — | P3 |
| StrongDM | `sdm connect` | TIDAK ADA | — | P3 |

### A8. Proxy dan forwarding untuk aplikasi lain

| Kemampuan | Tools pembanding | Status komando | Bukti/catatan | Prioritas |
|---|---|---|---|---|
| Local / remote forward / SOCKS5 lewat SSH di latar | `ssh -L/-R/-D` | ADA | `tunnel start -L/-R/-D`, `tunnel list/stop` | — |
| Tunnel ke conn berdasarkan nama (lewat `--via`/VPN) | — | ADA | `tunnel start app-db [--port]` | — |
| SOCKS "di dalam" VPN untuk browser | — | ADA | `tunnel start office -D 1080` (`docs/features/vpn.md`) | — |
| Bind tunnel di non-loopback butuh konfirmasi | — | SEBAGIAN | default `127.0.0.1` (`tunnel.go:66,77`), tetapi `-L 0.0.0.0:8080:...` diterima tanpa `--yes`. `network.md` "Keamanan": "kecuali diberi `--bind` (butuh `--yes`)" — tidak ditegakkan (`guardSafety` tidak dipanggil di `tunnel.go`) | **P1** — membuka port DB/SSH ke jaringan lokal/kafe; secure by default |
| Pakai proxy SOCKS yang ada (perusahaan) | proxychains | ADA | kind `socks` (`--address`, `--user` + `--password-ref`) | — |
| Memaksa aplikasi lain lewat proxy | `proxychains`, `tsocks` | SEBAGIAN | komando menyediakan SOCKS (`tunnel -D`), tetapi tidak membungkus program lain | P3 — alat asli via `tunnel` sudah cukup (ux.md §12) |
| VPN-over-SSH semua subnet | `sshuttle` | SEBAGIAN | `tunnel -D` + `--via` menutup kebutuhan komando sendiri; tidak ada mode "route subnet" | P3 — mengubah rute laptop bertentangan dengan `network.md` |
| Ekspos layanan lokal ke internet | `ngrok` | NON-GOAL | menjadi server publik (N1); `tunnel -R` ke server sendiri sudah ada | — |
| Forward ke pod / service Kubernetes | `kubectl port-forward` | SEBAGIAN | `cluster run` mengklasifikasikan `port-forward` sebagai destructive (`cluster.go:863`); tidak ada `tunnel start` ke service k8s | P2 — kebutuhan harian dev (di luar domain ini, dicatat) |

---

## B. Secrets & identitas

### B1. Vault lokal

| Kemampuan | Tools pembanding | Status komando | Bukti/catatan | Prioritas |
|---|---|---|---|---|
| Vault terenkripsi (AES-256-GCM, scrypt) | `pass`, `gopass`, ansible-vault | ADA | `internal/vault/vault.go`; mode `keyfile` atau `passphrase` (`KOMANDO_VAULT_PASS`) | — |
| Input secret tanpa argumen (prompt tersembunyi, `--from-env`, stdin) | `gh secret set` | ADA | `secret set`; `SECRET_IN_ARGS` menolak nilai posisional | — |
| `--reveal` hanya untuk manusia | 1Password (biometrik), `op read` butuh sesi | SEBAGIAN | `secret get --reveal` jalan dari pipe tanpa TTY/konfirmasi; hanya aturan di SKILL/AGENTS.md. Vision: "password tidak pernah terlihat oleh AI" | **P1** — agent bisa membaca semua password; secure by default |
| `secret rm` aman | `vault kv delete` (versi tetap ada) | SEBAGIAN | `key.go` `rm`: tanpa cek `IN_USE` (host/conn/vpn yang merujuk), tanpa konfirmasi/`--yes`, **tanpa baris audit**, hapus permanen. `ux.md` §8 meminta `IN_USE` untuk penghapusan yang masih dipakai | **P1** — satu perintah bisa memutus akses ke prod tanpa jejak |
| `secret set` tidak menimpa diam-diam | `gh secret set` (menimpa), `pass insert` (tanya) | SEBAGIAN | `vault.Set` selalu menimpa; tidak ada `--overwrite` (ux.md §3 nama flag baku) | P2 |
| Menyimpan `vault.key` di keyring OS (macOS Keychain, libsecret, Windows Credential Manager) | `aws-vault`, `gh auth` (keyring), `docker-credential-*` | TIDAK ADA | `vault.key` disimpan di sebelah `vault.json` (0600). Bisa via `security`/`secret-tool` CLI tanpa cgo | P2 — secure by default; mencuri satu folder = semua secret |
| Ganti passphrase / re-key vault | `ansible-vault rekey`, `gopass` | TIDAK ADA | tidak ada perintah | P2 |
| Kunci/buka vault sementara (sesi) | `op signin`, `bw unlock` | TIDAK ADA | keyfile selalu terbuka; passphrase per proses via env | P3 |
| Riwayat versi secret / pulihkan | Vault KV v2, gopass (git) | TIDAK ADA | satu nilai per nama, `UpdatedAt` saja | P3 |
| Generate password acak | `pass generate`, `op item create --generate-password` | TIDAK ADA | — | P3 |
| Rename/copy secret | `gopass mv/cp` | TIDAK ADA | — | P3 |
| Lihat siapa memakai secret | — | TIDAK ADA | `secret list` hanya `name`,`updated_at`; `host show`/`conn show` memperlihatkan ref dari sisi target | P2 — sebelum rotasi/hapus |
| Rotasi secret (ganti di server + vault sekaligus) | Vault dynamic, AWS SM rotation | TIDAK ADA | tidak ada `secret rotate`; manual: `user`/`db query ALTER USER` + `secret set` | P2 |
| Cek izin file untuk ref `file:` | `ssh` (menolak key 0644) | TIDAK ADA | `vault.Resolve` membaca `file:` tanpa cek mode, padahal `ux.md` §7 menyebut "izin file terlalu longgar → error" | P2 |

### B2. Referensi ke secret manager eksternal

| Kemampuan | Tools pembanding | Status komando | Bukti/catatan | Prioritas |
|---|---|---|---|---|
| `env:`, `file:` | — | ADA | `vault.Resolve` | — |
| 1Password (`op read`) | `op read` | ADA | `op://VAULT/ITEM/FIELD` → `op read --no-newline` | — |
| 1Password `op run` / `op inject` (env/template) | `op run --env-file`, `op inject` | TIDAK ADA | hanya satu nilai per ref; tidak ada injeksi env (lihat B4) | P2 |
| HashiCorp Vault KV | `vault kv get -field` | ADA | `vault:PATH#FIELD` | — |
| Vault dynamic DB credentials + lease renew/revoke | `vault read database/creds/role` | TIDAK ADA | ref hanya KV; tidak ada lease | P2 — kredensial singkat = praktik terbaik |
| Vault SSH CA (sign public key) | `vault ssh -mode=ca`, `vault write ssh/sign/...` | TIDAK ADA | lihat B5 | P2 |
| AWS Secrets Manager | `aws secretsmanager` | ADA | `aws-sm:NAME[#KEY]` | — |
| AWS SSM Parameter Store (SecureString) | `aws ssm get-parameter --with-decryption` | TIDAK ADA | hanya Secrets Manager | P2 — sangat umum di AWS |
| Google Secret Manager | `gcloud secrets versions access` | ADA | `gcp-sm:NAME[@PROJECT]` (selalu `latest`, tanpa pilih versi) | — |
| Azure Key Vault | `az keyvault secret show` | TIDAK ADA | ada aws-sm dan gcp-sm, Azure belum; tidak setara untuk "client universal" | P2 |
| Bitwarden / Vaultwarden | `bw get password` | TIDAK ADA | — | P2 — populer di tim kecil |
| `pass` / `gopass` | `pass show` | TIDAK ADA | — | P2 — murah ditambah (pola `external()`) |
| sops (file terenkripsi di git) | `sops -d --extract` | TIDAK ADA | — | P2 — umum di repo GitOps |
| age | `age -d` | TIDAK ADA | — | P3 |
| Doppler, Infisical | `doppler secrets get`, `infisical secrets get` | TIDAK ADA | — | P3 |
| aws-vault / profil AWS | `aws-vault exec` | SEBAGIAN | `aws-sm:` memakai `aws` CLI, jadi `AWS_PROFILE`/SSO berlaku; tidak ada pilihan profil per ref | P3 |
| Kubernetes Secret sebagai sumber | `kubectl get secret` | TIDAK ADA | `cluster get` menyembunyikan nilai Secret (benar), tidak ada ref `k8s:` | P3 |
| MFA/login eksternal tetap milik manusia | — | ADA | `external()` menjalankan CLI asli, pesan "(is it signed in?)" | — |
| Cache hasil ref eksternal dalam satu perintah | `op` session cache | SEBAGIAN | `external()` dipanggil tiap resolve, timeout 60s; banyak host dengan ref sama = banyak panggilan | P3 |

### B3. Identitas SSH & kunci

| Kemampuan | Tools pembanding | Status komando | Bukti/catatan | Prioritas |
|---|---|---|---|---|
| Generate/register/deploy kunci SSH | `ssh-keygen`, `ssh-copy-id` | ADA | `key gen/add/deploy/list/show/rm/edit` | — |
| Passphrase kunci dari vault | — | ADA | `key add --passphrase-ref` | — |
| ssh-agent (termasuk agent 1Password/Secretive/FIDO) | `ssh-agent` | ADA | `sshx/client.go:322` `agent.NewClient`; `IdentityAgent` dari ssh_config tidak dibaca (hanya `SSH_AUTH_SOCK`) | — |
| Sertifikat SSH dari file (`id_ed25519-cert.pub`) | OpenSSH `CertificateFile` | TIDAK ADA | `sshx` hanya memuat private key; sertifikat hanya jalan bila ada di agent | P2 — dibutuhkan Vault SSH CA/Teleport/step-ca |
| `IdentityAgent` per host | OpenSSH | TIDAK ADA | — | P3 |
| Rotasi kunci SSH di banyak server | `ssh-copy-id` + hapus lama | SEBAGIAN | `key deploy` (idempoten) ada; tidak ada "hapus kunci lama dari authorized_keys" | P2 |

### B4. Injeksi secret ke perintah/proses

| Kemampuan | Tools pembanding | Status komando | Bukti/catatan | Prioritas |
|---|---|---|---|---|
| Secret sebagai env var di perintah remote tanpa terlihat oleh agent (`--env DB_PASS=secret:x`) | `op run`, `doppler run`, Ansible `no_log` | TIDAK ADA | `exec/job/script --env` dan `host --env` menerima nilai literal (`common.go:475` `parseEnv`, tanpa `vault.Resolve`). Agent yang butuh password di skrip harus `--reveal` (melanggar visi) | **P1** — penghambat agent; inti "password tidak pernah terlihat AI" |
| Jalankan alat lokal dengan secret dari vault di env | `op run -- cmd`, `aws-vault exec` | SEBAGIAN | hanya untuk alat tertentu: `db shell` (psql/mysql) dan tunnel; tidak ada pembungkus umum | P2 |
| Muat `.env` (direnv) | `direnv`, `dotenv` | SEBAGIAN | `import env` membaca `.env` untuk membuat conn; tidak mengekspor `.env` ke perintah | P3 |
| Upload file berisi secret (template) ke server | `op inject`, Ansible template + vault | TIDAK ADA | `fs write --content/--from` literal; tidak ada `{{secret:x}}` | P2 — mis. menulis `.env` aplikasi tanpa membuka password |
| `host --env` tersimpan polos di `state.json` | — | SEBAGIAN | nilai `--env` host disimpan sebagai teks biasa; tidak ada peringatan bila berisi secret | P2 |

### B5. Berbagi tim & identitas terpusat

| Kemampuan | Tools pembanding | Status komando | Bukti/catatan | Prioritas |
|---|---|---|---|---|
| Berbagi vault antar anggota tim | 1Password shared vault, gopass multi-recipient, sops+age | SEBAGIAN | vault lokal per orang; jalur tim = ref eksternal (`op://`, `vault:`). Tidak ada vault multi-penerima | P2 — dokumentasikan pola "tim pakai ref eksternal" dulu |
| Export terenkripsi berikut secret | `ansible-vault`, `gopass export` | TIDAK ADA | `export` "no passwords"; `vision.md` Migrasi: "tanpa secret (atau terenkripsi)" belum dibangun | P2 |
| SSO/OIDC login ke komando | `gcloud auth login`, `az login` | NON-GOAL | tidak ada server komando (N1) | — |

---

## C. UX lintas-fungsi & platform

### C1. Konfigurasi, profil, env

| Kemampuan | Tools pembanding | Status komando | Bukti/catatan | Prioritas |
|---|---|---|---|---|
| Satu file konfigurasi + `config show/set` | `aws configure`, `gh config` | ADA | `config show/set` (host_key_policy, default_user, timeouts, parallel, max_output_bytes, audit, audit_sql, vpn_idle) | — |
| Pengaman untuk setting keamanan | — | ADA | `guardSafety` (`SAFETY_SETTING`) | — |
| Profil/konteks (beberapa inventaris: kerja vs klien) | `aws --profile`, `kubectl config use-context`, `az account set` | SEBAGIAN | hanya `KOMANDO_HOME=...`; tidak ada `--home`/`context use`. Grup/tag menutup sebagian kebutuhan | P3 — grup + selector cukup (KISS) |
| Override setting via env (`KOMANDO_TIMEOUT`, `KOMANDO_PARALLEL`) | `AWS_*`, `KUBECONFIG` | SEBAGIAN | hanya `KOMANDO_HOME`, `KOMANDO_OUTPUT`, `KOMANDO_ACTOR`, `KOMANDO_VAULT_PASS` | P3 |
| Konfigurasi per proyek (file di repo) | `.terraform`, `ansible.cfg` | TIDAK ADA | — | P3 |

### C2. Output

| Kemampuan | Tools pembanding | Status komando | Bukti/catatan | Prioritas |
|---|---|---|---|---|
| JSON envelope stabil + exit code | `gh --json`, `kubectl -o json` | ADA | `internal/out`, `meta.contract=1`, `docs/features/output.md` | — |
| Otomatis text di TTY, JSON di pipe | `gh` | ADA | `-o auto` (`root.go` `outputFormat`), `KOMANDO_OUTPUT` | — |
| `--pretty` JSON | `jq .` | ADA | `--pretty` | — |
| NDJSON streaming | `kubectl get -w -o json` | ADA | `exec --stream`, `logs --follow` | — |
| YAML | `kubectl -o yaml`, `az -o yaml` | TIDAK ADA | `out.go:89` "yaml-ish not supported, keep it simple" — keputusan KISS | P3 |
| CSV/TSV (mis. hasil `db query`, `list`) | `az -o tsv`, `psql --csv` | TIDAK ADA | hanya json/text | P2 — ekspor hasil query ke spreadsheet sering diminta |
| Filter/query bawaan (JMESPath/jq) | `aws --query`, `gh --jq`, `az --query` | TIDAK ADA | pengguna harus pakai `jq` | P3 — `jq` cukup; KISS |
| Template output (Go template) | `gh --template`, `docker --format` | TIDAK ADA | — | P3 |
| Pilih kolom/field | `gh --json f1,f2`, `kubectl -o custom-columns` | TIDAK ADA | — | P3 |
| `--no-headers` | `kubectl --no-headers` | TIDAK ADA | teks tabel selalu berheader | P3 |
| Warna & `NO_COLOR` | `gh`, `kubectl` | ADA | tidak ada warna sama sekali (grep tidak menemukan kode ANSI), jadi `NO_COLOR` otomatis terpenuhi; `ux.md` §4 | — |
| Output terpotong dengan `truncated` + hint | `kubectl logs --limit-bytes` | ADA | `--max-output`, `--limit`, `ux.md` §4 | — |
| Pagination (cursor/continue) | `aws --starting-token`, `gh --paginate` | SEBAGIAN | `--limit` + `truncated`; tidak ada token lanjutan (`storage ls`, `registry ls`, `cache keys`) | P3 |
| `--quiet` (hanya kode keluar) | `grep -q`, `gh -q` | TIDAK ADA | — | P3 |
| `--watch`/refresh | `kubectl get -w`, `watch` | TIDAK ADA | `job wait`, `logs --follow` ada; refresh status berulang mendekati N3 | P3 |

### C3. Bantuan, completion, dokumentasi

| Kemampuan | Tools pembanding | Status komando | Bukti/catatan | Prioritas |
|---|---|---|---|---|
| `--help` dengan contoh nyata | `gh`, `kubectl` | ADA | `Example:` di perintah (`TestConventions`) | — |
| "Did you mean" untuk perintah/selector | `git`, `kubectl` | ADA | `komando lst` → saran; `ux.md` §2.4 | — |
| `komando` tanpa argumen: tiga langkah pertama | `gh` | SEBAGIAN | menampilkan help panjang penuh, bukan "tiga langkah" (`ux.md` §10) | P3 |
| Completion statis bash/zsh/fish/powershell | semua CLI | ADA | `completion` (cobra) | — |
| Completion dinamis nama host/conn/grup/tag/VPN/secret | `kubectl` (nama resource), `gh` | TIDAK ADA | 0 `ValidArgsFunction`/`RegisterFlagCompletionFunc`; `__complete exec ""` kosong. `ux.md` §10 menjanjikannya | **P1** — kebutuhan harian, ramah pemula, dijanjikan di ux.md |
| Man page | `git`, `gh` (man) | TIDAK ADA | cobra/doc bisa membuatnya di `make dist` | P3 |
| Dokumen offline | `gh help`, `az find` | ADA | `guide`, `schema`, `--help`, `docs/features/` | — |
| i18n (Bahasa Indonesia) | — | SEBAGIAN | `README.id.md`, `docs/features/id/` lengkap; pesan CLI/hint hanya Inggris | P3 — dokumen sudah ID; pesan stabil penting untuk agent |
| Positioning di root help | — | SEBAGIAN | `root.go` Short/Long masih "servers (SSH), databases, caches and storage", belum cluster/registry/VPN/secret (`vision.md` celah 1) | P3 |

### C4. Logging, debug, diagnosa

| Kemampuan | Tools pembanding | Status komando | Bukti/catatan | Prioritas |
|---|---|---|---|---|
| `--verbose`/`--debug`/trace (SSH handshake, HTTP, jalur `--via`) | `ssh -vvv`, `kubectl -v=8`, `aws --debug` | TIDAK ADA | tidak ada flag; `-v` dipakai untuk `--version` | P2 — mendiagnosis koneksi VPN/bastion yang gagal |
| `doctor` (cek lokal) | `flyctl doctor`, `brew doctor` | ADA | state, keys, ssh-agent, klien VPN, platform | — |
| `doctor` cek CLI secret eksternal (`op`, `vault`, `aws`, `gcloud`) yang dirujuk | — | TIDAK ADA | doctor tidak memeriksa ref eksternal | P3 |
| Log VPN per sesi | — | ADA | log file per sesi (`vpnsession.go` `logFile`) | — |

### C5. Distribusi, rilis, platform

| Kemampuan | Tools pembanding | Status komando | Bukti/catatan | Prioritas |
|---|---|---|---|---|
| Skrip install + checksum | `flyctl`, `doctl` | ADA | `install.sh` (verifikasi `checksums.txt`) | — |
| `go install` | — | ADA | README | — |
| Homebrew | `brew install gh` | TIDAK ADA | tidak ada tap/formula | P2 — jalur install paling umum di macOS; ramah pemula |
| apt/rpm (deb/rpm, repo) | `gh`, `doctl` | TIDAK ADA | `make dist` hanya tar.gz | P3 |
| Scoop/winget | `gh`, `az` | TIDAK ADA | Windows tidak didukung | P3 |
| Docker image (untuk CI) | `amazon/aws-cli`, `bitnami/kubectl` | TIDAK ADA | — | P3 |
| Nix | nixpkgs | TIDAK ADA | — | P3 |
| Windows native | semua CLI pembanding | TIDAK ADA | `Makefile` `PLATFORMS` hanya linux/darwin; `install.sh` menolak; `syscall.SysProcAttr{Setsid}` di `vpnsession.go` | P2 — client universal; WSL sebagai jalan sementara sudah didokumentasikan |
| Rilis bertanda tangan / provenance / SBOM | `cosign`, GitHub attestations, `gh` (signed) | SEBAGIAN | hanya `checksums.txt` dari sumber yang sama (`release.yml`); tanpa signature/SBOM | P2 — alat yang memegang kunci SSH; secure by default |
| Cek versi / self-update | `gh` (notifikasi), `flyctl version upgrade` | TIDAK ADA | `version` hanya cetak versi; jalankan ulang `install.sh` | P2 — patch keamanan cepat sampai (SECURITY.md: hanya rilis terbaru didukung) |
| Kebijakan telemetri | `gh` (opt-out), `az` | SEBAGIAN | tidak ada telemetri (tidak ada kode jaringan keluar), tapi tidak dinyatakan di README/SECURITY | P3 — tulis "no telemetry" |
| Biner tunggal pure Go ≤ 40 MB | — | ADA | `CGO_ENABLED=0`, aturan `vision.md` | — |

### C6. Inventaris, pindah mesin, tim

| Kemampuan | Tools pembanding | Status komando | Bukti/catatan | Prioritas |
|---|---|---|---|---|
| Selector universal (glob, `@group`, `tag:`, `label:`, `kind:`, `!`) | Ansible patterns, `kubectl -l` | ADA | `select.go`, `docs/features/targets.md` | — |
| Import dari alat lain | — | ADA | `import ssh-config|pgpass|mycnf|env|kubeconfig|docker|filezilla|rclone|dbeaver|komando` | — |
| Import `~/.aws` (conn storage), Termius, TablePlus | — | SEBAGIAN | `vision.md` tabel Migrasi mencantumkan `aws`, `termius`, `tableplus`; belum ada (`importer.go`) | P3 |
| Export/import pindah mesin | `gh` (tidak ada), Termius sync | ADA | `export [TARGET] --to`, `import komando` | — |
| Sinkron antar-mesin otomatis | Termius cloud sync | NON-GOAL | butuh server/daemon (N1); file export + git cukup | — |
| Inventaris tim terpusat | Ansible inventory di git, Teleport | SEBAGIAN | export file bisa di-commit; tidak ada `import --update` yang merge perubahan tim (idempoten, tapi beda dilaporkan, tidak diterapkan) | P2 — pola "inventaris tim di git" perlu didokumentasikan |
| Inventaris dinamis dari API cloud (EC2, GCP, DO, Hetzner) | Ansible dynamic inventory, `doctl compute droplet list` | TIDAK ADA | `vision.md`: "VM cloud" kandidat setelah v1.0 | P2 — server cloud berubah sering |
| Ringkasan kesehatan sekali jalan | `flyctl status`, `kubectl get` | SEBAGIAN | `test all`, `recipe run health`, `cluster status`, `facts`; tidak ada satu "status @prod" yang menggabungkan | P3 |
| Biaya/penggunaan | `aws ce`, `doctl balance` | NON-GOAL | provisioning/billing cloud di luar "client devops" (N2) | — |

### C7. Keamanan proses, tata kelola, audit

| Kemampuan | Tools pembanding | Status komando | Bukti/catatan | Prioritas |
|---|---|---|---|---|
| `--dry-run` global | `terraform plan`, `kubectl --dry-run=server` | ADA | flag global; `dryrun_test.go` | — |
| Protected + `--yes`, konfirmasi manusia `[y/N]`/ketik nama | `terraform apply` approval | ADA | `ux.md` §6, `confirmProtected` | — |
| Policy perintah destruktif + `--allow-dangerous` | — | ADA | `policy list/check/deny/allow` | — |
| Approval dua orang / RBAC | Teleport access request, Boundary | NON-GOAL | butuh server (N1); protected + human prompt adalah penggantinya | — |
| Audit log lokal (actor, target, via) | CloudTrail, `ansible` log | ADA | `audit.jsonl`, `KOMANDO_ACTOR`, filter `--target/--command/--failed/--limit` | — |
| Audit **gagal tertutup** | — | SEBAGIAN | `common.go` `audit()`: bila file tak bisa dibuka → `return` diam-diam, hasil `f.Write` diabaikan. Bertentangan dengan `ux.md` §6 "Gagal tertutup: kalau audit tidak bisa ditulis, perubahan ditolak" | **P1** — janji keamanan tidak ditepati |
| Filter audit berdasarkan waktu (`--since/--until`) dan actor | `aws cloudtrail lookup-events` | TIDAK ADA | hanya limit/target/command/failed | P2 |
| Kirim audit ke syslog/SIEM/HTTP | auditd, Vector | TIDAK ADA | file JSONL lokal (bisa di-tail oleh alat lain) | P2 — tim/perusahaan butuh jejak terpusat |
| Rotasi file audit | logrotate | TIDAK ADA | `audit.jsonl` tumbuh terus; `audit` membaca seluruh file | P3 |
| Notifikasi (Slack/webhook) setelah aksi/job | Ansible callback, `gh` notifications | TIDAK ADA | notifikasi berkelanjutan adalah NON-GOAL (N3); notifikasi satu kali saat `job wait` selesai tidak ada | P3 |
| Penjadwalan | cron, `gh workflow` | SEBAGIAN | `cron set/list/rm` mengatur crontab **remote**; penjadwalan di laptop = daemon (N1) | — (sisi lokal NON-GOAL) |

### C8. Integrasi AI agent

| Kemampuan | Tools pembanding | Status komando | Bukti/catatan | Prioritas |
|---|---|---|---|---|
| Skill untuk Claude Code, Codex, Cursor, Gemini CLI | — | ADA | `guide install [--project]` → `.claude/skills`, `.agents/skills`; `skills/komando/SKILL.md`, `AGENTS.md` | — |
| Playbook agent | — | ADA | `komando guide` (`internal/cli/guide.md`) | — |
| Skema mesin semua perintah/flag/exit code | `gh api`-style, OpenAPI | SEBAGIAN | `schema [--compact]` ada, tapi bagian tetapnya basi: `meta.go:244-254` `target_selectors` menyebut "hosts" saja dan tanpa `kind:`; `secret_refs` hanya `secret:|env:|file:` (tanpa `op://`, `vault:`, `aws-sm:`, `gcp-sm:`). Agent diarahkan memakai `schema` sebagai sumber kebenaran | **P1** — agent menerima info salah; murah diperbaiki |
| Skema bentuk `data` per perintah (JSON Schema output) | — | TIDAK ADA | hanya envelope; field `data` tidak dideskripsikan | P2 — kontrak v1.0 lebih kuat |
| MCP server (stdio) | banyak CLI devops kini punya MCP | TIDAK ADA | tidak ada; skill + CLI sudah jalan. MCP stdio dijalankan oleh agent (bukan daemon), tapi menambah permukaan | P2 — klien non-shell (Claude Desktop, IDE) tidak bisa memakai komando |
| Nama actor otomatis untuk agent | — | SEBAGIAN | `KOMANDO_ACTOR` manual; default `$USER` (agent dan manusia sama di audit) | P2 — audit tidak membedakan agent bila lupa diset |
| Agent tidak bisa menjawab prompt | — | ADA | jawaban dibaca dari TTY, bukan stdin (`ux.md` §6) | — |

### C9. Keandalan

| Kemampuan | Tools pembanding | Status komando | Bukti/catatan | Prioritas |
|---|---|---|---|---|
| Idempotensi | Ansible | ADA | `cron set`, `user add`, `key deploy`, `import`, `fs write --if-changed` | — |
| Paralel dibatasi | Ansible forks | ADA | `-P/--parallel`, `--fail-fast` | — |
| Retry/backoff koneksi | `aws` (retry mode), Ansible `retries` | TIDAK ADA | hanya `minio.MaxRetry=2` dan retry token registry; guide melarang retry buta | P3 — hint + agent memutuskan sudah sejalan dengan desain |
| Rate limit (Docker Hub, API) | `crane` | TIDAK ADA | hanya `--parallel` | P3 |
| Ctrl-C bersih (exit 130, rollback) | — | ADA | `signal.NotifyContext` di `root.go`; `ux.md` §6 | — |
| Job panjang terlepas | `nohup`, Ansible async | ADA | `job start/status/logs/wait/kill/rm` | — |
| State aman untuk proses bersamaan | — | ADA | `store.Update` dengan file lock (`ux.md` §8) | — |
| Fuzzy picker / prompt interaktif pilih host | `fzf`, `gcloud` interactive | NON-GOAL | mendekati TUI (N1: "GUI, TUI ... komando tetap CLI murni"); completion dinamis adalah penggantinya | — |
| Alias/perintah buatan pengguna | `gh alias set`, `git alias` | SEBAGIAN | `recipe add` (perintah remote tersimpan dengan `{{blank}}`); tidak ada alias perintah komando sendiri | P3 |

---

## Ringkasan prioritas P1 (urut dampak)

1. **Secret ke env/perintah remote tanpa `--reveal`** (`exec/job/script --env K=secret:x`, template `fs write`) — B4. Tanpa ini agent terpaksa membaca password.
2. **`secret get --reveal` tanpa gerbang manusia** — B1. Agent bisa membaca semua secret; harus TTY/konfirmasi seperti `--yes`.
3. **`secret rm` tanpa `IN_USE`, konfirmasi, dan audit** — B1.
4. **Audit fail-open** (`common.go` `audit()` mengabaikan error) — C7, melanggar `ux.md` §6.
5. **Tunnel bind non-loopback tanpa `--yes`** — A8, melanggar `network.md` "Keamanan".
6. **AWS SSM Session Manager (shell + port forwarding) sebagai langkah `--via`** — A7.
7. **`ProxyCommand` dibuang diam-diam saat `import ssh-config`** (dan tidak ada jalur ProxyCommand generik) — A7, melanggar `ux.md` §9.
8. **Completion dinamis nama target** — C3, dijanjikan `ux.md` §10.
9. **`komando schema` basi** (selector & secret ref) — C8; agent memakai schema sebagai sumber kebenaran.

(Hanya sembilan item yang layak P1; kandidat P2 teratas berikutnya: SAML/SSO openconnect, `HTTPS_PROXY`, keyring OS untuk `vault.key`, `--debug`, Homebrew, rilis bertanda tangan, MCP server, Azure Key Vault/Bitwarden/pass/sops.)

## Hitungan status

Total 197 kemampuan dinilai:

| Status | Jumlah |
|---|---|
| ADA | 68 |
| SEBAGIAN | 40 |
| TIDAK ADA | 78 |
| NON-GOAL | 11 |

Prioritas celah (baris SEBAGIAN/TIDAK ADA): P1 = 10 baris (9 tema; SSM shell dan SSM port forwarding dihitung terpisah), P2 = 43, P3 = 64.
