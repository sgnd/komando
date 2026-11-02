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
| Kill switch / ubah rute default laptop | WARP, Mullvad | TIDAK ADA | tidak dikecualikan oleh `vision.md` "Bukan tujuan" (N1–N4 tidak menyebutnya), jadi bukan NON-GOAL; tetapi sengaja tidak dibangun: `network.md:169` "komando tidak pernah mengubah rute, DNS, atau firewall laptop" | P3 — jangan dibangun selama keputusan `network.md` berlaku |
| VPN di menu bar / GUI status | Tunnelblick, Viscosity | NON-GOAL | N1 "GUI, TUI ... komando tetap CLI murni" | — |
| Proxy perusahaan HTTP(S) (`HTTPS_PROXY`, CONNECT proxy) | `aws`, `kubectl`, `gh` menghormati `HTTPS_PROXY` | SEBAGIAN | `storage` (S3) sudah menghormati `HTTPS_PROXY`: `internal/storex/storex.go:72` meng-clone `http.DefaultTransport` (berisi `ProxyFromEnvironment`; dimatikan hanya bila ada `--via`). Cluster dan registry belum: `internal/kube/kube.go:236`, `internal/registry/registry.go:43` membuat `http.Transport{}` tanpa `Proxy`. SSH/db/cache tidak lewat proxy HTTP; kind VPN hanya `socks`, tidak ada `http-proxy`. `ux.md:295` edge case menyebut "proxy perusahaan" | P2 — kantor dengan proxy wajib tidak bisa memakai cluster/registry |

### A2. WireGuard (wg / wg-quick)

| Kemampuan | Tools pembanding | Status komando | Bukti/catatan | Prioritas |
|---|---|---|---|---|
| Impor config wg-quick, kunci pindah ke vault | `wg-quick up` | ADA | `vpn add NAME wireguard --config`; `netx.StripWGKeys` → `secret:NAME-key`, `-psk` | — |
| Jalan di dalam proses tanpa root | wireguard-go, `wg-quick` (root) | ADA | `netstack.CreateNetTUN` di `netx/wireguard.go:225` | — |
| MTU, beberapa alamat, PSK | `wg-quick` | ADA | `WGConfig.MTU`, PSK ref | — |
| `PostUp`/`Table`/`ListenPort` | `wg-quick` | TIDAK ADA | sengaja diabaikan (`netx/wireguard.go:119`): tidak menyentuh jaringan laptop. Keputusan `network.md:169`, bukan `vision.md` "Bukan tujuan", jadi bukan NON-GOAL | P3 — jangan dibangun (menjalankan skrip/mengubah rute laptop) |
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
| Static challenge / OTP OpenVPN | `openvpn --static-challenge` | TIDAK ADA | direktif lolos filter (`vpn.go:61`), tetapi tidak ada jalan mengetik OTP: mode container `docker run -d` + `--daemon` (`ovpn/entrypoint.sh:13`), mode OS `openvpn --daemon` dengan `--auth-user-pass` file (`vpnsession.go:258-264`); keduanya tanpa stdin, termasuk saat `vpn up` interaktif | P3 |
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
| Teleport (`tsh ssh`, `tsh db`, `tsh kube`), sertifikat singkat | `tsh` | TIDAK ADA | tidak ada integrasi; sertifikat SSH dari file juga tidak dimuat (lihat B3) | P2 |
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
| Vault terenkripsi (AES-256-GCM, scrypt), daftar nama secret tanpa nilai | `pass`/`pass ls`, `gopass ls`, ansible-vault, `vault kv list` | ADA | `internal/vault/vault.go`; mode `keyfile` atau `passphrase` (`KOMANDO_VAULT_PASS`); `secret list` hanya nama dan `updated_at` | — |
| Input secret tanpa argumen (prompt tersembunyi, `--from-env`, stdin) | `gh secret set` | ADA | `secret set`; `SECRET_IN_ARGS` menolak nilai posisional | — |
| `--reveal` hanya untuk manusia | 1Password (biometrik), `op read` butuh sesi | SEBAGIAN | `secret get --reveal` jalan dari pipe tanpa TTY/konfirmasi (`key.go:447-452`; hanya dicatat `secret.reveal` di audit); hanya aturan di SKILL/AGENTS.md. Vision: "password tidak pernah terlihat oleh AI" | **P1** — agent bisa membaca semua password; secure by default |
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
| Vault SSH CA (sign public key) | `vault ssh -mode=ca`, `vault write ssh/sign/...` | TIDAK ADA | lihat B3 (sertifikat SSH dari file) | P2 |
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
| `--help` dengan contoh nyata | `gh`, `kubectl` | ADA | `Example:` di 66 dari ±155 perintah (`grep -c 'Example:' internal/cli/*.go`); `TestConventions` tidak memeriksa contoh, jadi perintah seperti `vpn up`, `secret get` tanpa contoh | — |
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
| Biner tunggal pure Go (tanpa batas ukuran) | — | ADA | `CGO_ENABLED=0` + `-trimpath -s -w` di `Makefile` `dist`; build rilis terukur 35 MB (darwin/arm64) dan 37 MB (linux/amd64). `bin/komando` lokal 51 MB karena build biasa; aturan `vision.md:185` | — |

### C6. Inventaris, pindah mesin, tim

| Kemampuan | Tools pembanding | Status komando | Bukti/catatan | Prioritas |
|---|---|---|---|---|
| Selector universal (glob, `@group`, `tag:`, `label:`, `kind:`, `!`) | Ansible patterns, `kubectl -l` | ADA | `select.go`, `docs/features/targets.md` | — |
| Import dari alat lain | — | ADA | `import` dengan sumber `ssh-config`, `pgpass`, `mycnf`, `env`, `kubeconfig`, `docker`, `filezilla`, `rclone`, `dbeaver`, `komando` (`importer.go:49`) | — |
| Import `~/.aws` (conn storage), Termius, TablePlus | — | SEBAGIAN | `vision.md` tabel Migrasi mencantumkan `aws`, `termius`, `tableplus`; belum ada (`importer.go`) | P3 |
| Export/import pindah mesin | `gh` (tidak ada), Termius sync | ADA | `export [TARGET] --to`, `import komando` | — |
| Sinkron antar-mesin otomatis | Termius cloud sync | NON-GOAL | butuh server/daemon (N1); file export + git cukup | — |
| Inventaris tim terpusat | Ansible inventory di git, Teleport | SEBAGIAN | export file bisa di-commit; `import komando FILE` melewati nama yang sudah ada (dilaporkan sebagai `skipped`), dan `--overwrite` mengganti seluruh entri; tidak ada merge per field / laporan beda | P2 — pola "inventaris tim di git" perlu didokumentasikan |
| Inventaris dinamis dari API cloud (EC2, GCP, DO, Hetzner) | Ansible dynamic inventory, `doctl compute droplet list` | TIDAK ADA | `vision.md`: "VM cloud" kandidat setelah v1.0 | P2 — server cloud berubah sering |
| Ringkasan kesehatan sekali jalan | `flyctl status`, `kubectl get` | SEBAGIAN | `test all`, `recipe run health`, `cluster status`, `facts`; tidak ada satu "status @prod" yang menggabungkan | P3 |
| Biaya/penggunaan | `aws ce`, `doctl balance` | TIDAK ADA | `vision.md` "Bukan tujuan" N2 hanya menyebut IaC, provisioning cloud, dan GitOps; melihat biaya tidak dikecualikan, jadi bukan NON-GOAL. Tidak ada perintah biaya | P3 — bukan kebutuhan harian; nilai dengan "kriteria menambah family" |

### C7. Keamanan proses, tata kelola, audit

| Kemampuan | Tools pembanding | Status komando | Bukti/catatan | Prioritas |
|---|---|---|---|---|
| `--dry-run` global | `terraform plan`, `kubectl --dry-run=server` | ADA | flag global; `dryrun_test.go` | — |
| Protected + `--yes`, konfirmasi manusia `[y/N]`/ketik nama | `terraform apply` approval | ADA | `ux.md` §6, `confirmProtected` | — |
| Policy perintah destruktif + `--allow-dangerous` | — | ADA | `policy list/check/deny/allow` | — |
| Approval dua orang / RBAC | Teleport access request, Boundary | NON-GOAL | butuh server (N1); protected + human prompt adalah penggantinya | — |
| Audit log lokal (actor, target) | CloudTrail, `ansible` log | ADA | `audit.jsonl` (`common.go:370`: ts, command, ok, dry_run, actor, hosts, remote), `KOMANDO_ACTOR`, filter `--target/--command/--failed/--limit`. Jalur `--via` tidak dicatat (hanya `tunnel.start` mencatat spec) | — |
| Audit **gagal tertutup** | — | SEBAGIAN | `common.go` `audit()`: bila file tak bisa dibuka → `return` diam-diam, hasil `f.Write` diabaikan. Bertentangan dengan `ux.md` §6 "Gagal tertutup: kalau audit tidak bisa ditulis, perubahan ditolak" | **P1** — janji keamanan tidak ditepati |
| Filter audit berdasarkan waktu (`--since/--until`) dan actor | `aws cloudtrail lookup-events` | TIDAK ADA | hanya limit/target/command/failed | P2 |
| Kirim audit ke syslog/SIEM/HTTP | auditd, Vector | TIDAK ADA | file JSONL lokal (bisa di-tail oleh alat lain) | P2 — tim/perusahaan butuh jejak terpusat |
| Rotasi file audit | logrotate | TIDAK ADA | `audit.jsonl` tumbuh terus; `audit` membaca seluruh file | P3 |
| Notifikasi (Slack/webhook) setelah aksi/job | Ansible callback, `gh` notifications | TIDAK ADA | notifikasi berkelanjutan adalah NON-GOAL (N3); notifikasi satu kali saat `job wait` selesai tidak ada | P3 |
| Penjadwalan | cron, `gh workflow` | ADA | `cron set/list/rm` mengatur crontab **remote** (`modules.go:716`); penjadwalan di laptop = daemon (N1), jadi bagian yang belum ada adalah NON-GOAL, bukan celah | — |

### C8. Integrasi AI agent

| Kemampuan | Tools pembanding | Status komando | Bukti/catatan | Prioritas |
|---|---|---|---|---|
| Skill untuk Claude Code, Codex, Cursor, Gemini CLI | `claude mcp add`, `npx skills add`, aturan Cursor (`.cursor/rules`) | ADA | `guide install [--project]` → `.claude/skills`, `.agents/skills`; `skills/komando/SKILL.md`, `AGENTS.md` | — |
| Playbook agent | — | ADA | `komando guide` (`internal/cli/guide.md`) | — |
| Skema mesin semua perintah/flag/exit code | `gh api`-style, OpenAPI | SEBAGIAN | `schema [--compact]` ada, tapi bagian tetapnya basi: `meta.go:243-253` `target_selectors` menyebut "hosts" saja dan tanpa `kind:`; `secret_refs` hanya `secret:` / `env:` / `file:` (tanpa `op://`, `vault:`, `aws-sm:`, `gcp-sm:`). Agent diarahkan memakai `schema` sebagai sumber kebenaran | **P1** — agent menerima info salah; murah diperbaiki |
| Skema bentuk `data` per perintah (JSON Schema output) | — | TIDAK ADA | hanya envelope; field `data` tidak dideskripsikan | P2 — kontrak v1.0 lebih kuat |
| MCP server (stdio) | banyak CLI devops kini punya MCP | TIDAK ADA | tidak ada; skill + CLI sudah jalan. MCP stdio dijalankan oleh agent (bukan daemon), tapi menambah permukaan | P2 — klien non-shell (Claude Desktop, IDE) tidak bisa memakai komando |
| Nama actor otomatis untuk agent | — | SEBAGIAN | `KOMANDO_ACTOR` manual; default `$USER` (agent dan manusia sama di audit) | P2 — audit tidak membedakan agent bila lupa diset |
| Agent tidak bisa menjawab prompt | — | ADA | prompt hanya muncul bila stdin **dan** stderr adalah terminal (`common.go:295` `interactive()`); dari pipe/agent jawabannya selalu "tidak" (`confirmYes`, `common.go:314`). Jawaban dibaca dari stdin-yang-TTY, bukan `/dev/tty` (`ux.md` §6) | — |

### C9. Keandalan

| Kemampuan | Tools pembanding | Status komando | Bukti/catatan | Prioritas |
|---|---|---|---|---|
| Idempotensi | Ansible | ADA | `cron set`, `user add`, `key deploy`, `import`, `fs write --if-changed` | — |
| Paralel dibatasi | Ansible forks | ADA | `-P/--parallel`, `--fail-fast` | — |
| Retry/backoff koneksi | `aws` (retry mode), Ansible `retries` | TIDAK ADA | hanya `minio.MaxRetry=2` dan retry token registry; guide melarang retry buta | P3 — hint + agent memutuskan sudah sejalan dengan desain |
| Rate limit (Docker Hub, API) | `crane` | TIDAK ADA | hanya `--parallel` | P3 |
| Ctrl-C bersih (exit 130, rollback) | — | SEBAGIAN | `signal.NotifyContext` di `root.go:64` membatalkan context; tetapi `context.Canceled` dipetakan ke `CANCELLED` dengan exit **1** (`common.go:122-123`, `out.ExitError`), bukan 130, dan audit tidak mencatat `interrupted` seperti janji `ux.md:183` (§6) | P3 — agent tidak bisa membedakan Ctrl-C dari error biasa |
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

Total 197 kemampuan dinilai (setelah verifikasi per baris; lihat bagian berikut):

| Status | Jumlah |
|---|---|
| ADA | 68 |
| SEBAGIAN | 40 |
| TIDAK ADA | 81 |
| NON-GOAL | 8 |

Prioritas celah (121 baris SEBAGIAN/TIDAK ADA, semuanya kini berprioritas): P1 = 10 baris (9 tema; SSM shell dan SSM port forwarding dihitung terpisah), P2 = 43, P3 = 68.

Perubahan dari versi sebelumnya (ADA 68, SEBAGIAN 40, TIDAK ADA 78, NON-GOAL 11; P3 = 64): tiga baris NON-GOAL
yang tidak dikecualikan `vision.md` (kill switch, `PostUp`/`Table`/`ListenPort`, biaya) menjadi TIDAK ADA P3; proxy HTTP(S)
menjadi SEBAGIAN (storage sudah menghormati `HTTPS_PROXY`); static challenge OpenVPN menjadi TIDAK ADA; penjadwalan
menjadi ADA (sisi lokal NON-GOAL); Ctrl-C menjadi SEBAGIAN P3 (exit 1, bukan 130).

## Verifikasi per baris

Diperiksa ulang 2026-11-02 pada commit `4784fc9`: setiap baris dicek langsung ke kode (grep/baca file) dan ke biner
(`KOMANDO_HOME=$(mktemp -d) bin/komando ... --help`), bukan dari teks "Bukti" lama. NON-GOAL hanya diterima bila
`docs/design/vision.md` bagian "Bukan tujuan" (baris 221–228) benar-benar mengecualikannya; keputusan di `network.md`
tidak dihitung sebagai NON-GOAL. Path relatif ke `internal/cli/` kecuali disebut lain.

| # | Kemampuan (singkat) | Status akhir | Hasil cek | Bukti di kode |
|---|---|---|---|---|
| 1 | Rantai jalur `--via` | ADA | Benar | `host.go:55` `--via` (+alias `--jump`), `conn.go:65` `--via`; edit: `host.go:183`, `conn.go:203` |
| 2 | Banyak VPN sekaligus | ADA | Benar | `netx/netx.go:47` wireguard "many at once"; sesi per VPN `vpnsession.go:144` |
| 3 | Sambung otomatis | ADA | Benar | `vpn.go:32` Long "A command that needs it connects it" |
| 4 | Sesi dipakai ulang + idle | ADA | Benar | `vpnsession.go:540` `serve` `Hidden: true`; `root.go:146` `netx.ReapIdle()`; `meta.go:408` `vpn_idle` (default 30m di `config show`) |
| 5 | MFA oleh manusia | ADA | Benar | `netx/netx.go:75` dan `vpnsession.go:273` `VPN_LOGIN_REQUIRED`; `vpn.go:322` `--mfa` |
| 6 | Status VPN | SEBAGIAN | Benar | `vpnsession.go:501-510` `vpnStatusRow`: name, kind, up, since, last_used, socks, used_by; tidak ada handshake/byte/IP |
| 7 | Uji konektivitas lewat VPN | ADA | Benar | `netx/netx.go:361` dial `v.Check`; `everything.go:156` alias `ping` |
| 8 | Ubah VPN (`vpn edit`) | SEBAGIAN | Benar | `grep 'Use: *"edit' internal/cli`: hanya conn/host/key; `vpn.go:327` `--overwrite` |
| 9 | Bentrok rute mode OS | ADA | Benar | `netx/routes.go:108` `Clashes`; dipakai di `vpnsession.go:402` |
| 10 | Audit sambung/putus | ADA | Benar | `vpnsession.go:295` `vpn.up`, `vpnsession.go:492` `vpn.down` |
| 11 | `doctor` klien VPN | ADA | Benar | `meta.go:581-584` `vpnClients` + `installHint` (`vpnsession.go:83,100`) |
| 12 | Split DNS | SEBAGIAN | Benar | `netx/wireguard.go:93` "search domains are ignored"; `CreateNetTUN(..., c.DNS, ...)` `wireguard.go:225` |
| 13 | Kill switch | TIDAK ADA | Dikoreksi: NON-GOAL→TIDAK ADA (P3) | `vision.md:221-228` tidak menyebutnya; keputusan ada di `network.md:169` |
| 14 | VPN menu bar / GUI | NON-GOAL | Benar | `vision.md:227` N1 "GUI, TUI ... CLI murni" |
| 15 | Proxy HTTP(S) perusahaan | SEBAGIAN | Dikoreksi: TIDAK ADA→SEBAGIAN | `storex/storex.go:72` clone `http.DefaultTransport` (proxy env aktif); `kube/kube.go:236`, `registry/registry.go:43` tanpa `Proxy`; `grep ProxyFromEnvironment internal`: 0 hasil |
| 16 | Impor wg-quick, kunci ke vault | ADA | Benar | `vpn.go:199-207` `netx.StripWGKeys` → `secret:NAME-key`, `-psk` |
| 17 | WG tanpa root | ADA | Benar | `netx/wireguard.go:225` `netstack.CreateNetTUN` |
| 18 | MTU, alamat, PSK | ADA | Benar | `netx/wireguard.go:26-33` `DNS`, `MTU`, `PresharedKey`; `Addresses` slice |
| 19 | `PostUp`/`Table`/`ListenPort` | TIDAK ADA | Dikoreksi: NON-GOAL→TIDAK ADA (P3) | `netx/wireguard.go:119` diabaikan; `vision.md:221-228` tidak mengecualikannya |
| 20 | Buat kunci WG | TIDAK ADA | Benar | `grep -i 'genkey\|wgtypes' internal`: 0 hasil; `key gen` hanya SSH (`key.go:54,66`) |
| 21 | Statistik handshake WG | TIDAK ADA | Benar | `grep -i 'IpcGet\|rx_bytes' internal`: 0 hasil |
| 22 | Peringatan `.conf` berisi kunci | ADA | Benar | `vpn.go:298` "still holds the keys" |
| 23 | Profil `.ovpn` / Pritunl | ADA | Benar | `vpn.go:149-150` `pritunl` → `openvpn` |
| 24 | OpenVPN di container | ADA | Benar | `vpnsession.go:238` `openvpnContainer`; `vpnsession.go:104` hint Docker |
| 25 | OpenVPN mode OS sudo | ADA | Benar | `vpn.go:321` `--os-mode`; `vpnsession.go:251,258` `/var/run/komando-openvpn-*.pid`, `--syslog` |
| 26 | Filter direktif `.ovpn` | ADA | Benar | `vpn.go:55` `ovpnAllowed`, `vpn.go:77` `checkOVPN`, `vpn.go:115` inline-only |
| 27 | Static challenge OpenVPN | TIDAK ADA | Dikoreksi: SEBAGIAN→TIDAK ADA | `vpn.go:61` diizinkan; `ovpn/entrypoint.sh:13` `--daemon`; `vpnsession.go:258-264` `--daemon` + file auth; tidak ada stdin |
| 28 | OpenVPN 3 / DCO / SAML | TIDAK ADA | Benar | `grep -i 'openvpn3\|dco' internal`: 0 hasil |
| 29 | OpenVPN userspace (minivpn) | TIDAK ADA | Benar | `grep -i minivpn internal`: 0 hasil; hanya `network.md:105` |
| 30 | Keluarga openconnect | ADA | Benar | `netx/netx.go:51-55` protocol `gp`, `fortinet`, `anyconnect`, `pulse`, `f5`; `vpnsession.go:206` `ocproxy -D` |
| 31 | Protokol `nc`/`array` | TIDAK ADA | Benar | `netx/netx.go:46-56` tanpa `nc`/`array` |
| 32 | SAML/SSO openconnect | TIDAK ADA | Benar | `vpnsession.go:205-211` hanya `--user`, `--non-inter`, `--passwd-on-stdin`; `grep -i 'external-browser\|saml' internal`: 0 hasil |
| 33 | `--servercert` | TIDAK ADA | Benar | `grep -i servercert internal`: 0 hasil |
| 34 | `--authgroup`/`--usergroup` | TIDAK ADA | Benar | `grep -i 'authgroup\|usergroup' internal`: 0 hasil |
| 35 | Sertifikat klien openconnect | TIDAK ADA | Benar | `vpnsession.go:205-211` tanpa `-c`/`-k`; flag `vpn add` tidak punya cert |
| 36 | HIP report `--csd-wrapper` | TIDAK ADA | Benar | `grep -i csd internal`: 0 hasil (selain `nproc`) |
| 37 | `tunsocks` | TIDAK ADA | Benar | `grep -i tunsocks internal`: 0 hasil |
| 38 | Tailscale userspace | ADA | Benar | `vpnsession.go:167` `--tun=userspace-networking`; `vpn.go:229-231` tanpa key → `MFA` |
| 39 | Headscale | ADA | Benar | `vpnsession.go:188` `--login-server`; `vpn.go:318` `--server` |
| 40 | Daftar peer tailnet | SEBAGIAN | Benar | `grep 'tailscale.*status' internal`: 0 hasil; hanya `vpn status` |
| 41 | `tailscale ping` | TIDAK ADA | Benar | `grep '"ping"' internal/cli`: hanya alias `test` dan direktif ovpn |
| 42 | Exit node | TIDAK ADA | Benar | `grep -i exit-node internal`: 0 hasil |
| 43 | Tailscale SSH | SEBAGIAN | Benar | SOCKS tailnet `vpnsession.go:168`; tidak ada `tailscale ssh` |
| 44 | `serve`/`funnel` | NON-GOAL | Benar | `vision.md:227` N1 daemon/server (harus terus berjalan untuk mengekspos) |
| 45 | Taildrop | TIDAK ADA | Benar | `grep -i 'taildrop\|file cp' internal`: 0 hasil |
| 46 | Tag ACL / ephemeral | SEBAGIAN | Benar | `vpnsession.go:178-189` hanya `--auth-key`, `--login-server`, `--hostname`; `grep advertise-tags`: 0 hasil |
| 47 | ZeroTier | SEBAGIAN | Benar | `netx/netx.go:46-56` tanpa `zerotier`; `system` `netx.go:49` |
| 48 | Nebula, NetBird | SEBAGIAN | Benar | `grep -i 'nebula\|netbird' internal`: 0 hasil; hanya `system` |
| 49 | L2TP/IPsec/IKEv2 | ADA | Benar | `vpn.go:151-152` alias → `system`; `vpnsession.go:351,353` `scutil --nc` / `nmcli` |
| 50 | Cloudflare WARP | SEBAGIAN | Benar | `grep -i warp internal`: 0 hasil; `system` + `--check` |
| 51 | AWS SSM shell | TIDAK ADA | Benar | `grep -i ssm internal`: 0 hasil |
| 52 | AWS SSM port forward | TIDAK ADA | Benar | `grep -i ssm internal`: 0 hasil |
| 53 | `ProxyCommand` | TIDAK ADA | Benar | `host.go:547-559` hanya hostname/user/proxyjump/port/identityfile; `grep -i proxycommand internal`: 0 hasil; tidak ada catatan ke `Skipped` |
| 54 | GCP IAP | TIDAK ADA | Benar | `grep -i 'iap\|gcloud compute' internal`: 0 hasil |
| 55 | Azure Bastion | TIDAK ADA | Benar | `grep -i azure internal`: 0 hasil |
| 56 | Cloudflare Access | TIDAK ADA | Benar | `grep -i cloudflared internal`: 0 hasil |
| 57 | Cloudflare Tunnel | NON-GOAL | Benar | `vision.md:227` N1 daemon/server |
| 58 | Teleport | TIDAK ADA | Dikoreksi: bukti "lihat B5"→"lihat B3" | `grep -i 'teleport\|tsh' internal`: 0 hasil |
| 59 | Boundary | TIDAK ADA | Benar | `grep -i boundary internal`: 0 hasil |
| 60 | StrongDM | TIDAK ADA | Benar | `grep -i 'strongdm\|sdm' internal`: 0 hasil |
| 61 | `tunnel -L/-R/-D` | ADA | Benar | `tunnel.go:222-224` flag; `tunnel.go:260,305` list/stop |
| 62 | Tunnel ke conn | ADA | Benar | `tunnel.go:95-96` contoh `app-db --port`; `tunnel.go:225` |
| 63 | SOCKS di dalam VPN | ADA | Benar | `tunnel.go:136-137` nama VPN jadi `--via`; `docs/features/vpn.md:34` |
| 64 | Bind non-loopback tanpa `--yes` | SEBAGIAN | Benar | `tunnel.go:66,77` default `127.0.0.1`; `tunnel.go:68-69,78-79` bind bebas; `grep 'guardSafety\|g.yes' internal/cli/tunnel.go`: 0 hasil |
| 65 | Pakai SOCKS yang ada | ADA | Benar | `vpn.go:210-221` kind `socks` (`--address`, `--user` + `--password-ref`) |
| 66 | Bungkus aplikasi lewat proxy | SEBAGIAN | Benar | `tunnel -D` ada; `grep -i 'proxychains\|tsocks' internal`: 0 hasil |
| 67 | VPN-over-SSH subnet | SEBAGIAN | Benar | `grep -i sshuttle internal`: 0 hasil |
| 68 | Ekspos ke internet (ngrok) | NON-GOAL | Benar | `vision.md:227` N1 server |
| 69 | Port-forward k8s | SEBAGIAN | Benar | `cluster.go:863` port-forward = destructive; `cluster.go:1025` tidak bisa dry-run; `tunnel.go` tanpa k8s |
| 70 | Vault AES-GCM + scrypt | ADA | Benar | `vault/vault.go:134` scrypt, `:138-142` AES-GCM; mode keyfile/passphrase `:114-131` |
| 71 | Input secret tanpa argumen | ADA | Benar | `key.go:385` `SECRET_IN_ARGS`, `:390` `--from-env`, `:407` prompt TTY |
| 72 | `--reveal` hanya manusia | SEBAGIAN | Benar | `key.go:447-452` tanpa cek TTY/konfirmasi (hanya audit `secret.reveal`) |
| 73 | `secret rm` aman | SEBAGIAN | Benar | `key.go:471-494` tanpa `IN_USE`, tanpa konfirmasi, tanpa `audit(`; `vault.go:185` hapus permanen |
| 74 | `secret set` menimpa | SEBAGIAN | Benar | `vault.go:159` menimpa entri; `key.go:434` hanya flag `--from-env` |
| 75 | `vault.key` di keyring OS | TIDAK ADA | Benar | `vault.go:121-127` `vault.key` file 0600; `grep -i 'keyring\|secret-tool' internal`: 0 hasil |
| 76 | Re-key vault | TIDAK ADA | Benar | `secret --help`: get/list/rm/set saja; `grep -i rekey internal`: 0 hasil |
| 77 | Kunci/buka vault | TIDAK ADA | Benar | `grep -i unlock internal`: 0 hasil |
| 78 | Riwayat versi secret | TIDAK ADA | Benar | `vault.go:159` satu entri per nama + `UpdatedAt` |
| 79 | Generate password | TIDAK ADA | Benar | `secret --help`: tidak ada `generate` |
| 80 | Rename/copy secret | TIDAK ADA | Benar | `secret --help`: tidak ada `mv`/`cp` |
| 81 | Siapa memakai secret | TIDAK ADA | Benar | `vault.go:40-43` `Info{name, updated_at}` |
| 82 | Rotasi secret | TIDAK ADA | Benar | `grep -i rotate internal`: 0 hasil |
| 83 | Izin file `file:` | TIDAK ADA | Benar | `vault.go:263-265` `os.ReadFile` tanpa `Stat`/mode |
| 84 | `env:`, `file:` | ADA | Benar | `vault.go:256-265` |
| 85 | 1Password `op read` | ADA | Benar | `vault.go:265-266` |
| 86 | `op run`/`op inject` | TIDAK ADA | Benar | `grep '"op", "run"\|inject' internal`: 0 hasil |
| 87 | Vault KV | ADA | Benar | `vault.go:267-272` `vault kv get -field` |
| 88 | Vault dynamic creds | TIDAK ADA | Benar | `vault.go:267-272` hanya `kv get`; `grep -i lease internal`: 0 hasil |
| 89 | Vault SSH CA | TIDAK ADA | Dikoreksi: bukti "lihat B5"→"lihat B3" | `grep -i 'ssh/sign' internal`: 0 hasil |
| 90 | AWS Secrets Manager | ADA | Benar | `vault.go:273-279` |
| 91 | SSM Parameter Store | TIDAK ADA | Benar | `vault.go:227` prefiks: secret/env/file/op/vault/aws-sm/gcp-sm; `grep get-parameter internal`: 0 hasil |
| 92 | Google Secret Manager | ADA | Benar | `vault.go:280-286` selalu `latest` |
| 93 | Azure Key Vault | TIDAK ADA | Benar | `grep -i 'keyvault\|azure' internal`: 0 hasil |
| 94 | Bitwarden | TIDAK ADA | Benar | `grep -i 'bitwarden\|"bw"' internal`: 0 hasil |
| 95 | `pass`/`gopass` | TIDAK ADA | Benar | `vault.go:227` tanpa prefiks `pass:` |
| 96 | sops | TIDAK ADA | Benar | `grep -i sops internal`: 0 hasil |
| 97 | age | TIDAK ADA | Benar | `vault.go:227` tanpa prefiks `age:` |
| 98 | Doppler, Infisical | TIDAK ADA | Benar | `grep -i 'doppler\|infisical' internal`: 0 hasil |
| 99 | Profil AWS | SEBAGIAN | Benar | `vault.go:299` `exec.CommandContext` mewarisi env (`AWS_PROFILE`); tidak ada profil per ref |
| 100 | K8s Secret sebagai sumber | TIDAK ADA | Benar | `cluster.go:325-328` `redact`; `vault.go:227` tanpa `k8s:` |
| 101 | MFA eksternal milik manusia | ADA | Benar | `vault.go:293-308` `external()`, "(is it signed in?)" |
| 102 | Cache ref eksternal | SEBAGIAN | Benar | `vault.go:297` timeout 60s per panggilan; `grep -i cache internal/vault`: 0 hasil |
| 103 | Kunci SSH gen/add/deploy | ADA | Benar | `key.go:37,116,170,196,227,248,283` gen/add/edit/list/show/rm/deploy |
| 104 | Passphrase dari vault | ADA | Benar | `key.go:163` `--passphrase-ref`; `sshx/client.go:285` |
| 105 | ssh-agent | ADA | Benar | `sshx/client.go:320-322` `SSH_AUTH_SOCK` + `agent.NewClient` |
| 106 | Sertifikat SSH dari file | TIDAK ADA | Benar | `sshx/client.go:276,289` hanya `ParsePrivateKey`; `grep NewCertSigner internal`: 0 hasil |
| 107 | `IdentityAgent` per host | TIDAK ADA | Benar | `grep -i identityagent internal`: 0 hasil |
| 108 | Rotasi kunci SSH | SEBAGIAN | Benar | `key.go:308-309` hanya menambah ke `authorized_keys`; tidak ada penghapusan |
| 109 | Secret di `--env` remote | TIDAK ADA | Benar | `common.go:475-481` `parseEnv` tanpa `vault.Resolve`; `exec.go:76,205`, `job.go:76,146`, `host.go:65,71` |
| 110 | Alat lokal dengan secret | SEBAGIAN | Benar | `dbshell.go:151` `PGPASSWORD`, `:193` `MYSQL_PWD`; tidak ada pembungkus umum |
| 111 | Muat `.env` | SEBAGIAN | Benar | `importer.go:499` `importEnv` hanya membuat conn |
| 112 | Template secret di `fs write` | TIDAK ADA | Benar | `fs.go:547-548` `--content`/`--from` literal; `grep '{{secret' internal`: 0 hasil |
| 113 | `host --env` polos | SEBAGIAN | Benar | `store/store.go:31` `Env map[string]string` di `state.json` |
| 114 | Berbagi vault tim | SEBAGIAN | Benar | `vault.go:30` vault lokal satu kunci; ref eksternal `vault.go:219-222` |
| 115 | Export terenkripsi + secret | TIDAK ADA | Benar | `importer.go:616` `export` "(no passwords)"; `vision.md:158` |
| 116 | SSO/OIDC ke komando | NON-GOAL | Benar | `vision.md:227` N1 (butuh server) |
| 117 | `config show/set` | ADA | Benar | `meta.go:341-343,358` (host_key_policy, default_user, timeouts, parallel, max_output_bytes, audit, audit_sql, vpn_idle) |
| 118 | Pengaman setting keamanan | ADA | Benar | `common.go:324-328` `guardSafety` → `SAFETY_SETTING`; `meta.go:371,403` |
| 119 | Profil/konteks | SEBAGIAN | Benar | `root.go` tanpa flag `--home`; hanya env `KOMANDO_HOME` |
| 120 | Override setting via env | SEBAGIAN | Benar | `grep KOMANDO_ internal`: HOME, OUTPUT, ACTOR, VAULT_PASS (+SOCKS_* internal) |
| 121 | Konfigurasi per proyek | TIDAK ADA | Benar | tidak ada pembacaan file konfigurasi proyek di `root.go`/`store` |
| 122 | JSON envelope + exit code | ADA | Benar | `out/out.go:16-26` exit code, `:65-72` `contract` |
| 123 | Auto text/JSON | ADA | Benar | `root.go:60,134,159` `outputFormat`, `KOMANDO_OUTPUT` |
| 124 | `--pretty` | ADA | Benar | `root.go:160` |
| 125 | NDJSON streaming | ADA | Benar | `exec.go:80` `--stream`; `modules.go:785-789` `followLogs` memakai `stream: true`; `out.go:167` `Event` |
| 126 | YAML | TIDAK ADA | Benar | `out/out.go:89` "yaml-ish not supported" |
| 127 | CSV/TSV | TIDAK ADA | Benar | `grep -i 'csv\|tsv' internal/out`: 0 hasil |
| 128 | Filter jq/JMESPath | TIDAK ADA | Benar | `grep '"query"\|"jq"' internal/cli/root.go`: 0 hasil |
| 129 | Template output | TIDAK ADA | Benar | tidak ada flag `--template`/`--format` global (`root.go:159-168`) |
| 130 | Pilih kolom | TIDAK ADA | Benar | `grep '"fields"\|"columns"' internal/cli`: 0 hasil |
| 131 | `--no-headers` | TIDAK ADA | Benar | `grep no-headers internal`: 0 hasil |
| 132 | Warna / `NO_COLOR` | ADA | Benar | `grep '\x1b\[\|NO_COLOR' internal`: 0 hasil (tanpa warna) |
| 133 | Output terpotong | ADA | Benar | `root.go:168` `--max-output`; `sshx/run.go:38-39` `*_truncated` |
| 134 | Pagination | SEBAGIAN | Benar | `storage ls --help` hanya `-n/--limit`; tidak ada token lanjutan |
| 135 | `--quiet` | TIDAK ADA | Benar | `grep '"quiet"' internal`: 0 hasil |
| 136 | `--watch` | TIDAK ADA | Benar | `grep '"watch"' internal/cli`: 0 hasil; `job wait`, `logs -f` ada |
| 137 | `--help` dengan contoh | ADA | Dikoreksi: bukti (`TestConventions` tidak memeriksa contoh) | 66 `Example:` dari ±155 `Use:` di `internal/cli`; `conventions_test.go:13-43` tanpa cek Example |
| 138 | Did you mean | ADA | Benar | cobra (`komando lst` → saran `list`); `select.go:76-77,250-251` untuk selector |
| 139 | Tanpa argumen: tiga langkah | SEBAGIAN | Benar | `komando` tanpa argumen mencetak Long help `root.go:111` |
| 140 | Completion statis | ADA | Benar | `completion --help`: bash, fish, powershell, zsh |
| 141 | Completion dinamis | TIDAK ADA | Benar | `grep 'ValidArgsFunction\|RegisterFlagCompletionFunc' internal`: 0 hasil; `__complete exec ""` kosong |
| 142 | Man page | TIDAK ADA | Benar | `grep 'GenMan\|cobra/doc' internal Makefile`: 0 hasil |
| 143 | Dokumen offline | ADA | Benar | `meta.go:37` `guide`, `meta.go:179` `schema`; `docs/features/` |
| 144 | i18n | SEBAGIAN | Benar | `README.id.md`, `docs/features/id/` (19 file); pesan CLI Inggris |
| 145 | Positioning root help | SEBAGIAN | Benar | `root.go:110-112` "servers (SSH), databases, caches and storage" |
| 146 | `--verbose`/`--debug` | TIDAK ADA | Benar | `grep '"verbose"\|"debug"' internal/cli/root.go`: 0 hasil; `-v` = `--version` |
| 147 | `doctor` | ADA | Benar | `meta.go:547-587` state, hosts, keys, ssh_agent, klien VPN, platform |
| 148 | `doctor` cek ref eksternal | TIDAK ADA | Benar | `meta.go:547-587` tanpa cek `op`/`vault`/`aws`/`gcloud` |
| 149 | Log VPN per sesi | ADA | Benar | `vpnsession.go:137` `logFile` |
| 150 | Install + checksum | ADA | Benar | `install.sh:31-36` unduh dan cek `checksums.txt` |
| 151 | `go install` | ADA | Benar | `README.md:47` |
| 152 | Homebrew | TIDAK ADA | Benar | `git ls-files \| grep -i 'brew\|formula'`: 0 hasil |
| 153 | apt/rpm | TIDAK ADA | Benar | `Makefile:35-44` hanya tar.gz |
| 154 | Scoop/winget | TIDAK ADA | Benar | `git ls-files \| grep -i 'scoop\|winget'`: 0 hasil |
| 155 | Docker image komando | TIDAK ADA | Benar | Dockerfile hanya `internal/cli/ovpn/` dan `test/e2e/` |
| 156 | Nix | TIDAK ADA | Benar | `git ls-files \| grep -i nix`: 0 hasil |
| 157 | Windows native | TIDAK ADA | Benar | `Makefile:6` PLATFORMS linux/darwin; `install.sh:15` menolak; `vpnsession.go:308` `Setsid` |
| 158 | Rilis bertanda tangan | SEBAGIAN | Benar | `.github/workflows/release.yml` hanya `make dist` + `gh release create`; `grep -i 'cosign\|attest\|sbom' .github`: 0 hasil |
| 159 | Cek versi / self-update | TIDAK ADA | Benar | `root.go:200-206` `version` hanya cetak; `grep api.github.com internal`: 0 hasil |
| 160 | Telemetri | SEBAGIAN | Benar | `grep -ri telemetr README* SECURITY.md docs` (di luar gap): 0 hasil |
| 161 | Biner pure Go (tanpa batas ukuran) | ADA | Benar (bukti ditambah ukuran terukur) | `Makefile:40` `CGO_ENABLED=0 ... -trimpath`; build `-s -w`: 35 MB darwin/arm64, 37 MB linux/amd64 |
| 162 | Selector universal | ADA | Benar | `select.go:98-99` `!`, `:125` `kind:`, `:210-214` `@`, `tag:`, `label:`, `:224` glob |
| 163 | Import dari alat lain | ADA | Dikoreksi: bukti (pipe di dalam backtick merusak tabel) | `importer.go:49` daftar sumber; `import --help` 10 sumber |
| 164 | Import aws/Termius/TablePlus | SEBAGIAN | Benar | `import --help` tanpa aws/termius/tableplus; `vision.md:166,170` |
| 165 | Export/import pindah mesin | ADA | Benar | `importer.go:616` `export [TARGET] --to`; sumber `komando` |
| 166 | Sinkron otomatis | NON-GOAL | Benar | `vision.md:227` N1 daemon/server |
| 167 | Inventaris tim | SEBAGIAN | Dikoreksi: bukti (`--overwrite` menerapkan perubahan) | `importer.go:142-196` skip nama yang ada kecuali `--overwrite` |
| 168 | Inventaris dinamis cloud | TIDAK ADA | Benar | `grep -i 'ec2\|droplet\|hetzner' internal`: 0 hasil; `vision.md:206-208` |
| 169 | Ringkasan kesehatan | SEBAGIAN | Benar | `ops.go:106` recipe `health`, `ops.go:80` `facts`, `cluster.go:207` `status` |
| 170 | Biaya/penggunaan | TIDAK ADA | Dikoreksi: NON-GOAL→TIDAK ADA (P3) | `vision.md:226` N2 hanya IaC/provisioning/GitOps |
| 171 | `--dry-run` global | ADA | Benar | `root.go:161`; `internal/cli/dryrun_test.go` |
| 172 | Protected + konfirmasi | ADA | Benar | `common.go:307` `confirmProtected`, `:346` "Type ... to continue" |
| 173 | Policy + `--allow-dangerous` | ADA | Benar | `meta.go:442` `policy` (allow/check/deny/list); `root.go:163` |
| 174 | Approval dua orang / RBAC | NON-GOAL | Benar | `vision.md:227` N1 (butuh server) |
| 175 | Audit log lokal | ADA | Dikoreksi: bukti (`via` tidak dicatat) | `common.go:374-389` field rekaman; `meta.go:331-334` filter |
| 176 | Audit gagal tertutup | SEBAGIAN | Benar | `common.go:391-396` `return` saat gagal buka, hasil `f.Write` diabaikan |
| 177 | Filter audit waktu/actor | TIDAK ADA | Benar | `meta.go:331-334` hanya target/command/failed (+limit) |
| 178 | Audit ke SIEM | TIDAK ADA | Benar | `common.go:391` hanya `audit.jsonl` |
| 179 | Rotasi file audit | TIDAK ADA | Benar | `meta.go:295` `bufio.Scanner` membaca seluruh file; tidak ada rotasi |
| 180 | Notifikasi | TIDAK ADA | Benar | `grep -i 'webhook\|slack' internal`: 0 hasil |
| 181 | Penjadwalan | ADA | Dikoreksi: SEBAGIAN→ADA | `modules.go:716,754` `cron set/list/rm`; sisi lokal N1 `vision.md:227` |
| 182 | Skill agent | ADA | Benar | `meta.go:61` `.claude/skills`, `.agents/skills`; `meta.go:105` `--project` |
| 183 | Playbook agent | ADA | Benar | `meta.go:37` `guide`; `internal/cli/guide.md` |
| 184 | Skema mesin | SEBAGIAN | Dikoreksi: bukti (baris `meta.go:244-254`→`243-253`) | `meta.go:243-253` selektor "hosts" tanpa `kind:`; `secret_refs` tanpa op/vault/aws-sm/gcp-sm |
| 185 | Skema bentuk `data` | TIDAK ADA | Benar | `meta.go:179` `schema` hanya perintah/flag/envelope |
| 186 | MCP server | TIDAK ADA | Benar | `grep -i mcp internal cmd`: 0 hasil |
| 187 | Actor otomatis agent | SEBAGIAN | Benar | `common.go:399-404` `KOMANDO_ACTOR`, jika kosong `$USER` |
| 188 | Agent tidak bisa menjawab prompt | ADA | Dikoreksi: bukti (stdin TTY, bukan /dev/tty) | `common.go:295` `interactive()`, `:301` baca `os.Stdin`, `:314` `confirmYes` |
| 189 | Idempotensi | ADA | Benar | `fs.go:550` `--if-changed`; `key.go:308-309` deploy; `modules.go:754` cron set |
| 190 | Paralel dibatasi | ADA | Benar | `root.go:166` `-P/--parallel`; `exec.go:81` `--fail-fast` |
| 191 | Retry/backoff | TIDAK ADA | Benar | `storex/storex.go:67` `MaxRetry = 2`; `registry/registry.go:105` retry token; tanpa backoff |
| 192 | Rate limit | TIDAK ADA | Benar | `grep -i 'rate.Limit\|ratelimit' internal`: 0 hasil |
| 193 | Ctrl-C bersih | SEBAGIAN | Dikoreksi: ADA→SEBAGIAN (P3) | `root.go:64` `NotifyContext`; `common.go:122-123` `CANCELLED` exit 1; `grep 130 internal/cli`: 0 hasil |
| 194 | Job terlepas | ADA | Benar | `job.go:35` job start/status/logs/wait/kill/rm/list |
| 195 | State aman bersamaan | ADA | Benar | `store/store.go:297-316` `Update` + `syscall.Flock` |
| 196 | Fuzzy picker | NON-GOAL | Benar | `vision.md:227` N1 "TUI" |
| 197 | Alias perintah pengguna | SEBAGIAN | Benar | `ops.go:214,263` `recipe add NAME COMMAND`; tidak ada alias perintah komando |
