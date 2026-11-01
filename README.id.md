# komando

**"Remote control" berbasis command line untuk server Anda, dibuat khusus untuk AI agent.**

🇬🇧 [Read in English](README.md)

---

## Ini apa, dalam bahasa sederhana?

Bayangkan Anda punya beberapa komputer di cloud ("server") yang menjalankan
website, database, atau aplikasi Anda. Biasanya, untuk merawatnya, seseorang
membuka aplikasi seperti **Termius** atau **PuTTY**, login ke tiap server, lalu
mengetik perintah satu per satu.

**komando** mengerjakan hal yang sama, tetapi dirancang agar **asisten AI**
(seperti Claude Code, Codex, atau bot buatan Anda) bisa melakukannya untuk Anda
— dengan aman:

- 📒 **Mengingat semua server Anda** — seperti buku kontak di HP, tapi untuk server.
- 🔑 **Menyimpan password dan kunci di brankas terenkripsi.** AI hanya melihat
  *nama*-nya, misalnya `secret:db-password`, tidak pernah isi password-nya.
- 🧾 **Setiap jawaban terstruktur** (JSON), jadi AI paham persis apa yang
  terjadi, bukan menebak-nebak dari teks yang berantakan.
- 🛑 **Punya "sabuk pengaman".** Perintah berbahaya (menghapus disk, reboot,
  menghapus database) diblokir kecuali manusia mengizinkan secara eksplisit.
  Server produksi bisa ditandai *protected* (dilindungi).
- 📜 **Mencatat buku harian.** Semua aksi dicatat, sehingga Anda bisa melihat
  apa yang dilakukan AI, di server mana, dan berhasil atau tidak.

Semuanya **100% command line** — tanpa jendela, tanpa menu, tanpa layar
interaktif. Itulah yang dibutuhkan AI agent.

```
 Anda ──minta──▶ AI agent ──menjalankan──▶ komando ──SSH──▶ server Anda
                     ▲                        │
                     └────── hasil JSON ◀─────┘
```

## Bisa apa saja?

| Bidang | Perintah | Contoh |
|--------|----------|--------|
| Daftar server (inventory) | `host`, `group` | tambah server, impor dari `~/.ssh/config`, tes koneksi |
| Kunci & password | `key`, `secret` | buat SSH key, pasang ke server, brankas terenkripsi |
| Jalankan perintah | `exec`, `script` | di satu server atau 100 server sekaligus (paralel) |
| Tugas lama | `job` | mulai backup, cek hasilnya nanti |
| File | `fs`, `cp` | baca/ubah konfigurasi dengan aman, upload/download |
| Tunnel | `tunnel` | akses database privat lewat server gateway |
| Cek kesehatan | `facts`, `ops` | 39 resep siap pakai: disk, memori, port, sertifikat, update… |
| Service | `svc`, `logs` | start/stop/restart, baca log |
| Docker | `docker` | container, log, compose |
| Paket | `pkg` | install/upgrade di Linux apa pun (apt, dnf, yum, apk, zypper, pacman) |
| Jaringan | `net` | "apakah server ini bisa menjangkau database?", cek HTTP, port terbuka |
| User & cron | `user`, `cron` | buat akun, jadwalkan tugas |
| Untuk AI | `guide`, `schema`, `audit`, `policy` | petunjuk kerja, referensi lengkap, riwayat |

## Instalasi

Butuh [Go](https://go.dev/dl/) versi 1.26 atau lebih baru.

```bash
go install github.com/sgnd/komando/cmd/komando@latest
```

Atau build dari folder ini:

```bash
make build        # hasilnya ./bin/komando
```

Cek apakah sudah jalan:

```bash
komando version
```

## Mulai dalam 5 menit

**1. Tambahkan server.** Ganti dengan user dan alamat server Anda.

```bash
komando host add web1 ubuntu@203.0.113.10 --group web
```

Sudah punya `~/.ssh/config`? Impor semuanya sekaligus:

```bash
komando host import --ssh-config ~/.ssh/config
```

**2. Beri tahu cara login.** Jika Anda biasa login dengan SSH key, langsung
jalan (komando membaca `~/.ssh/id_ed25519` dan ssh-agent Anda). Jika memakai
password, simpan dulu di brankas — setelah itu tidak akan pernah ditampilkan lagi:

```bash
echo -n 'password-saya' | komando secret set web1-pass
komando host edit web1 --password-ref secret:web1-pass
```

Lebih baik lagi: buat kunci dan pasang ke server, supaya tidak perlu password:

```bash
komando key gen deploy
komando key deploy deploy web1 --set-default
```

**3. Tes koneksi.**

```bash
komando host test web1
```

**4. Coba tanya sesuatu.**

```bash
komando facts web1                 # OS apa, memori/disk berapa, tool apa saja
komando ops run health web1        # cek kesehatan cepat
komando exec web1 -- uptime        # perintah apa pun
```

Lebih suka teks biasa daripada JSON? Tambahkan `-o text`:

```bash
komando -o text exec web1 -- df -h
```

**5. Tandai server produksi sebagai protected.**

```bash
komando host edit web1 --protected
```

Sekarang setiap aksi yang *mengubah* sesuatu di `web1` wajib memakai `--yes`.

## Menghubungkan AI agent Anda

Beri tahu agent untuk memakai komando. Untuk Claude Code, Codex, dan
kebanyakan agent, salin [`AGENTS.md`](AGENTS.md) ke project Anda (atau tempel
ke instruksi agent). Versi singkatnya:

> Gunakan CLI `komando` untuk mengelola server. Jalankan `komando guide` dulu
> dan ikuti petunjuknya. Jangan pernah memakai `--allow-dangerous` atau `--yes`
> tanpa bertanya kepada saya.

Agent bisa belajar sendiri:

```bash
komando guide            # cara kerja yang aman (langkah demi langkah)
komando schema           # semua perintah dan opsi, dalam format mesin
```

Beri nama agar riwayat mencatat siapa melakukan apa:

```bash
export KOMANDO_ACTOR=claude
komando audit            # lihat aksi terakhir
```

## Contoh sehari-hari

```bash
# Server mana yang disknya hampir penuh?
komando ops run disk @web

# Kenapa website lambat? Lihat error 30 menit terakhir
komando logs web1 --unit nginx --since -30m --grep 'error|crit'

# Ubah satu baris konfigurasi, simpan backup, lalu reload
komando fs replace web1 /etc/nginx/nginx.conf \
  --old 'worker_connections 768;' --new 'worker_connections 4096;' --sudo --backup
komando ops run nginx-test web1
komando svc reload web1 nginx

# Upload file ke semua web server
komando cp ./release.tar.gz @web:/tmp/

# Mulai backup yang lama, cek nanti
komando job start db1 -- 'pg_dump app | gzip > /backup/app.sql.gz'
komando job wait <job-id>

# Akses database privat lewat gateway ("bastion")
komando host add db1 admin@10.0.0.5 --jump bastion
komando tunnel start db1 -L 15432:localhost:5432
# sekarang hubungkan aplikasi database Anda ke localhost:15432

# Kapan sertifikat HTTPS kedaluwarsa?
komando ops run cert-expiry web1 --param name=example.com
```

## Memilih server ("target")

Kebanyakan perintah butuh *target* — server mana yang mau dikerjakan:

| Anda menulis | Artinya |
|--------------|---------|
| `web1` | server bernama web1 |
| `web-*` | semua server yang namanya diawali `web-` |
| `@web` | semua server di grup `web` |
| `tag:prod` | semua server dengan tag `prod` |
| `label:dc=jkt` | semua server dengan label `dc=jkt` |
| `all` | semua server |
| `@web,!web3` | grup web kecuali web3 |
| `root@1.2.3.4:22` | server sekali pakai yang tidak ada di daftar |

## Bagaimana komando menjaga keamanan

| Sabuk pengaman | Yang terjadi |
|----------------|--------------|
| Filter perintah berbahaya | `rm -rf /`, `mkfs`, `reboot`, `DROP DATABASE`, `curl … \| sh`, hapus firewall, mematikan SSH, dan lainnya diblokir (exit code 6). Lihat `komando policy list`. |
| Server protected | Mengubah apa pun wajib `--yes`. Membaca selalu boleh dengan `--read-only`. |
| Dry run | `--dry-run` menampilkan persis apa yang *akan* dijalankan, dan apakah akan diblokir. |
| Edit aman | `fs replace` hanya mengubah jika teks lama muncul tepat satu kali; penulisan atomik; `--backup` menyimpan file lama. |
| Brankas terenkripsi | Password dienkripsi (AES-256-GCM). AI hanya melihat referensi, bukan isinya. |
| Cek identitas server | Koneksi pertama mengingat "sidik jari" server. Jika berubah (kemungkinan serangan), komando menolak terhubung (`HOSTKEY_MISMATCH`). |
| Log audit | Setiap aksi ditulis ke `~/.komando/audit.jsonl`. |

> Filter ini menangkap kecelakaan umum; **bukan** batas keamanan yang sempurna.
> Berikan agent user SSH yang hanya punya izin yang benar-benar dibutuhkan.

## Memahami hasil

Setiap perintah mencetak satu objek JSON:

```json
{
  "ok": false,
  "command": "exec",
  "data": { "results": [ { "host": "web1", "ok": false, "exit_code": 3, "stdout": "…", "stderr": "…" } ] },
  "error": { "code": "FAILED", "message": "host web1 failed", "hint": "inspect per-host results in data.results" },
  "meta": { "version": "0.1.0", "duration_ms": 211 }
}
```

- `ok` — apakah semuanya berhasil?
- `data` — jawaban sebenarnya.
- `error.hint` — **langkah selanjutnya yang disarankan**. Selalu baca ini.

Exit code: `0` sukses · `1` error · `2` salah pemakaian · `3` tidak ditemukan ·
`4` gagal konek/login · `5` perintah gagal di server · `6` diblokir demi
keamanan · `7` timeout · `8` syarat edit tidak terpenuhi.

## Kamus istilah (untuk pemula)

| Istilah | Arti |
|---------|------|
| **Server** | Komputer, biasanya di data center atau cloud, yang menjalankan aplikasi Anda. |
| **SSH** | Protokol "remote control" yang aman untuk login ke server Linux. |
| **CLI** | Command-line interface: mengetik perintah, bukan klik-klik. |
| **AI agent** | AI yang bisa menjalankan tool/perintah sendiri untuk menyelesaikan tugas. |
| **Inventory** | Daftar server Anda dan cara menjangkaunya. |
| **SSH key** | Sepasang file sebagai bukti identitas, lebih aman dari password. Bagian *private* tetap di Anda; bagian *public* dipasang di server. |
| **Vault / secret** | Penyimpanan terenkripsi untuk password. |
| **sudo** | Menjalankan perintah sebagai administrator (root). |
| **Jump host / bastion** | Server gerbang yang dilewati untuk menjangkau server privat. |
| **Tunnel / port forwarding** | Membuat layanan di server (mis. database) seolah-olah ada di komputer Anda. |
| **SOCKS proxy** | Tunnel untuk banyak tujuan sekaligus (`tunnel -D`). |
| **Host key / fingerprint** | "KTP" server. Jika berubah tiba-tiba = tanda bahaya. |
| **systemd / service** | Cara Linux menjalankan dan menjaga program latar belakang (nginx, database…). |
| **Job** | Tugas panjang yang dibiarkan berjalan di server sementara Anda mengerjakan hal lain. |
| **Exit code** | Angka hasil sebuah program: 0 = sukses, selain itu = ada masalah. |
| **JSON** | Format teks terstruktur yang mudah dibaca program (dan AI). |
| **Idempotent** | Aman dijalankan dua kali: jalankan kedua tidak mengubah apa-apa lagi. |

## Mengatasi masalah

| Kode error | Biasanya berarti | Coba |
|------------|------------------|------|
| `AUTH_FAILED` | user, kunci, atau password salah | `komando host show NAMA`, `komando key deploy` |
| `CONNECTION_REFUSED` / `CONNECT_TIMEOUT` | server mati, port salah, firewall | cek alamat/port, `--connect-timeout 30s` |
| `HOSTKEY_MISMATCH` | server di-install ulang — atau ada yang menyadap | pastikan ke penyedia server, lalu `komando host trust NAMA --reset` |
| `SECRET_UNRESOLVED` | password/env var yang dirujuk tidak ada | `komando secret list` |
| `sudo: a password is required` | sudo butuh password | `komando host edit NAMA --sudo-ref secret:NAMA` |
| `POLICY_BLOCKED` | terlihat merusak | periksa ulang, lalu (manusia) `--allow-dangerous` |

Jalankan `komando doctor` untuk mengecek setup lokal Anda.

## Data disimpan di mana?

Semuanya ada di `~/.komando/` (bisa diubah dengan `KOMANDO_HOME`):
`state.json` (server, kunci, pengaturan), `vault.json` + `vault.key` (secret
terenkripsi), `keys/` (SSH key yang dibuat), `known_hosts`, `audit.jsonl`.
Backup folder ini dan jaga kerahasiaannya.

## Struktur project (untuk kontributor)

```
cmd/komando/        titik masuk program
internal/cli/       semua perintah (satu file per bidang: host.go, exec.go, fs.go, …)
internal/sshx/      koneksi SSH, jump host, autentikasi, menjalankan perintah
internal/store/     menyimpan state ke ~/.komando
internal/vault/     secret terenkripsi
internal/policy/    aturan perintah berbahaya
internal/out/       format JSON dan exit code
test/e2e/           uji end-to-end nyata memakai server SSH di Docker
```

Lihat [CONTRIBUTING.md](CONTRIBUTING.md). Test: `make test` (cepat) dan
`make e2e` (butuh Docker).

## Lisensi

[MIT](LICENSE)
