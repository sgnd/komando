# Keamanan

Sabuk pengaman, dan apa yang harus dilakukan saat salah satunya menghentikan Anda. [Semua fitur](README.md) · [Standar keamanan](security-standards.md)

| Sabuk pengaman | Fungsinya |
|----------------|-----------|
| Filter perintah berbahaya | Memblokir `rm -rf /`, `mkfs`, `reboot`, `DROP DATABASE`, `curl … \| sh` *di server Anda*, menghapus semua aturan firewall, mematikan SSH, dan lainnya. Lihat `komando policy list`. |
| Server dan conn protected | Perubahan butuh `--yes`. Perintah yang hanya melihat (tidak mengubah) bisa menyatakannya dengan `--read-only` dan jalan tanpa `--yes`. Menghapus yang protected, menggantinya, atau mematikan perlindungannya juga butuh `--yes`. Apa pun di alamat yang sama (target `user@address`, nama kedua, conn kedua ke server database yang sama) ikut terlindungi. |
| Pengaturan keamanan | Mematikan log audit atau pengecekan identitas server, atau menghapus aturan deny, butuh `--yes`. |
| Bertanya ke manusia | Saat Anda sendiri mengetik perintah di terminal, komando bertanya alih-alih gagal: `[y/N]` untuk target protected, dan mengetik nama target untuk perintah berbahaya. Agent dan skrip tidak pernah melihat pertanyaan ini; mereka butuh flag-nya. |
| Manusia yang mengizinkan permintaan AI agent | Saat AI agent (Claude Code, Codex, Gemini CLI, Cursor) menambahkan `--yes`, `--allow-dangerous` atau `--reveal`, komando membuka jendela di layar Anda yang menampilkan perintahnya persis; perintah baru jalan kalau Anda klik **Allow once**. Agent tidak bisa mengkliknya. Kalau tidak ada layar (sesi SSH, server), agent ditolak dan meminta Anda menjalankan perintahnya sendiri di terminal. Skrip memakai flag seperti biasa. |
| Secret disembunyikan dari AI agent | Untuk AI agent, password, key dan token di output apa pun (file `.env`, `env`, baris log, baris database, Kubernetes Secret, private key, hash password) tampil sebagai `[hidden]`. Anda dan skrip Anda melihat nilai aslinya. Agent tetap bisa mengisinya: `fs replace --old 'DB_PASSWORD=[hidden]' --new 'DB_PASSWORD={{secret:db}}'` menaruh nilai dari vault di server tanpa agent melihatnya. Teks yang masih berisi `[hidden]` tidak pernah ditulis menimpa file asli. |
| File rahasia tetap di server | AI agent tidak bisa menyalin file yang dari namanya adalah rahasia (`.env`, private key, `credentials`, `shadow`, ...) ke komputer ini; salinan folder melewatinya. Agent membacanya dengan `fs cat`, tersamar. |
| Penjaga di komputer ini | `komando guide install` memasang penjaga di Claude Code: sebelum Claude membaca file atau menjalankan perintah shell, komando memeriksanya dan menghentikan pembacaan `~/.komando`, private key, file `.env`, penyimpanan kredensial (`~/.kube`, `~/.aws/credentials`, keychain), daftar semua environment variable, dan `ssh`/`scp` yang melewati komando. Lewati dengan `--no-guard`. |
| Dry run | `--dry-run` menampilkan apa yang akan dijalankan dan apakah akan diblokir. |
| Edit yang aman | Penulisan atomik, ganti hanya jika teksnya cocok persis, backup `.bak` opsional. |
| Vault terenkripsi | Password dienkripsi dengan AES-256-GCM. Yang pernah ditampilkan hanya namanya, dan hanya orang di terminal yang bisa melihat nilainya (`secret get --reveal`). |
| Disembunyikan di output | Kalau secret dari vault muncul di kiriman server (file `.env`, baris log, `env`), komando menampilkan `[secret:NAME]`, juga saat nilainya di-encode base64 atau URL. Nilai yang lebih pendek dari 6 karakter tidak disembunyikan. |
| Identitas server | Fingerprint server yang berubah menghentikan koneksi (`HOSTKEY_MISMATCH`). |
| Riwayat | Semua tindakan tercatat di `komando audit`, termasuk AI agent yang meminta dan apakah manusia mengizinkannya. Tiap catatan membawa hash catatan sebelumnya, jadi `komando audit verify` (dan `doctor`) mengetahui catatan yang diubah, ditambah, atau dihapus. Kalau log audit tidak bisa ditulis, komando menolak berjalan (`AUDIT_UNAVAILABLE`); `komando doctor` menunjukkan sebabnya. |

Menembus blokir butuh `--allow-dangerous` — itu keputusan manusia.
Secret tidak pernah diterima sebagai argumen perintah (nanti tersimpan di
riwayat shell Anda): `komando secret set NAME` menanyakan nilainya, atau pakai
`--from-env VAR` atau pipe.
Tambahkan aturan Anda sendiri dengan `komando policy deny 'REGEX'`.

## Yang tidak dihentikan

komando mengenali AI agent dari variabel yang dipasang agent di shell-nya, dan
agent berjalan sebagai user Anda sendiri di komputer Anda. Jendela izin,
penyamaran dan penjaga menghentikan kesalahan dan prompt injection (halaman
web atau file yang menyuruh agent membocorkan sesuatu). Semua itu tidak
menghentikan program yang sengaja menyamar atau menghapus penjaganya: tidak
ada yang bisa, kalau program itu berjalan sebagai Anda. Karena itu:

- beri komando, dan berarti agent Anda, user SSH yang hanya punya izin yang dibutuhkan;
- tandai produksi dengan `komando host edit NAMA --protected`;
- lindungi vault dengan passphrase (`KOMANDO_VAULT_PASS`) kalau orang lain
  atau backup bisa menjangkau `~/.komando`.

> Filter ini menangkap kecelakaan yang umum; ini bukan batas keamanan yang
> lengkap. Penyamaran bersifat usaha terbaik: secret dengan nama yang tidak
> biasa bisa saja lolos.
